"""Measure a real alert stream against the corpus, before building for it.

The pilot's remaining questions -- which response fields change a decision, and
whether observable enrichment or CVE ranking is the one that earns its place --
cannot be answered from this side. They need the consumer's own values run
against what the corpus actually holds.

This reads the local `reports/` archive rather than D1 on purpose: D1 stores
confirmed indicators only, so the `excluded` rate the reviewers asked about is
answerable here and nowhere else. Domain relationships use the same Public
Suffix List the Worker does, so a parent match measured here is one the Worker
would also make.

What it cannot compute is stated rather than approximated. Decision-change rate
needs a human reading the hits; latency belongs to the Worker. The hit list is
written out so that review has something to work from.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .ioc_query import REPORT_FILENAME, list_report_dates, reports_root
from .publicsuffix import is_public_suffix, public_suffix

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)
# Names an organisation gives its own machines. Sending these to a public-report
# corpus leaks internal structure and can never match, so they are skipped
# rather than answered "unseen" -- the distinction the reviewers asked for.
INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home.arpa", ".localdomain")


@dataclass
class Corpus:
    """Every indicator and CVE the archive holds, with where each was seen."""

    # value -> {"type", "dates": set, "sources": set, "actions": [...], "articles": [...]}
    confirmed: dict[str, dict[str, Any]] = field(default_factory=dict)
    # value -> reason codes, for the excluded-rate question D1 cannot answer
    excluded: dict[str, list[str]] = field(default_factory=dict)
    candidates: set[str] = field(default_factory=set)
    dates: list[str] = field(default_factory=list)

    @property
    def registrable_index(self) -> dict[str, list[str]]:
        """Confirmed hostnames grouped by registrable domain, for parent matching."""
        index: dict[str, list[str]] = {}
        for value, record in self.confirmed.items():
            if record["type"] not in {"domain", "url"}:
                continue
            host = _host_of(value)
            if not host:
                continue
            index.setdefault(_registrable(host), []).append(value)
        return index


def _host_of(value: str) -> str:
    if "://" in value:
        return (urlsplit(value).hostname or "").lower()
    return value.strip().strip(".").lower()


def _registrable(host: str) -> str:
    suffix = public_suffix(host)
    labels = host.split(".")
    depth = len(suffix.split("."))
    return ".".join(labels[-(depth + 1) :]) if len(labels) > depth else host


def load_corpus(reports_dir: str | Path | None = None) -> Corpus:
    corpus = Corpus()
    base = reports_root(reports_dir)
    for entry in list_report_dates(base):
        date = entry["date"]
        corpus.dates.append(date)
        payload = json.loads(
            (base / date / REPORT_FILENAME).read_text(encoding="utf-8")
        )
        actions = {
            (str(a.get("target_type")), str(a.get("target")).lower()): a
            for a in (payload.get("analyst_brief") or {}).get("actions") or []
            if isinstance(a, dict)
        }
        for article in payload.get("articles") or []:
            if not isinstance(article, dict):
                continue
            for evidence in article.get("evidence") or []:
                if not isinstance(evidence, dict):
                    continue
                kind = str(evidence.get("indicator_type") or "")
                value = str(evidence.get("normalized_value") or "").lower()
                if not kind or not value:
                    continue
                status = evidence.get("status")
                if status == "rejected":
                    corpus.excluded.setdefault(value, [])
                    corpus.excluded[value].extend(evidence.get("reason_codes") or [])
                    continue
                if status == "candidate":
                    corpus.candidates.add(value)
                    continue
                record = corpus.confirmed.setdefault(
                    value,
                    {"type": kind, "dates": set(), "sources": set(), "actions": [], "articles": []},
                )
                record["dates"].add(date)
                record["sources"].add(article.get("source"))
                record["articles"].append(
                    {
                        "title": article.get("article_title"),
                        "url": article.get("article_url"),
                        "date": date,
                    }
                )
                action = actions.get((kind, value))
                if action:
                    record["actions"].append(action)
    return corpus


def _classify(value: str) -> str:
    text = value.strip()
    if CVE_RE.match(text):
        return "cve"
    if HASH_RE.match(text):
        return "hash"
    if "://" in text:
        return "url"
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    return "domain" if "." in text else "other"


def _skip_reason(value: str, kind: str) -> str | None:
    if kind == "other":
        return "unsupported_type"
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return "invalid_value"
        if not address.is_global:
            # Covers RFC 1918 and the documentation ranges alike. The evidence
            # pipeline already calls this non_public_ip; the same name is used
            # here so one reason code means one thing across the project.
            return "non_public_ip"
    host = _host_of(value) if kind in {"domain", "url"} else ""
    if host and host.endswith(INTERNAL_SUFFIXES):
        return "internal_hostname"
    return None


def match_observables(values: Iterable[str], corpus: Corpus) -> dict[str, Any]:
    """One verdict per submitted value, with the distinctions the review named."""
    index = corpus.registrable_index
    hits: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    unseen: list[str] = []
    match_counts: Counter[str] = Counter()

    submitted = [v.strip() for v in values if v and v.strip()]
    for value in submitted:
        lowered = value.lower()
        kind = _classify(value)
        reason = _skip_reason(value, kind)
        if reason:
            skipped.append({"value": value, "reason_code": reason})
            continue
        if lowered in corpus.excluded:
            excluded.append(
                {"value": value, "reason_codes": sorted(set(corpus.excluded[lowered]))}
            )
            continue

        record = corpus.confirmed.get(lowered)
        matched_on, match_type = lowered, "exact"
        if record is None and kind in {"domain", "url"}:
            host = _host_of(value)
            # Only up to the registrable domain, the same boundary the Worker
            # stops at. Nothing at or above a public suffix belongs to anyone.
            for candidate in sorted(index.get(_registrable(host), []), key=len):
                candidate_host = _host_of(candidate)
                if host.endswith("." + candidate_host):
                    record, matched_on, match_type = (
                        corpus.confirmed[candidate],
                        candidate,
                        "parent_domain",
                    )
                    break
                if candidate_host.endswith("." + host) and not is_public_suffix(host):
                    record, matched_on, match_type = (
                        corpus.confirmed[candidate],
                        candidate,
                        "child_domain",
                    )
                    break
        if record is None:
            unseen.append(value)
            continue

        match_counts[match_type] += 1
        dates = sorted(record["dates"])
        action = record["actions"][0] if record["actions"] else {}
        hits.append(
            {
                "value": value,
                "matched_on": matched_on,
                "match": match_type,
                "indicator_type": record["type"],
                "first_seen": dates[0],
                "last_seen": dates[-1],
                "report_count": len(dates),
                "source_count": len({s for s in record["sources"] if s}),
                "action": action.get("action"),
                "benign_basis": action.get("benign_basis"),
                "reason": action.get("reason"),
                "citation": record["articles"][0] if record["articles"] else None,
            }
        )

    processed = len(submitted) - len(skipped)
    return {
        "submitted": len(submitted),
        "processed": processed,
        "skipped": len(skipped),
        "hits": len(hits),
        "hit_rate": round(len(hits) / processed, 5) if processed else None,
        "by_match": dict(match_counts),
        "benign_listed": sum(1 for h in hits if h["benign_basis"]),
        "excluded": len(excluded),
        "unseen": len(unseen),
        "detail": {
            "hits": hits,
            "excluded": excluded,
            "skipped": skipped,
            "unseen": unseen[:200],
        },
    }


def match_cves(values: Iterable[str], corpus: Corpus) -> dict[str, Any]:
    submitted = [v.strip().upper() for v in values if v and v.strip()]
    valid = [v for v in submitted if CVE_RE.match(v)]
    hits: list[dict[str, Any]] = []
    for cve_id in valid:
        record = corpus.confirmed.get(cve_id.lower())
        if record is None:
            continue
        action = record["actions"][0] if record["actions"] else {}
        dates = sorted(record["dates"])
        hits.append(
            {
                "cve": cve_id,
                "first_seen": dates[0],
                "last_seen": dates[-1],
                "report_count": len(dates),
                "source_count": len({s for s in record["sources"] if s}),
                "kev": action.get("kev"),
                "kev_due_date": action.get("kev_due_date"),
                "cvss_score": action.get("cvss_score"),
                "epss_score": action.get("epss_score"),
                "epss_percentile": action.get("epss_percentile"),
                "priority": action.get("priority"),
                "citation": record["articles"][0] if record["articles"] else None,
            }
        )
    ranked = [h for h in hits if h["kev"] or h["cvss_score"] or h["epss_score"]]
    return {
        "submitted": len(submitted),
        "malformed": len(submitted) - len(valid),
        "hits": len(hits),
        "hit_rate": round(len(hits) / len(valid), 5) if valid else None,
        "kev": sum(1 for h in hits if h["kev"]),
        "with_cvss": sum(1 for h in hits if h["cvss_score"] is not None),
        "with_epss": sum(1 for h in hits if h["epss_score"] is not None),
        "with_any_ranking_signal": len(ranked),
        "corroborated_by_two_publishers": sum(1 for h in hits if h["source_count"] > 1),
        "detail": {"hits": hits},
    }


def read_values(path: str | Path) -> list[str]:
    """One value per line. A CSV export works too: the first field is taken."""
    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        out.append(text.split(",")[0].strip().strip('"'))
    return out


def run_backtest(
    *,
    observables: list[str] | None,
    cves: list[str] | None,
    reports_dir: str | Path | None = None,
) -> dict[str, Any]:
    corpus = load_corpus(reports_dir)
    result: dict[str, Any] = {
        "corpus": {
            "days": len(corpus.dates),
            "first_date": corpus.dates[-1] if corpus.dates else None,
            "last_date": corpus.dates[0] if corpus.dates else None,
            "confirmed_values": len(corpus.confirmed),
            "excluded_values": len(corpus.excluded),
            "candidate_values": len(corpus.candidates),
        },
        "not_measured_here": [
            "decision-change rate: needs a human reading detail.hits against the "
            "original alerts, which is the acceptance measure that matters most",
            "citation reachability: this checks that a citation exists, not that "
            "the link resolves or supports the value",
            "latency and payload size: properties of the Worker, not of the corpus",
        ],
    }
    if observables:
        result["observables"] = match_observables(observables, corpus)
    if cves:
        result["cves"] = match_cves(cves, corpus)
    return result


def render_markdown(result: dict[str, Any]) -> str:
    corpus = result["corpus"]
    lines = [
        "# Backtest against the published-report corpus",
        "",
        f"Corpus: {corpus['days']} days, {corpus['first_date']} to {corpus['last_date']}, "
        f"{corpus['confirmed_values']} confirmed values.",
        "",
    ]
    obs = result.get("observables")
    if obs:
        rate = "n/a" if obs["hit_rate"] is None else f"{obs['hit_rate'] * 100:.2f}%"
        lines += [
            "## Observables",
            "",
            f"| submitted | processed | skipped | hits | hit rate |",
            "|---|---|---|---|---|",
            f"| {obs['submitted']} | {obs['processed']} | {obs['skipped']} | {obs['hits']} | {rate} |",
            "",
            f"Match types: {obs['by_match'] or 'none'}. "
            f"Benign-listed {obs['benign_listed']}, excluded {obs['excluded']}, "
            f"unseen {obs['unseen']}.",
            "",
            "A low hit rate is not by itself a verdict: the review accepted one, "
            "provided exact hits are accurate and citable. What decides it is how "
            "many of the hits in `detail.hits` would have changed an investigation.",
            "",
        ]
    cve = result.get("cves")
    if cve:
        rate = "n/a" if cve["hit_rate"] is None else f"{cve['hit_rate'] * 100:.2f}%"
        lines += [
            "## CVEs",
            "",
            f"| submitted | hits | hit rate | KEV | with CVSS | with EPSS |",
            "|---|---|---|---|---|---|",
            f"| {cve['submitted']} | {cve['hits']} | {rate} | {cve['kev']} | "
            f"{cve['with_cvss']} | {cve['with_epss']} |",
            "",
            f"{cve['with_any_ranking_signal']} of {cve['hits']} carry at least one "
            f"ranking signal; {cve['corroborated_by_two_publishers']} were named by "
            "more than one publisher.",
            "",
        ]
    lines += ["## Not measured here", ""]
    lines += [f"- {item}" for item in result["not_measured_here"]]
    return "\n".join(lines) + "\n"
