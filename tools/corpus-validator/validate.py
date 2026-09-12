#!/usr/bin/env python3
"""Match a list of observables against a corpus snapshot, entirely offline.

Nothing here opens a socket. There is no endpoint, no upload and no telemetry:
the corpus travels to you in `corpus-snapshot.json`, your values stay on this
machine, and both the per-row results and the summary are written where you
point them. You can verify that claim by reading this file — it imports only
the Python standard library and the only I/O is the files named on the command
line.

    python3 validate.py --input observables.csv --output results.csv \
        --summary summary.json

Input is the CSV agreed in review:

    value,type,sample_id
    evil.example.com,domain,S000001

`type` and `sample_id` are optional. When `type` is absent it is detected; when
it is present and disagrees with detection, both are reported and the supplied
one is used, because a disagreement is a finding rather than something to
silently resolve.

Requires Python 3.9 or later.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CVE_RE = re.compile(r"\ACVE-\d{4}-\d{4,7}\Z", re.IGNORECASE)
MD5_RE = re.compile(r"\A[0-9a-f]{32}\Z", re.IGNORECASE)
SHA1_RE = re.compile(r"\A[0-9a-f]{40}\Z", re.IGNORECASE)
SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\A(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z", re.IGNORECASE)

# Names an organisation gives its own machines. These can never appear in a
# corpus of published reporting, and sending one anywhere leaks internal
# structure -- so they are skipped and reported as skipped, never as a miss.
INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home.arpa", ".localdomain", ".intranet")

#: Match methods that count toward the headline coverage rate. These are the
#: three the review enumerated. `child_domain` is computed and reported, but is
#: deliberately kept out of this set: the review's decision thresholds were set
#: against these relations, and quietly widening the definition would move the
#: rate against a rule written for something narrower.
HEADLINE_METHODS = ("exact", "parent_domain", "same_host")

RESULT_COLUMNS = [
    "sample_id",
    "value",
    "type_supplied",
    "type_detected",
    "type_used",
    "normalized_value",
    "status",
    "reason",
    "match_method",
    "matched_value",
    "report_count",
    "source_count",
    "first_seen",
    "last_seen",
    "publication_date",
    "citation_url",
    "citation_publisher",
    "citation_count",
    "publishers",
    "action",
    "priority",
    "benign_basis",
    "kev",
    "kev_due_date",
    "cvss_score",
    "cvss_severity",
    "cvss_version",
    "epss_score",
    "epss_percentile",
    "epss_date",
    "cve_provenance",
    "cve_observed_on",
]


# --------------------------------------------------------------- suffixes ---


class Boundaries:
    """The Public Suffix List algorithm, over the rules carried in the snapshot.

    This is what stops a parent-domain match at the registrable domain. Without
    it `tenant.github.io` and `other.github.io` would match each other through
    `github.io`, which is a registry and belongs to neither.
    """

    def __init__(self, rules: dict[str, Any]) -> None:
        self.normal = set(rules.get("normal") or ())
        self.wildcard = set(rules.get("wildcard") or ())
        self.exception = set(rules.get("exception") or ())
        if len(self.normal) < 1000:
            raise SystemExit(
                "corpus-snapshot.json carries too few public-suffix rules to draw "
                "boundaries; the file is truncated and results would be wrong"
            )

    def public_suffix(self, host: str) -> str:
        labels = host.split(".")
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.exception:
                return ".".join(labels[i + 1 :])
            parent = ".".join(labels[i + 1 :])
            if parent and parent in self.wildcard:
                return candidate
            if candidate in self.normal:
                return candidate
        return labels[-1]

    def registrable(self, host: str) -> str:
        suffix = self.public_suffix(host)
        labels = host.split(".")
        depth = len(suffix.split("."))
        return ".".join(labels[-(depth + 1) :]) if len(labels) > depth else host

    def parents(self, host: str) -> list[str]:
        """Ancestors of `host` down to the registrable domain, nearest first."""
        labels = host.split(".")
        depth = len(self.public_suffix(host).split("."))
        out = []
        for i in range(1, len(labels) - depth):
            out.append(".".join(labels[i:]))
        return out


# ------------------------------------------------------------ classifying ---


def detect_type(value: str) -> str:
    text = value.strip()
    if not text:
        return "empty"
    if CVE_RE.match(text):
        return "cve"
    if MD5_RE.match(text):
        return "md5"
    if SHA1_RE.match(text):
        return "sha1"
    if SHA256_RE.match(text):
        return "sha256"
    if "://" in text:
        return "url"
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if DOMAIN_RE.match(text.rstrip(".")):
        return "domain"
    return "unknown"


def normalize(value: str, kind: str) -> str:
    text = value.strip()
    if kind == "cve":
        return text.upper()
    if kind in ("md5", "sha1", "sha256"):
        return text.lower()
    if kind == "url":
        return (urlsplit(text).hostname or "").lower()
    if kind == "domain":
        return text.rstrip(".").lower()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return text
    return text.lower()


def skip_reason(value: str, kind: str) -> str | None:
    """Why a value must not be looked up -- never conflated with "not found"."""
    if kind == "empty":
        return "empty_value"
    if kind == "unknown":
        return "unsupported_type"
    if kind == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return "malformed_ip"
        if not address.is_global:
            return "non_public_ip"
    if kind in ("domain", "url"):
        host = normalize(value, kind)
        if not host:
            return "unparseable_host"
        if host.endswith(INTERNAL_SUFFIXES) or "." not in host:
            return "internal_hostname"
    return None


# --------------------------------------------------------------- matching ---


class Corpus:
    def __init__(self, snapshot: dict[str, Any]) -> None:
        self.values: dict[str, dict[str, Any]] = snapshot.get("values") or {}
        self.excluded: dict[str, dict[str, Any]] = snapshot.get("excluded") or {}
        self.cve_intel: dict[str, dict[str, Any]] = snapshot.get("cve_intel") or {}
        self.boundaries = Boundaries(snapshot.get("public_suffix_rules") or {})
        # Confirmed hostnames grouped by registrable domain, so the reverse
        # relation (corpus named a child of what was submitted) can be found
        # without scanning every value per lookup.
        self.by_registrable: dict[str, list[str]] = defaultdict(list)
        for key, row in self.values.items():
            if row.get("type") not in ("domain", "url"):
                continue
            self.by_registrable[self.boundaries.registrable(key)].append(key)

    def match(self, normalized: str, kind: str) -> tuple[str | None, str | None]:
        """(match_method, matched_key), or (None, None) for a miss."""
        key = normalized.lower()
        if key in self.values:
            return ("same_host" if kind == "url" else "exact"), key
        if kind not in ("domain", "url"):
            return None, None
        for parent in self.boundaries.parents(key):
            if parent in self.values:
                return "parent_domain", parent
        # The corpus named something beneath what was submitted. Real, weaker,
        # and reported under its own name so it cannot be read as an exact hit.
        children = [
            child
            for child in self.by_registrable.get(self.boundaries.registrable(key), ())
            if child != key and child.endswith("." + key)
        ]
        if children:
            return "child_domain", sorted(children)[0]
        return None, None


# ---------------------------------------------------------------- running ---


def read_input(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        has_header = "value" in sample.split("\n", 1)[0].lower()
        reader = csv.DictReader(handle) if has_header else None
        if reader is not None:
            for index, row in enumerate(reader):
                lowered = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
                rows.append(
                    {
                        "value": lowered.get("value", ""),
                        "type": lowered.get("type", ""),
                        "sample_id": lowered.get("sample_id", "") or f"row-{index + 1}",
                    }
                )
            return rows
        for index, line in enumerate(handle):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            first = next(csv.reader([text]))[0].strip()
            rows.append({"value": first, "type": "", "sample_id": f"row-{index + 1}"})
    return rows


def evaluate(rows: list[dict[str, str]], corpus: Corpus) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for row in rows:
        value = row["value"]
        supplied = (row.get("type") or "").strip().lower()
        detected = detect_type(value)
        used = supplied or detected
        out: dict[str, Any] = {column: "" for column in RESULT_COLUMNS}
        out.update(
            {
                "sample_id": row["sample_id"],
                "value": value,
                "type_supplied": supplied,
                "type_detected": detected,
                "type_used": used,
            }
        )
        if supplied and detected != "unknown" and supplied != detected:
            # Reported, not resolved. A value whose declared type disagrees with
            # its shape is worth an analyst's attention either way.
            out["reason"] = f"type_mismatch:supplied={supplied},detected={detected}"

        reason = skip_reason(value, used)
        if reason:
            out["status"] = "skipped"
            out["reason"] = "; ".join(filter(None, (out["reason"], reason)))
            results.append(out)
            continue

        normalized = normalize(value, used)
        out["normalized_value"] = normalized

        excluded = corpus.excluded.get(normalized.lower())
        if excluded:
            # "We looked and ruled this out" is not "we have never seen it".
            out["status"] = "excluded"
            out["reason"] = "; ".join(
                filter(None, (out["reason"], ",".join(excluded.get("reason_codes") or [])))
            )
            results.append(out)
            continue

        method, key = corpus.match(normalized, used)
        if not method or key is None:
            out["status"] = "miss"
            results.append(out)
            continue

        record = corpus.values[key]
        citations = record.get("citations") or []
        first = citations[0] if citations else {}
        out.update(
            {
                "status": "hit",
                "match_method": method,
                "matched_value": record.get("value", key),
                "report_count": record.get("report_count", ""),
                "source_count": record.get("source_count", ""),
                "first_seen": record.get("first_seen", ""),
                "last_seen": record.get("last_seen", ""),
                "publication_date": first.get("published_at", ""),
                "citation_url": first.get("article_url", ""),
                "citation_publisher": first.get("publisher", ""),
                "citation_count": len(citations),
                # Every publisher, not just the first. `source_count` alone
                # cannot tell corroboration from republication: in this corpus
                # every network indicator with more than one publisher is an
                # aggregator carrying an original researcher's report, and you
                # need the names to see that.
                "publishers": "; ".join(record.get("publishers") or []),
                "action": record.get("action", ""),
                "priority": record.get("priority", ""),
                "benign_basis": record.get("benign_basis", "") or "",
            }
        )
        intel = corpus.cve_intel.get(normalized.upper()) if used == "cve" else None
        if intel:
            out.update(
                {
                    "kev": intel.get("kev", ""),
                    "kev_due_date": intel.get("kev_due_date", "") or "",
                    "cvss_score": intel.get("cvss_score", "") if intel.get("cvss_score") is not None else "",
                    "cvss_severity": intel.get("cvss_severity", "") or "",
                    "cvss_version": intel.get("cvss_version", "") or "",
                    "epss_score": intel.get("epss_score", "") if intel.get("epss_score") is not None else "",
                    "epss_percentile": intel.get("epss_percentile", "")
                    if intel.get("epss_percentile") is not None
                    else "",
                    "epss_date": intel.get("epss_date", "") or "",
                    "cve_provenance": " ".join(intel.get("provenance") or []),
                    "cve_observed_on": intel.get("observed_on", "") or "",
                }
            )
        results.append(out)
    return results


def summarize(results: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Rates per observable type, over what was processed rather than submitted.

    A combined rate would hide the difference between CVEs and network
    indicators, which is the difference the exercise exists to measure.
    """
    by_type: dict[str, dict[str, Any]] = {}
    for row in results:
        bucket = by_type.setdefault(
            row["type_used"] or "unknown",
            {
                "submitted": 0,
                "processed": 0,
                "skipped": 0,
                "errors": 0,
                "excluded": 0,
                "hits": 0,
                "headline_hits": 0,
                "by_match_method": {},
            },
        )
        bucket["submitted"] += 1
        status = row["status"]
        if status == "skipped":
            bucket["skipped"] += 1
            continue
        if status == "error":
            bucket["errors"] += 1
            continue
        bucket["processed"] += 1
        if status == "excluded":
            bucket["excluded"] += 1
        elif status == "hit":
            bucket["hits"] += 1
            method = row["match_method"]
            bucket["by_match_method"][method] = bucket["by_match_method"].get(method, 0) + 1
            if method in HEADLINE_METHODS:
                bucket["headline_hits"] += 1

    for bucket in by_type.values():
        processed = bucket["processed"]
        bucket["hit_rate"] = round(bucket["headline_hits"] / processed, 4) if processed else None
        bucket["hit_rate_including_child_domain"] = (
            round(bucket["hits"] / processed, 4) if processed else None
        )

    network = {k: v for k, v in by_type.items() if k in ("domain", "ip", "url", "md5", "sha1", "sha256")}
    processed = sum(v["processed"] for v in network.values())
    headline = sum(v["headline_hits"] for v in network.values())

    return {
        "corpus_version": snapshot.get("corpus_version"),
        "corpus": snapshot.get("corpus"),
        "corpus_generated_at": snapshot.get("generated_at"),
        "public_suffix_list_version": snapshot.get("public_suffix_list_version"),
        "days_with_source_failures": [
            day for day in snapshot.get("coverage") or [] if day.get("sources_failed")
        ],
        "headline_methods": list(HEADLINE_METHODS),
        "by_type": by_type,
        "network_combined": {
            "processed": processed,
            "headline_hits": headline,
            "hit_rate": round(headline / processed, 4) if processed else None,
        },
        "not_measured_here": snapshot.get("not_measured_here") or [],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True, help="CSV of values (value[,type][,sample_id])")
    parser.add_argument("--snapshot", default="corpus-snapshot.json", help="corpus snapshot to match against")
    parser.add_argument("--output", default="results.csv", help="per-row results")
    parser.add_argument("--summary", default="summary.json", help="rates per observable type")
    args = parser.parse_args(argv)

    snapshot_path = Path(args.snapshot)
    if not snapshot_path.is_file():
        print(f"error: no snapshot at {snapshot_path}", file=sys.stderr)
        return 2
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

    rows = read_input(Path(args.input))
    if not rows:
        print(f"error: no values read from {args.input}", file=sys.stderr)
        return 2

    corpus = Corpus(snapshot)
    results = evaluate(rows, corpus)
    summary = summarize(results, snapshot)

    with Path(args.output).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=RESULT_COLUMNS)
        writer.writeheader()
        writer.writerows(results)
    Path(args.summary).write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    combined = summary["network_combined"]
    print(f"corpus {summary['corpus_version']} covering {summary['corpus']['days']} days")
    print(f"rows {len(results)} -> {args.output}")
    for kind in sorted(summary["by_type"]):
        bucket = summary["by_type"][kind]
        rate = "n/a" if bucket["hit_rate"] is None else f"{bucket['hit_rate'] * 100:.2f}%"
        print(
            f"  {kind:8} submitted {bucket['submitted']:5} processed {bucket['processed']:5} "
            f"skipped {bucket['skipped']:4} hits {bucket['headline_hits']:4} rate {rate}"
        )
    rate = "n/a" if combined["hit_rate"] is None else f"{combined['hit_rate'] * 100:.2f}%"
    print(f"  network combined: {combined['headline_hits']}/{combined['processed']} = {rate}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
