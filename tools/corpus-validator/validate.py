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
import hashlib
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
    "normalization_applied",
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


#: Defanging this undoes, and nothing else. `docs/data-handling.md` and the
#: specification both state that defanged input is accepted, so the validator
#: has to actually accept it -- a value exported from a ticket as `evil[.]com`
#: was otherwise classified `unsupported_type` and dropped from the denominator,
#: which is a documented promise the code did not keep.
DEFANG_RULES = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[dot]", "."),
    ("(dot)", "."),
)
DEFANG_SCHEMES = (("hxxps", "https"), ("hxxp", "http"), ("fxp", "ftp"))


def undefang(value: str) -> tuple[str, list[str]]:
    """Return the real value and the normalizations that were applied.

    Every change is named in `normalization_applied` rather than performed
    silently: a value that was altered before lookup is a value the caller
    should be able to see was altered.
    """
    text = value.strip()
    applied: list[str] = []

    lowered = text.lower()
    for fanged, real in DEFANG_SCHEMES:
        if lowered.startswith(fanged + "://"):
            text = real + text[len(fanged) :]
            applied.append("defang_scheme")
            break

    replaced = text
    for fanged, real in DEFANG_RULES:
        if fanged in replaced or fanged.upper() in replaced:
            replaced = replaced.replace(fanged, real).replace(fanged.upper(), real)
    if replaced != text:
        applied.append("defang")
        text = replaced

    if text != text.strip():
        text = text.strip()
    if text.endswith(".") and "://" not in text:
        text = text.rstrip(".")
        applied.append("trailing_dot")
    return text, applied


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


def _skip_reason_for(value: str, kind: str) -> str | None:
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
        try:
            # A bare address arriving under a domain label is still an address.
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            if not address.is_global:
                return "non_public_ip"
        if host.endswith(INTERNAL_SUFFIXES) or "." not in host:
            return "internal_hostname"
    return None


def skip_reason(value: str, supplied: str, detected: str) -> str | None:
    """Why a value must not be looked up -- never conflated with "not found".

    Checked against the supplied type *and* the detected one, and a skip from
    either wins. A private address declared as `domain` otherwise passed every
    guard, was looked up, and came back `miss` -- entering the denominator and
    being reported as not-found, which is exactly what the review's hard
    requirement forbids. Safety checks do not defer to a caller's label.
    """
    reasons = [
        _skip_reason_for(value, kind)
        for kind in dict.fromkeys(filter(None, (supplied, detected)))
    ]
    for reason in reasons:
        # `unsupported_type` is the weakest answer: if either reading of the
        # value yields a usable type, the value is usable.
        if reason and reason != "unsupported_type":
            return reason
    if reasons and all(reason == "unsupported_type" for reason in reasons):
        return "unsupported_type"
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

    def match(self, normalized: str, kind: str, original: str = "") -> tuple[str | None, str | None]:
        """(match_method, matched_key), or (None, None) for a miss.

        A submitted URL is tried whole before it is reduced to its host. The
        corpus does hold some full URLs, and reducing first made those
        unreachable while labelling a host-level match `same_host` -- so the
        stronger relation existed in the data and could never be reported.
        """
        key = normalized.lower()
        if kind == "url" and original:
            whole = original.strip().rstrip("/").lower()
            if whole in self.values:
                return "exact", whole
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


# ------------------------------------------------------------- integrity ---


def recompute_corpus_version(snapshot: dict[str, Any]) -> str:
    """Rebuild `corpus_version` from the snapshot's own contents.

    The field was previously read and trusted. Trusting it means a truncated,
    edited or partially-written snapshot reports the version it claims rather
    than the version it is, and every result carries that claim forward into
    your records.

    This is an integrity check, not an authenticity one: it proves the file is
    internally consistent and has not been altered or truncated since it was
    built. It cannot prove who built it. A digest that travels in the same
    message as the file proves neither -- ask for the digest through a channel
    that is not the one the file arrived on.
    """
    material = json.dumps(
        {
            "values": snapshot.get("values") or {},
            "excluded": snapshot.get("excluded") or {},
            "cve_intel": snapshot.get("cve_intel") or {},
            "psl": snapshot.get("public_suffix_list_version"),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    last = (snapshot.get("corpus") or {}).get("last_date") or "unknown"
    return f"{last}.{digest}"


def verify_snapshot(snapshot: dict[str, Any]) -> str:
    """Refuse to run on a snapshot that does not match its own contents."""
    claimed = str(snapshot.get("corpus_version") or "")
    actual = recompute_corpus_version(snapshot)
    if not claimed:
        raise SystemExit("snapshot carries no corpus_version; refusing to run")
    if claimed != actual:
        raise SystemExit(
            "snapshot integrity check failed: it claims corpus_version "
            f"{claimed} but its contents produce {actual}. The file has been "
            "altered or truncated since it was built; do not use these results."
        )
    counts = snapshot.get("corpus") or {}
    stated = counts.get("confirmed_values")
    held = len(snapshot.get("values") or {})
    if stated is not None and int(stated) != held:
        raise SystemExit(
            f"snapshot says it holds {stated} confirmed values but carries {held}; "
            "refusing to run"
        )
    return actual


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
    """One result row per input row, whatever happens to it.

    Every row is evaluated inside its own guard. A malformed value previously
    raised out of the loop and ended the run, which meant the documented
    `status=error` could not occur: the promise was a row, and the behaviour was
    a traceback and no output at all.
    """
    results: list[dict[str, Any]] = []
    for row in rows:
        out: dict[str, Any] = {column: "" for column in RESULT_COLUMNS}
        out["sample_id"] = row.get("sample_id", "")
        out["value"] = row.get("value", "")
        try:
            results.append(_evaluate_row(row, corpus, out))
        except Exception as error:  # one bad row must not end the run
            out["status"] = "error"
            out["reason"] = f"{type(error).__name__}: {error}"[:200]
            results.append(out)
    return results


def _evaluate_row(row: dict[str, str], corpus: Corpus, out: dict[str, Any]) -> dict[str, Any]:
    raw = row["value"]
    value, applied = undefang(raw)
    supplied = (row.get("type") or "").strip().lower()
    detected = detect_type(value)
    used = supplied or detected
    out.update(
        {
            "type_supplied": supplied,
            "type_detected": detected,
            "type_used": used,
            "normalization_applied": ",".join(applied),
        }
    )
    if supplied and detected != "unknown" and supplied != detected:
        # Reported, not resolved. A value whose declared type disagrees with
        # its shape is worth an analyst's attention either way.
        out["reason"] = f"type_mismatch:supplied={supplied},detected={detected}"

    reason = skip_reason(value, supplied, detected)
    if reason:
        out["status"] = "skipped"
        out["reason"] = "; ".join(filter(None, (out["reason"], reason)))
        return out

    normalized = normalize(value, used)
    out["normalized_value"] = normalized

    excluded = corpus.excluded.get(normalized.lower())
    if excluded:
        # "We looked and ruled this out" is not "we have never seen it".
        out["status"] = "excluded"
        out["reason"] = "; ".join(
            filter(None, (out["reason"], ",".join(excluded.get("reason_codes") or [])))
        )
        return out

    method, key = corpus.match(normalized, used, original=value)
    if not method or key is None:
        out["status"] = "miss"
        return out

    record = corpus.values[key]
    citations = [c for c in (record.get("citations") or []) if c.get("article_url")]
    if not citations:
        # The specification requires that a value which cannot be cited is not
        # reported as a hit. Emitting one with a blank citation column would
        # satisfy the letter of "one row per value" and break the rule the row
        # exists to enforce.
        out["status"] = "error"
        out["reason"] = "; ".join(filter(None, (out["reason"], "missing_citation")))
        out["matched_value"] = record.get("value", key)
        out["match_method"] = method
        return out
    first = citations[0]
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
            # Every publisher, not just the first. `source_count` alone cannot
            # tell corroboration from republication: in this corpus every
            # network indicator with more than one publisher is an aggregator
            # carrying an original researcher's report, and you need the names
            # to see that.
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
    return out


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
        "corpus_version_recomputed": recompute_corpus_version(snapshot),
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
    # Before anything else: a snapshot that does not match its own contents
    # produces results that look ordinary and are not.
    verified = verify_snapshot(snapshot)

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
    print(f"corpus {verified} covering {summary['corpus']['days']} days (integrity verified)")
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
