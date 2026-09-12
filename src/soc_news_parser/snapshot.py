"""Build a self-contained corpus snapshot the consumer can match against offline.

The reviewers asked for a validator that runs on their side rather than a file
transfer, and this goes one step further: the bundle carries the corpus, so
their values never leave their network at all. Nothing is uploaded, nothing is
looked up, and there is no endpoint to trust — which answers four of their five
transfer prerequisites by removing the transfer.

What travels is what a citation needs: the confirmed value, which report and
publisher named it, the article URL and its publication date, and for CVEs the
KEV/CVSS/EPSS record with the provenance attached. Article bodies do not travel;
they are 26 publishers' text and no match needs them. Candidate and rejected
rows do not travel either, with one deliberate exception: the excluded values
and their reason codes, because "we looked and ruled this out" is a different
answer from "we have never seen this" and the review asked for the distinction.

The boundary rules travel too. A match made on their side has to be the same
match this project would make, so the Public Suffix List that decides where a
parent domain stops is embedded rather than fetched.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ioc_query import REPORT_DATE_RE, REPORT_FILENAME, reports_root
from .publicsuffix import (
    EXCEPTION_RULES,
    NORMAL_RULES,
    WILDCARD_RULES,
    public_suffix_list_version,
)

SNAPSHOT_SCHEMA = "corpus-snapshot/1"

#: Indicator types that travel. `filename` is excluded: Disclosure 2 measured it
#: as the noisiest class, and a filename is not an observable the reviewers
#: listed. `url` travels because the corpus holds some, even though the first
#: sample will not contain any.
SNAPSHOT_TYPES = frozenset({"domain", "ip", "url", "md5", "sha256", "sha1"})


def _load_day(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _iter_days(reports_dir: str | Path | None):
    base = reports_root(reports_dir)
    if not base.is_dir():
        return
    for folder in sorted(base.iterdir()):
        if not REPORT_DATE_RE.match(folder.name) or not folder.is_dir():
            continue
        payload = _load_day(folder / REPORT_FILENAME)
        if payload is not None:
            yield folder.name, payload


def _action_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The analyst action per target, so a hit can carry what was decided."""
    out: dict[str, dict[str, Any]] = {}
    for action in (payload.get("analyst_brief") or {}).get("actions") or []:
        target = str(action.get("target") or "")
        if target:
            out.setdefault(target.lower(), action)
    return out


def build_snapshot(reports_dir: str | Path | None = None) -> dict[str, Any]:
    values: dict[str, dict[str, Any]] = {}
    excluded: dict[str, dict[str, Any]] = {}
    cve_intel: dict[str, dict[str, Any]] = {}
    coverage: list[dict[str, Any]] = []
    dates: list[str] = []

    for date, payload in _iter_days(reports_dir):
        dates.append(date)
        actions = _action_index(payload)

        # Which sources failed that day travels with the corpus. A value absent
        # because its publisher could not be read is not the same as a value
        # nobody reported, and only this says which days had a gap.
        failures = [
            str(item.get("source_key") or "")
            for item in payload.get("source_failures") or []
            if isinstance(item, dict) and item.get("source_key")
        ]
        coverage.append(
            {
                "report_date": date,
                "window_start": payload.get("window_start"),
                "window_end": payload.get("window_end"),
                "article_count": payload.get("article_count"),
                "sources_failed": sorted(set(failures)),
            }
        )

        for article in payload.get("articles") or []:
            citation = {
                "publisher": article.get("source"),
                "article_title": article.get("article_title"),
                "article_url": article.get("article_url"),
                "published_at": article.get("published_at"),
            }
            for item in article.get("evidence") or []:
                status = item.get("status")
                value = str(item.get("normalized_value") or "").strip()
                if not value:
                    continue
                kind = str(item.get("indicator_type") or "")
                key = value.lower()

                if status == "rejected":
                    row = excluded.setdefault(
                        key,
                        {"value": value, "type": kind, "reason_codes": [], "dates": []},
                    )
                    for code in item.get("reason_codes") or []:
                        if code not in row["reason_codes"]:
                            row["reason_codes"].append(str(code))
                    if date not in row["dates"]:
                        row["dates"].append(date)
                    continue

                if status != "confirmed":
                    continue
                if kind != "cve" and kind not in SNAPSHOT_TYPES:
                    continue

                row = values.setdefault(
                    key,
                    {
                        "value": value,
                        "type": kind,
                        "report_dates": [],
                        "publishers": [],
                        "citations": [],
                    },
                )
                if date not in row["report_dates"]:
                    row["report_dates"].append(date)
                publisher = citation["publisher"]
                if publisher and publisher not in row["publishers"]:
                    row["publishers"].append(str(publisher))
                # One citation per publisher per value keeps the bundle small
                # without losing the corroboration count the review asked for.
                if not any(
                    c["publisher"] == citation["publisher"]
                    and c["article_url"] == citation["article_url"]
                    for c in row["citations"]
                ):
                    row["citations"].append({**citation, "report_date": date})

                action = actions.get(key)
                if action:
                    row["action"] = action.get("action")
                    row["priority"] = action.get("priority")
                    row["benign_basis"] = action.get("benign_basis")

        for cve_id, record in (payload.get("cve_intel") or {}).items():
            if not isinstance(record, dict):
                continue
            # The newest day wins: KEV due dates and EPSS scores move, and a
            # stale copy presented beside a fresh one is the kind of silent
            # mismatch the review's provenance requirement exists to prevent.
            cve_intel[str(cve_id).upper()] = {
                **{k: v for k, v in record.items() if k != "sources"},
                "provenance": list(record.get("sources") or []),
                "observed_on": date,
            }

    for row in values.values():
        row["report_count"] = len(row["report_dates"])
        row["source_count"] = len(row["publishers"])
        row["first_seen"] = min(row["report_dates"]) if row["report_dates"] else None
        row["last_seen"] = max(row["report_dates"]) if row["report_dates"] else None

    snapshot: dict[str, Any] = {
        "schema": SNAPSHOT_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus": {
            "days": len(dates),
            "first_date": dates[0] if dates else None,
            "last_date": dates[-1] if dates else None,
            "confirmed_values": len(values),
            "excluded_values": len(excluded),
            "cve_records": len(cve_intel),
        },
        "public_suffix_list_version": public_suffix_list_version(),
        "public_suffix_rules": {
            "normal": sorted(NORMAL_RULES),
            "wildcard": sorted(WILDCARD_RULES),
            "exception": sorted(EXCEPTION_RULES),
        },
        "coverage": coverage,
        "values": values,
        "excluded": excluded,
        "cve_intel": cve_intel,
        "not_measured_here": [
            "This is current-corpus coverage, not what the service would have "
            "known at the time of each alert: the corpus holds only the days it "
            "has collected, and the input carries no alert timestamps.",
            "It is not detection performance and not decision impact. A hit "
            "means a publisher named the value, nothing more.",
            "A miss is not a judgement that the value is benign or unreported; "
            "it means this corpus, over the days it covers, does not name it.",
        ],
    }
    snapshot["corpus_version"] = _corpus_version(snapshot)
    return snapshot


def _corpus_version(snapshot: dict[str, Any]) -> str:
    """Identifies the corpus state: the same version must reproduce the result.

    Hashes what a match can depend on — the values, their counts and citations,
    the excluded set and the boundary rules — and not `generated_at`, so
    rebuilding an unchanged corpus twice yields one version rather than two.
    """
    material = json.dumps(
        {
            "values": snapshot["values"],
            "excluded": snapshot["excluded"],
            "cve_intel": snapshot["cve_intel"],
            # The rules themselves, not the version string that names them.
            # Hashing only the version left the one part of the bundle that
            # decides where a parent match stops editable without detection:
            # drop `github.io` from the normal set, keep the version, and every
            # tenant beneath it starts matching every other tenant, with the
            # integrity check still passing.
            "psl_rules": snapshot["public_suffix_rules"],
            "psl_version": snapshot["public_suffix_list_version"],
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    last = snapshot["corpus"]["last_date"] or "unknown"
    return f"{last}.{digest}"


def write_bundle(destination: str | Path, reports_dir: str | Path | None = None) -> dict[str, Any]:
    """Write the snapshot, the validator that reads it, and the validator's own
    tests, ready to hand over."""
    out = Path(destination)
    out.mkdir(parents=True, exist_ok=True)
    snapshot = build_snapshot(reports_dir)
    (out / "corpus-snapshot.json").write_text(
        json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )

    validator = Path(__file__).resolve().parents[2] / "tools" / "corpus-validator"
    # The tests travel with the tool. The reviewers could not verify a claim
    # that 202 tests passed, because none of them was in the bundle -- and a
    # claim the consumer cannot check is one they are right to discount.
    for name in ("validate.py", "README.md", "test_validate.py"):
        source = validator / name
        if source.is_file():
            # Newline is forced: the file is written on Windows and read on the
            # consumer's machine, and a CRLF shebang is a script that will not
            # start. The same mistake has cost this project a deployment before.
            (out / name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    return snapshot
