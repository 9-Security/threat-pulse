from __future__ import annotations

import json
import os
import re
from datetime import date as date_type
from pathlib import Path
from typing import Any


REPORT_FILENAME = "daily-evidence.json"
DEFAULT_LIMIT = 40
MAX_LIMIT = 100
REPORT_DATE_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}\Z")


def _report_directory(base: Path, date: str) -> Path:
    """Resolve one dated report directory, refusing anything outside the root.

    `date` arrives from an MCP client, so it is not joined to the root until it
    has been proved to be a plain YYYY-MM-DD key, and the resolved path is
    checked against the root again in case a symlink points away.
    """
    if not REPORT_DATE_RE.match(date):
        raise ValueError("report date must be a plain YYYY-MM-DD key")
    try:
        date_type.fromisoformat(date)
    except ValueError:
        raise ValueError("report date must be a plain YYYY-MM-DD key") from None
    folder = (base / date).resolve()
    if base != folder and base not in folder.parents:
        raise ValueError("report date resolves outside the reports directory")
    return folder


def reports_root(path: str | Path | None = None) -> Path:
    if path is not None:
        return Path(path).expanduser().resolve()
    env = os.environ.get("SOC_IOC_REPORTS_DIR", "").strip()
    return Path(env or "reports").expanduser().resolve()


def list_report_dates(root: str | Path | None = None) -> list[dict[str, Any]]:
    base = reports_root(root)
    if not base.is_dir():
        return []
    results: list[dict[str, Any]] = []
    for folder in sorted(base.iterdir(), reverse=True):
        if not REPORT_DATE_RE.match(folder.name):
            continue
        evidence = folder / REPORT_FILENAME
        if not folder.is_dir() or not evidence.is_file():
            continue
        try:
            payload = json.loads(evidence.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        brief = payload.get("analyst_brief") or {}
        results.append(
            {
                "date": folder.name,
                "path": str(evidence),
                "subject": payload.get("subject"),
                "article_count": payload.get("article_count"),
                "confirmed_ioc_count": payload.get("confirmed_ioc_count"),
                "patch_count": brief.get("patch_count") if isinstance(brief, dict) else None,
                "block_count": brief.get("block_count") if isinstance(brief, dict) else None,
                "hunt_count": brief.get("hunt_count") if isinstance(brief, dict) else None,
                "kev_count": _kev_count(brief) if isinstance(brief, dict) else None,
            }
        )
    return results


def load_report(
    date: str | None = None, root: str | Path | None = None
) -> tuple[str, dict[str, Any]]:
    base = reports_root(root)
    if date:
        evidence = _report_directory(base, date) / REPORT_FILENAME
        if not evidence.is_file():
            raise FileNotFoundError(f"no report JSON for {date}")
        # The directory is inside the root, but the file itself may still be a
        # symlink pointing out of it.
        if evidence.resolve() != evidence and base not in evidence.resolve().parents:
            raise ValueError("report file resolves outside the reports directory")
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"invalid report JSON for {date}")
        return date, payload
    listed = list_report_dates(base)
    if not listed:
        raise FileNotFoundError(f"no reports under {base}")
    latest = listed[0]["date"]
    return load_report(latest, base)


def report_summary(
    date: str | None = None, root: str | Path | None = None
) -> dict[str, Any]:
    chosen, payload = load_report(date, root)
    brief = payload.get("analyst_brief") if isinstance(payload.get("analyst_brief"), dict) else {}
    return {
        "date": chosen,
        "subject": payload.get("subject"),
        "window_start": payload.get("window_start"),
        "window_end": payload.get("window_end"),
        "generated_at": payload.get("generated_at"),
        "article_count": payload.get("article_count"),
        "confirmed_ioc_count": payload.get("confirmed_ioc_count"),
        "priority_line": brief.get("priority_line"),
        "patch_count": brief.get("patch_count"),
        "block_count": brief.get("block_count"),
        "hunt_count": brief.get("hunt_count"),
        "monitor_count": brief.get("monitor_count"),
        "new_ioc_count": brief.get("new_ioc_count"),
        "kev_count": _kev_count(brief),
        "enrichment": payload.get("enrichment"),
    }


def _kev_count(brief: Any) -> int | None:
    actions = brief.get("actions") if isinstance(brief, dict) else None
    if not isinstance(actions, list):
        return None
    return len(
        {
            str(item.get("target"))
            for item in actions
            if isinstance(item, dict)
            and item.get("action") == "patch"
            and item.get("kev")
        }
    )


def _action_index(payload: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    brief = payload.get("analyst_brief")
    if not isinstance(brief, dict):
        return {}
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for action in brief.get("actions") or []:
        if not isinstance(action, dict):
            continue
        key = (str(action.get("target_type") or ""), str(action.get("target") or ""))
        if key[0] and key[1] and key not in indexed:
            indexed[key] = action
    return indexed


def _clip_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(int(limit), MAX_LIMIT))


def search_iocs(
    query: str = "",
    *,
    date: str | None = None,
    action: str | None = None,
    indicator_type: str | None = None,
    status: str = "confirmed",
    limit: int | None = None,
    root: str | Path | None = None,
) -> dict[str, Any]:
    chosen, payload = load_report(date, root)
    needle = query.strip().lower()
    wanted_action = action.strip().lower() if action else None
    wanted_type = indicator_type.strip().lower() if indicator_type else None
    wanted_status = status.strip().lower() if status else "confirmed"
    cap = _clip_limit(limit)
    actions = _action_index(payload)
    matches: list[dict[str, Any]] = []
    for article in payload.get("articles") or []:
        if not isinstance(article, dict):
            continue
        title = str(article.get("article_title") or "")
        url = str(article.get("article_url") or "")
        for evidence in article.get("evidence") or []:
            if not isinstance(evidence, dict):
                continue
            if wanted_status and str(evidence.get("status") or "").lower() != wanted_status:
                continue
            itype = str(evidence.get("indicator_type") or "")
            value = str(evidence.get("normalized_value") or "")
            if wanted_type and itype.lower() != wanted_type:
                continue
            related = actions.get((itype, value), {})
            action_name = str(related.get("action") or "")
            if wanted_action and action_name.lower() != wanted_action:
                continue
            haystack = " ".join(
                [
                    itype,
                    value,
                    str(evidence.get("raw_value") or ""),
                    title,
                    action_name,
                    str(related.get("reason") or ""),
                ]
            ).lower()
            if needle and needle not in haystack:
                continue
            matches.append(
                {
                    "indicator_type": itype,
                    "normalized_value": value,
                    "status": evidence.get("status"),
                    "action": action_name or None,
                    "priority": related.get("priority"),
                    "reason": related.get("reason"),
                    "kev": related.get("kev"),
                    "cvss_score": related.get("cvss_score"),
                    "article_title": title,
                    "article_url": url,
                }
            )
            if len(matches) >= cap:
                return {"date": chosen, "count": len(matches), "truncated": True, "items": matches}
    return {"date": chosen, "count": len(matches), "truncated": False, "items": matches}


def lookup_indicator(
    value: str,
    *,
    date: str | None = None,
    root: str | Path | None = None,
) -> dict[str, Any]:
    needle = value.strip().lower()
    if not needle:
        raise ValueError("value is required")
    chosen, payload = load_report(date, root)
    actions = _action_index(payload)
    items: list[dict[str, Any]] = []
    for article in payload.get("articles") or []:
        if not isinstance(article, dict):
            continue
        for evidence in article.get("evidence") or []:
            if not isinstance(evidence, dict):
                continue
            normalized = str(evidence.get("normalized_value") or "")
            raw = str(evidence.get("raw_value") or "")
            if needle not in {normalized.lower(), raw.lower()}:
                continue
            itype = str(evidence.get("indicator_type") or "")
            related = actions.get((itype, normalized), {})
            items.append(
                {
                    "indicator_type": itype,
                    "normalized_value": normalized,
                    "raw_value": raw,
                    "status": evidence.get("status"),
                    "reason_codes": evidence.get("reason_codes"),
                    "action": related.get("action"),
                    "priority": related.get("priority"),
                    "reason": related.get("reason"),
                    "kev": related.get("kev"),
                    "kev_due_date": related.get("kev_due_date"),
                    "cvss_score": related.get("cvss_score"),
                    "cvss_severity": related.get("cvss_severity"),
                    "article_title": article.get("article_title"),
                    "article_url": article.get("article_url"),
                    "section": evidence.get("section"),
                    "context": evidence.get("context"),
                }
            )
    return {"date": chosen, "count": len(items), "items": items}
