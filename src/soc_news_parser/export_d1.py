"""Turn a daily report JSON into SQL for the D1-backed IoC service.

Only what the service answers with travels: indicator values, the actions and
reasons this project derived, KEV/NVD facts, and the article title and link.
`canonical_body` never leaves the audit file - it is 26 publishers' full text,
some of it under redistribution terms, and no query needs it.

Statements are idempotent, so re-pushing a day repairs it rather than
duplicating it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from .ioc_query import REPORT_DATE_RE
from .publicsuffix import registrable_domain
from .schedule import DEFAULT_TIMEZONE, slot_date_key

COUNTED_TYPES = frozenset({"md5", "sha1", "sha256", "ip", "domain", "url", "cve"})
EXPORTED_STATUSES = frozenset({"confirmed"})
# A context line is a verbatim source sentence; keep it short enough to be a
# citation rather than a reproduction.
MAX_CONTEXT_CHARS = 300


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    text = str(value).replace("'", "''")
    return f"'{text}'"


def _row(values: Iterable[Any]) -> str:
    return "(" + ", ".join(_sql_literal(item) for item in values) + ")"


def _clip(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    flattened = " ".join(value.split())
    if len(flattened) <= MAX_CONTEXT_CHARS:
        return flattened
    return flattened[:MAX_CONTEXT_CHARS].rsplit(" ", 1)[0] + "…"


def _actions_by_target(payload: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    brief = payload.get("analyst_brief")
    actions = brief.get("actions") if isinstance(brief, dict) else None
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for action in actions or []:
        if not isinstance(action, dict):
            continue
        key = (str(action.get("target_type") or ""), str(action.get("target") or ""))
        indexed.setdefault(key, action)
    return indexed


def _kev_count(payload: dict[str, Any]) -> int:
    brief = payload.get("analyst_brief")
    actions = brief.get("actions") if isinstance(brief, dict) else None
    return len(
        {
            str(item.get("target"))
            for item in actions or []
            if isinstance(item, dict) and item.get("action") == "patch" and item.get("kev")
        }
    )


def _registrable(kind: str, value: str) -> str | None:
    """The key the service uses to find values *beneath* a submitted domain.

    Domains only, as in the offline validator: a URL's registrable domain is
    never used for a child relation there, so it is not used here either.
    """
    if kind != "domain":
        return None
    return registrable_domain(value) or None


def indicator_rows(payload: dict[str, Any], report_date: str) -> Iterator[tuple[Any, ...]]:
    """Every confirmed indicator, joined to the action taken on it."""
    actions = _actions_by_target(payload)
    # The snapshot keys actions by target alone, lower-cased. Falling back to that
    # keeps the hosted answer and the offline one from differing on case.
    by_lower = {target.lower(): action for (_, target), action in reversed(list(actions.items()))}
    seen: set[tuple[str, str, str]] = set()
    for article in payload.get("articles") or []:
        if not isinstance(article, dict):
            continue
        url = str(article.get("article_url") or "")
        for evidence in article.get("evidence") or []:
            if not isinstance(evidence, dict):
                continue
            if evidence.get("status") not in EXPORTED_STATUSES:
                continue
            kind = str(evidence.get("indicator_type") or "")
            value = str(evidence.get("normalized_value") or "")
            if not kind or not value or not url:
                continue
            key = (kind, value, url)
            if key in seen:
                continue
            seen.add(key)
            action = actions.get((kind, value)) or by_lower.get(value.lower()) or {}
            yield (
                report_date,
                kind,
                value,
                evidence.get("raw_value"),
                evidence.get("status"),
                action.get("action"),
                action.get("priority"),
                action.get("reason"),
                action.get("kev"),
                action.get("kev_due_date"),
                action.get("cvss_score"),
                action.get("cvss_severity"),
                article.get("source"),
                article.get("article_title"),
                url,
                evidence.get("section"),
                _clip(evidence.get("context")),
                action.get("benign_basis"),
                action.get("epss_score"),
                action.get("epss_percentile"),
                article.get("published_at"),
                _registrable(kind, value),
            )


def excluded_rows(payload: dict[str, Any], report_date: str) -> Iterator[tuple[Any, ...]]:
    """Values the pipeline saw and ruled out, with every reason given that day.

    Built as the snapshot builds its excluded set, so the hosted service and the
    offline validator answer `excluded` for the same values. One row per value
    per day; reasons from several articles are merged in first-seen order.
    """
    rows: dict[str, list[Any]] = {}
    for article in payload.get("articles") or []:
        if not isinstance(article, dict):
            continue
        for evidence in article.get("evidence") or []:
            if not isinstance(evidence, dict) or evidence.get("status") != "rejected":
                continue
            value = str(evidence.get("normalized_value") or "").strip()
            if not value:
                continue
            row = rows.setdefault(value.lower(), [value, str(evidence.get("indicator_type") or ""), []])
            for code in evidence.get("reason_codes") or []:
                if str(code) not in row[2]:
                    row[2].append(str(code))
    for value, kind, codes in rows.values():
        yield (report_date, kind, value, json.dumps(codes, ensure_ascii=False))


def cve_intel_rows(payload: dict[str, Any], report_date: str) -> Iterator[tuple[Any, ...]]:
    """The day's KEV/CVSS/EPSS record per CVE, verbatim, provenance included."""
    for cve_id, record in (payload.get("cve_intel") or {}).items():
        if isinstance(record, dict):
            yield (report_date, str(cve_id).upper(), json.dumps(record, ensure_ascii=False, sort_keys=True))


def _sources_failed(payload: dict[str, Any]) -> str:
    keys = {
        str(item.get("source_key"))
        for item in payload.get("source_failures") or []
        if isinstance(item, dict) and item.get("source_key")
    }
    return json.dumps(sorted(keys))


def corpus_state_row(snapshot: dict[str, Any], computed_at: str) -> tuple[Any, ...]:
    """What the service reports as `corpus_version`, taken from the offline build.

    The version is the one `snapshot` would put in a bundle built from the same
    report folder, so a hosted answer and an offline one can be compared by it.
    The service only reports it while D1 holds exactly the days it was built from.
    """
    corpus = snapshot["corpus"]
    publishers = {name for row in snapshot["values"].values() for name in row.get("publishers") or []}
    return (
        1,
        snapshot["corpus_version"],
        corpus["days"],
        corpus["first_date"],
        corpus["last_date"],
        corpus["confirmed_values"],
        corpus["excluded_values"],
        corpus["cve_records"],
        len(publishers),
        snapshot["public_suffix_list_version"],
        computed_at,
    )


def report_row(payload: dict[str, Any], report_date: str, ingested_at: str) -> tuple[Any, ...]:
    brief = payload.get("analyst_brief") or {}
    return (
        report_date,
        payload.get("report_id"),
        payload.get("subject"),
        payload.get("window_start"),
        payload.get("window_end"),
        payload.get("generated_at"),
        payload.get("article_count") or 0,
        payload.get("confirmed_ioc_count") or 0,
        brief.get("patch_count") or 0,
        brief.get("block_count") or 0,
        brief.get("hunt_count") or 0,
        _kev_count(payload),
        brief.get("unavailable_count") or 0,
        brief.get("priority_line"),
        json.dumps(payload.get("enrichment") or {}, ensure_ascii=False),
        ingested_at,
        _sources_failed(payload),
    )


INDICATOR_COLUMNS = (
    "report_date, indicator_type, value, raw_value, status, action, priority, "
    "reason, kev, kev_due_date, cvss_score, cvss_severity, source, "
    "article_title, article_url, section, context, benign_basis, "
    "epss_score, epss_percentile, published_at, registrable_lc"
)
EXCLUDED_COLUMNS = "report_date, indicator_type, value, reason_codes"
CVE_INTEL_COLUMNS = "report_date, cve_id, record"
CORPUS_STATE_COLUMNS = (
    "id, corpus_version, days, first_date, last_date, confirmed_values, "
    "excluded_values, cve_records, publisher_count, psl_version, computed_at"
)
# D1 rejects an over-long statement with SQLITE_TOOBIG. Batches are sized by
# encoded length, not character count: a Chinese-language advisory is three
# bytes per character, and a 40,000-character batch already went out at 41 KB.
MAX_STATEMENT_BYTES = 40_000


def _encoded(text: str) -> int:
    """Bytes on the wire, which is what D1 measures."""
    return len(text.encode("utf-8"))


def _insert_batches(
    rows: list[tuple[Any, ...]],
    table: str = "indicators",
    columns: str = INDICATOR_COLUMNS,
) -> Iterator[str]:
    header = f"INSERT OR REPLACE INTO {table} ({columns}) VALUES"
    batch: list[str] = []
    size = _encoded(header)
    for row in rows:
        rendered = _row(row)
        if batch and size + _encoded(rendered) + 2 > MAX_STATEMENT_BYTES:
            yield header + "\n" + ",\n".join(batch) + ";"
            batch, size = [], _encoded(header)
        batch.append(rendered)
        size += _encoded(rendered) + 2
    if batch:
        yield header + "\n" + ",\n".join(batch) + ";"


def render_sql(
    payload: dict[str, Any],
    report_date: str,
    *,
    ingested_at: str | None = None,
    corpus_state: tuple[Any, ...] | None = None,
) -> str:
    """Statements only, no explicit transaction: D1 runs a file as one batch.

    `corpus_state`, when given, is written in the same batch as the day, so the
    version the service reports can never describe a push that failed.
    """
    stamp = ingested_at or datetime.now(timezone.utc).isoformat()
    day = _sql_literal(report_date)
    lines = [
        f"-- {report_date}: confirmed indicators, exclusions and CVE records; no article bodies.",
        f"DELETE FROM indicators WHERE report_date = {day};",
        f"DELETE FROM excluded_values WHERE report_date = {day};",
        f"DELETE FROM cve_intel WHERE report_date = {day};",
        "INSERT OR REPLACE INTO reports (report_date, report_id, subject, "
        "window_start, window_end, generated_at, article_count, "
        "confirmed_ioc_count, patch_count, block_count, hunt_count, kev_count, "
        "unavailable_count, priority_line, enrichment_json, ingested_at, sources_failed) VALUES",
        _row(report_row(payload, report_date, stamp)) + ";",
    ]
    lines.extend(_insert_batches(list(indicator_rows(payload, report_date))))
    lines.extend(_insert_batches(list(excluded_rows(payload, report_date)), "excluded_values", EXCLUDED_COLUMNS))
    lines.extend(_insert_batches(list(cve_intel_rows(payload, report_date)), "cve_intel", CVE_INTEL_COLUMNS))
    if corpus_state is not None:
        lines.append(f"INSERT OR REPLACE INTO corpus_state ({CORPUS_STATE_COLUMNS}) VALUES")
        lines.append(_row(corpus_state) + ";")
    return "\n".join(lines) + "\n"


def report_date_for(
    payload: dict[str, Any],
    fallback: str | None = None,
    timezone_name: str = DEFAULT_TIMEZONE,
) -> str:
    """The report's own day key, in the same timezone the folders use.

    `deliver` names folders by the local slot date, so a window ending
    2026-09-04T22:00Z is the 2026-09-05 report in Asia/Taipei. Keying D1 off the
    UTC date instead would give the same report two different names in two
    systems.
    """
    window_end = payload.get("window_end")
    if isinstance(window_end, str) and window_end:
        try:
            return slot_date_key(datetime.fromisoformat(window_end), timezone_name)
        except (ValueError, KeyError):
            pass
    if fallback:
        return fallback
    raise ValueError("report JSON has no usable window_end and no fallback date")


def export_report(
    json_path: str | Path,
    *,
    report_date: str | None = None,
    ingested_at: str | None = None,
    timezone_name: str = DEFAULT_TIMEZONE,
    corpus_state_from: str | Path | None = None,
) -> str:
    path = Path(json_path).expanduser()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("report JSON is not an object")
    # A dated folder names the report already; trust it over any derivation.
    if report_date is not None and not REPORT_DATE_RE.match(report_date):
        # It becomes the primary key, so a typo would write rows no later
        # re-push could replace and no query could select.
        raise ValueError("report date must be a plain YYYY-MM-DD key")
    folder = path.parent.name if REPORT_DATE_RE.match(path.parent.name) else None
    chosen = report_date or folder or report_date_for(payload, timezone_name=timezone_name)
    state = None
    if corpus_state_from is not None:
        from .snapshot import build_snapshot  # the snapshot imports this package's helpers

        snapshot = build_snapshot(corpus_state_from)
        if chosen not in {day["report_date"] for day in snapshot["coverage"]}:
            # The version would describe a corpus without the day being pushed.
            raise ValueError(f"{chosen} is not a report day under {corpus_state_from}")
        state = corpus_state_row(snapshot, datetime.now(timezone.utc).isoformat(timespec="seconds"))
    return render_sql(payload, chosen, ingested_at=ingested_at, corpus_state=state)
