"""Public-safe IoC export for the Malware Analyser website.

The website at malware.nine-security.com runs on the same host as this collector,
under a different Unix user. It reads one JSON file from a shared, read-only
directory; this module writes that file from the D1 corpus, which is the same
data the MCP service answers from.

Three sides are merged per (type, value):
  * news   - values a publisher named in a confirmed IoC context (`indicators`);
  * sample - values the malware analyser extracted from an uploaded file
             (`sample_indicators`);
  * feed   - values abuse.ch lists (`feed_indicators`: ThreatFox, Feodo).

What is written, and what is not
  * indicator values, the action taken on them (news side), priority, reason,
    KEV and CVSS, and the names of the feeds and integrations that listed them;
  * one citation per news value (the most recent article), and the analyser
    report link for sample values;
  * NOT written: `context` (a source sentence), `canonical_body` (publisher text
    under redistribution terms), `raw_value`, and the analyser's job data.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

SCHEMA_VERSION = 2
PAGE_SIZE = 2000
MAX_INTEGRATIONS = 6
MAX_PUBLISHERS = 8
DEFAULT_DATABASE_ID = "819cd0ac-bd1a-43bd-91fd-9a21a9d34dd3"
API_URL = "https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{database}/query"
SAMPLE_REPORT_URL = "https://malware.nine-security.com/s/{sha256}"

Query = Callable[[str], list[dict[str, Any]]]


class ExportError(RuntimeError):
    """The corpus could not be read; the message names the cause and no secret."""


def d1_query_from_env(client: httpx.Client | None = None) -> Query:
    """A runner for read-only SQL against the IoC database, using the collector token."""
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    if not token or not account:
        raise ExportError("CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID must be set")
    url = API_URL.format(
        account=account,
        database=os.environ.get("D1_DATABASE_ID", DEFAULT_DATABASE_ID),
    )
    http = client or httpx.Client(timeout=60.0)

    def run(sql: str) -> list[dict[str, Any]]:
        try:
            response = http.post(url, json={"sql": sql}, headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError as error:
            raise ExportError(f"D1 request failed: {type(error).__name__}") from error
        if response.status_code != 200:
            raise ExportError(f"D1 returned HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as error:
            raise ExportError("D1 returned a non-JSON response") from error
        if not isinstance(body, dict) or not body.get("success"):
            raise ExportError("D1 rejected the query")
        try:
            return body["result"][0]["results"]
        except (KeyError, IndexError, TypeError) as error:
            raise ExportError("D1 returned an unexpected response shape") from error

    return run


def _pages(run: Query, table: str, columns: str, where: str) -> Iterator[dict[str, Any]]:
    """Every row of a table, in rowid order, one page at a time."""
    offset = 0
    while True:
        rows = run(
            f"SELECT {columns} FROM {table} {where} "
            f"ORDER BY rowid LIMIT {PAGE_SIZE} OFFSET {offset}"
        )
        yield from rows
        if len(rows) < PAGE_SIZE:
            return
        offset += PAGE_SIZE


def _day(value: Any) -> str | None:
    return str(value)[:10] if value else None


class _Merge:
    """Accumulates the three sides into one entry per (type, value)."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}
        self.news_urls: dict[tuple[str, str], set[str]] = {}
        self.news_publishers: dict[tuple[str, str], set[str]] = {}
        self.sample_hashes: dict[tuple[str, str], set[str]] = {}
        self.sample_latest: dict[tuple[str, str], str] = {}
        self.sample_integrations: dict[tuple[str, str], set[str]] = {}
        self.feed_entries: dict[tuple[str, str], set[tuple[str, str | None, str | None]]] = {}
        # Newest day each side has produced; the site shows how stale each side is.
        self.newest_by_side: dict[str, str | None] = {"news": None, "sample": None, "feed": None}

    def item(self, kind: str, value: str) -> dict[str, Any]:
        key = (kind, value)
        if key not in self.items:
            self.items[key] = {
                "type": kind,
                "value": value,
                "sides": [],
                "action": None,
                "priority": None,
                "reason": None,
                "kev": None,
                "cvss_score": None,
                "cvss_severity": None,
                "first_seen": None,
                "last_seen": None,
                "news": None,
                "samples": None,
                "feeds": None,
            }
        return self.items[key]

    def note_newest(self, side: str, day: str | None) -> None:
        if day is None:
            return
        current = self.newest_by_side[side]
        self.newest_by_side[side] = day if current is None else max(current, day)

    def seen(self, item: dict[str, Any], day: str | None) -> None:
        if day is None:
            return
        item["first_seen"] = day if item["first_seen"] is None else min(item["first_seen"], day)
        item["last_seen"] = day if item["last_seen"] is None else max(item["last_seen"], day)

    def add_side(self, item: dict[str, Any], side: str) -> None:
        if side not in item["sides"]:
            item["sides"].append(side)

    def news_row(self, row: dict[str, Any]) -> None:
        item = self.item(row["type"], row["value"])
        key = (row["type"], row["value"])
        day = _day(row["report_date"])
        self.add_side(item, "news")
        self.seen(item, day)
        self.note_newest("news", day)
        urls = self.news_urls.setdefault(key, set())
        if row["source"]:
            self.news_publishers.setdefault(key, set()).add(row["source"])
        if row["article_url"]:
            urls.add(row["article_url"])
        previous = item["news"]
        if previous is None or (day or "") >= (previous["_day"] or ""):
            for field in ("action", "priority", "reason", "kev", "cvss_score", "cvss_severity"):
                item[field] = row[field]
            item["news"] = {
                "_day": day,
                "source": row["source"],
                "title": row["article_title"],
                "url": row["article_url"],
            }

    def sample_row(self, row: dict[str, Any]) -> None:
        item = self.item(row["type"], row["value"])
        key = (row["type"], row["value"])
        self.add_side(item, "sample")
        self.seen(item, _day(row["first_seen_at"]))
        self.note_newest("sample", _day(row["first_seen_at"]))
        self.sample_hashes.setdefault(key, set()).add(row["sha256"])
        day = _day(row["first_seen_at"])
        if day and (key not in self.sample_latest or day > self.sample_latest[key]):
            self.sample_latest[key] = day
        if row["integration"]:
            self.sample_integrations.setdefault(key, set()).add(row["integration"])

    def feed_row(self, row: dict[str, Any]) -> None:
        item = self.item(row["type"], row["value"])
        key = (row["type"], row["value"])
        self.add_side(item, "feed")
        self.seen(item, _day(row["first_seen"]))
        self.seen(item, _day(row["last_seen"]))
        self.note_newest("feed", _day(row["last_seen"]) or _day(row["first_seen"]))
        self.feed_entries.setdefault(key, set()).add(
            (row["source"], row["threat_type"], row["malware"])
        )

    def finish(self) -> list[dict[str, Any]]:
        for key, item in self.items.items():
            if item["news"] is not None:
                item["news"] = {
                    "articles": len(self.news_urls.get(key, ())),
                    "publishers": sorted(self.news_publishers.get(key, ()))[:MAX_PUBLISHERS],
                    "publisher_count": len(self.news_publishers.get(key, ())),
                    "source": item["news"]["source"],
                    "title": item["news"]["title"],
                    "url": item["news"]["url"],
                }
            if key in self.sample_hashes:
                hashes = self.sample_hashes[key]
                item["samples"] = {
                    "count": len(hashes),
                    # The day the analyser first saw the newest of these files. A sample is
                    # not re-recorded when it reappears, so this is not a "last seen" date.
                    "latest_analysis": self.sample_latest.get(key),
                    "integrations": sorted(self.sample_integrations.get(key, ()))[:MAX_INTEGRATIONS],
                    "example_url": SAMPLE_REPORT_URL.format(sha256=min(hashes)),
                }
            if key in self.feed_entries:
                item["feeds"] = [
                    {"source": source, "threat_type": threat, "malware": malware}
                    for source, threat, malware in sorted(
                        self.feed_entries[key], key=lambda entry: tuple(str(p) for p in entry)
                    )
                ]
            item["sides"].sort()
        ordered = sorted(
            self.items.values(),
            key=lambda item: (item["last_seen"] or "", item["value"]),
            reverse=True,
        )
        return ordered


def build_document(
    run: Query | None = None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Read the three sides of the corpus and merge them into one document."""
    query = run or d1_query_from_env()
    generated = now or datetime.now(timezone.utc)
    merged = _Merge()

    for row in _pages(
        query,
        "indicators",
        "indicator_type AS type, value, report_date, action, priority, reason, kev, "
        "cvss_score, cvss_severity, source, article_title, article_url",
        "WHERE status = 'confirmed'",
    ):
        merged.news_row(row)
    for row in _pages(
        query,
        "sample_indicators",
        "indicator_type AS type, value, sha256, integration, first_seen_at",
        "",
    ):
        merged.sample_row(row)
    for row in _pages(
        query,
        "feed_indicators",
        "source, indicator_type AS type, value, threat_type, malware, first_seen, last_seen",
        "",
    ):
        merged.feed_row(row)

    indicators = merged.finish()
    counts = {
        side: sum(1 for item in indicators if side in item["sides"])
        for side in ("news", "sample", "feed")
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "indicator_count": len(indicators),
        "counts": counts,
        "newest_by_side": merged.newest_by_side,
        "indicators": indicators,
    }


def write_document(document: dict[str, Any], output: str | Path) -> Path:
    """Write atomically, world-readable, so the analyser's user can read it."""
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path
