"""Rebuild a day's report from a stored evidence JSON, using the current parser.

A day collected near its window holds more than any later collection can get
back: feeds carry only their most recent items, and re-collecting the same window
three days later returned 45% of the articles. So when the best surviving copy of
a day was produced by an older parser revision, fetching it again is the wrong
fix -- that returns the decayed copy. The right one is to run today's extraction
and analysis over the article bodies the good copy already stored.

That works because `canonical_body` is exactly what the parser extracted:
`build_manifest` stores `article.body` verbatim. Re-extracting from it reproduces
what extraction saw that day, and the whole report pipeline after the fetch --
deduplication, topic relevance, enrichment, the analyst brief, counts, the report
id -- runs unchanged, because it only ever reads manifests.

Two things are not reproduced, and the output says so rather than implying
otherwise. The fetch is not repeated, so an article whose body was unavailable at
collection stays unavailable. And CVE enrichment -- KEV, CVSS, EPSS -- reflects the
day the re-analysis runs, not the day the articles were collected.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .parser import ParsedArticle, parse_utc
from .report import DailyReport, collect_report
from .sources import SOURCES

SOURCE_KEY_BY_NAME = {source.name: key for key, source in SOURCES.items()}


def _stored_articles(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Every stored manifest, kept and excluded alike.

    Excluded articles go back in too. Topic relevance is decided again by the
    current code, and an article an older revision excluded may be one the
    current revision keeps -- leaving them out would freeze the old decision.
    """
    return [
        item
        for item in (payload.get("articles") or []) + (payload.get("excluded_articles") or [])
        if isinstance(item, dict)
    ]


def parsed_article_from_manifest(item: dict[str, Any]) -> ParsedArticle | None:
    """Reconstruct what the parser handed to `build_manifest`, or None if unknown.

    `publisher_hosts` is not stored in the manifest; it comes from the source
    registry. It is what lets extraction recognise a publisher's own domain in its
    own article and reject it, so dropping it would turn every self-link back into
    a confirmed indicator.
    """
    name = str(item.get("source") or "")
    key = SOURCE_KEY_BY_NAME.get(name)
    if key is None:
        return None
    body = str(item.get("canonical_body") or "")
    return ParsedArticle(
        source=name,
        title=str(item.get("article_title") or ""),
        url=str(item.get("article_url") or ""),
        published_at=item.get("published_at"),
        body=body,
        extraction_method=str(item.get("extraction_method") or ""),
        body_characters=int(item.get("body_characters") or len(body)),
        warnings=[str(w) for w in (item.get("extraction_warnings") or [])],
        feed_excerpt=item.get("source_summary"),
        publisher_hosts=tuple(SOURCES[key].article_hosts),
    )


@dataclass
class StoredParser:
    """Stands in for NewsParser: serves stored articles instead of fetching them."""

    by_source: dict[str, list[ParsedArticle]] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)

    def parse_feed(self, source: Any, **_: Any) -> list[ParsedArticle]:
        return list(self.by_source.get(source.name, []))


@dataclass(frozen=True)
class Reanalysis:
    report: DailyReport
    provenance: dict[str, Any]


def reanalyze(
    payload: dict[str, Any],
    *,
    source_path: str | Path | None = None,
    enricher: Callable[[list], tuple[dict, Any]] | None = None,
    previous_iocs: set[tuple[str, str]] | None = None,
    now: datetime | None = None,
) -> Reanalysis:
    window_start = payload.get("window_start")
    window_end = payload.get("window_end")
    if not window_start or not window_end:
        # The window is what the day *is*. Guessing it would put the re-analysed
        # articles under a different day's key.
        raise ValueError("stored report has no window_start/window_end")

    by_source: dict[str, list[ParsedArticle]] = {}
    unknown_sources: set[str] = set()
    stored = _stored_articles(payload)
    for item in stored:
        article = parsed_article_from_manifest(item)
        if article is None:
            unknown_sources.add(str(item.get("source") or ""))
            continue
        by_source.setdefault(article.source, []).append(article)

    checked = [key for key in (payload.get("sources_checked") or []) if key in SOURCES]
    for name in by_source:
        key = SOURCE_KEY_BY_NAME[name]
        if key not in checked:
            checked.append(key)

    generated_at = parse_utc(payload["generated_at"]) if payload.get("generated_at") else None
    report = collect_report(
        StoredParser(by_source),  # type: ignore[arg-type]
        checked,
        since=parse_utc(window_start),
        until=parse_utc(window_end),
        generated_at=generated_at,
        previous_iocs=previous_iocs,
        enricher=enricher,
    )

    raw = None
    if source_path is not None:
        raw = Path(source_path).read_bytes()
    with_body = sum(1 for item in stored if str(item.get("canonical_body") or "").strip())
    provenance = {
        "reanalyzed_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "source_file_sha256": hashlib.sha256(raw).hexdigest() if raw is not None else None,
        "original": {
            "report_id": payload.get("report_id"),
            "schema_version": payload.get("schema_version"),
            "generated_at": payload.get("generated_at"),
            "parser_revisions": sorted(
                {str(item.get("parser_revision")) for item in stored if item.get("parser_revision")}
            ),
            "article_count": payload.get("article_count"),
            "confirmed_ioc_count": payload.get("confirmed_ioc_count"),
        },
        "stored_articles": len(stored),
        "stored_articles_with_body": with_body,
        "unknown_sources_skipped": sorted(unknown_sources),
        "not_reproduced": [
            "the fetch: an article whose body was unavailable at collection is still unavailable",
            "CVE enrichment (KEV, CVSS, EPSS) reflects reanalyzed_at, not the collection date",
        ],
    }
    return Reanalysis(report=report, provenance=provenance)


def attach_provenance(json_content: str, provenance: dict[str, Any]) -> str:
    """Add the re-analysis record to a serialized report without touching the rest.

    `reader_digest` covers the Markdown, not the JSON, and `report_id` is computed
    from the report's identity before serialization, so neither moves.
    """
    payload = json.loads(json_content)
    payload["reanalysis"] = provenance
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
