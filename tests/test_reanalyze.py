import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc_news_parser.parser import ParsedArticle
from soc_news_parser.reanalyze import (
    StoredParser,
    attach_provenance,
    parsed_article_from_manifest,
    reanalyze,
)
from soc_news_parser.report import collect_report, serialize_report
from soc_news_parser.sources import SOURCES

SINCE = datetime(2026, 9, 2, 22, 0, tzinfo=timezone.utc)
UNTIL = datetime(2026, 9, 3, 22, 0, tzinfo=timezone.utc)

BODY = (
    "Microsoft has patched CVE-2026-31337, a remote code execution vulnerability "
    "that attackers exploited before a fix was available. The flaw affects the "
    "Windows print spooler, and CISA added it to the Known Exploited Vulnerabilities "
    "catalog. Researchers observed exploitation against government networks."
)


def _article(source_key: str, title: str, url: str, body: str = BODY) -> ParsedArticle:
    source = SOURCES[source_key]
    return ParsedArticle(
        source=source.name,
        title=title,
        url=url,
        published_at="2026-09-03T09:00:00+00:00",
        body=body,
        extraction_method="site-selector:main",
        body_characters=len(body),
        warnings=[],
        publisher_hosts=tuple(source.article_hosts),
    )


class _Parser:
    def __init__(self, articles: list[ParsedArticle]) -> None:
        self.articles = articles
        self.diagnostics: list[str] = []

    def parse_feed(self, source, **_):
        return [a for a in self.articles if a.source == source.name]


def _stored_payload(articles: list[ParsedArticle]) -> dict:
    report = collect_report(
        _Parser(articles),  # type: ignore[arg-type]
        ["the-hacker-news", "bleepingcomputer"],
        since=SINCE,
        until=UNTIL,
        generated_at=UNTIL,
    )
    json_content, _ = serialize_report(report)
    return json.loads(json_content)


def _confirmed(payload_or_report) -> set[tuple[str, str]]:
    articles = (
        payload_or_report["articles"]
        if isinstance(payload_or_report, dict)
        else [m.to_dict() for m in payload_or_report.articles]
    )
    return {
        (e["indicator_type"], e["normalized_value"])
        for a in articles
        for e in (a.get("evidence") or [])
        if e.get("status") == "confirmed"
    }


def test_reanalysing_a_current_report_reproduces_it() -> None:
    """The claim the whole module rests on: the stored body is what extraction saw.

    If a report produced by the current code, re-analysed by the current code,
    came back different, then re-analysing an old report would be measuring the
    round trip rather than the parser.
    """
    payload = _stored_payload(
        [
            _article("the-hacker-news", "Microsoft patches exploited spooler flaw",
                     "https://thehackernews.com/2026/09/spooler.html"),
            _article("bleepingcomputer", "Windows spooler zero-day exploited",
                     "https://www.bleepingcomputer.com/news/security/spooler/"),
        ]
    )
    assert _confirmed(payload), "fixture must confirm something or the test proves nothing"

    result = reanalyze(payload)

    assert _confirmed(result.report) == _confirmed(payload)
    assert result.report.report_id == payload["report_id"]
    assert result.report.window_start == payload["window_start"]
    assert result.report.window_end == payload["window_end"]


def test_an_article_without_a_body_stays_without_evidence() -> None:
    """The fetch is not repeated; an unavailable body is still unavailable."""
    empty = _article("the-hacker-news", "Security advisory without a body",
                     "https://thehackernews.com/2026/09/empty.html", body="")
    payload = _stored_payload(
        [empty, _article("bleepingcomputer", "Windows spooler zero-day exploited",
                         "https://www.bleepingcomputer.com/news/security/spooler/")]
    )

    result = reanalyze(payload)

    urls = {m.article_url: m for m in result.report.articles + result.report.excluded_articles}
    assert "https://thehackernews.com/2026/09/empty.html" in urls
    assert urls["https://thehackernews.com/2026/09/empty.html"].evidence == []
    assert result.provenance["stored_articles_with_body"] == 1


def test_excluded_articles_are_decided_again() -> None:
    """An older revision's exclusion is an input to re-analysis, not a verdict on it."""
    payload = _stored_payload(
        [_article("the-hacker-news", "Microsoft patches exploited spooler flaw",
                  "https://thehackernews.com/2026/09/spooler.html")]
    )
    moved = payload["articles"].pop()
    payload["excluded_articles"] = [moved]

    result = reanalyze(payload)

    assert [m.article_url for m in result.report.articles] == [moved["article_url"]]


def test_publisher_hosts_come_back_from_the_registry() -> None:
    """They are not stored, and without them a publisher's self-links become indicators."""
    item = {
        "source": "The Hacker News",
        "article_title": "t",
        "article_url": "https://thehackernews.com/x",
        "canonical_body": "body",
    }

    article = parsed_article_from_manifest(item)

    assert article is not None
    assert article.publisher_hosts == tuple(SOURCES["the-hacker-news"].article_hosts)
    assert article.publisher_hosts, "the registry must name at least one host"


def test_an_unknown_source_is_recorded_not_guessed() -> None:
    payload = _stored_payload(
        [_article("the-hacker-news", "Microsoft patches exploited spooler flaw",
                  "https://thehackernews.com/2026/09/spooler.html")]
    )
    payload["articles"][0]["source"] = "A Publisher That Was Removed"

    result = reanalyze(payload)

    assert result.provenance["unknown_sources_skipped"] == ["A Publisher That Was Removed"]
    assert result.report.articles == []


def test_a_report_without_a_window_is_refused() -> None:
    """The window is what the day is; guessing it files articles under another day."""
    with pytest.raises(ValueError):
        reanalyze({"articles": []})


def test_provenance_names_what_was_not_reproduced(tmp_path: Path) -> None:
    payload = _stored_payload(
        [_article("the-hacker-news", "Microsoft patches exploited spooler flaw",
                  "https://thehackernews.com/2026/09/spooler.html")]
    )
    path = tmp_path / "stored.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    result = reanalyze(payload, source_path=path)
    json_content, _ = serialize_report(result.report)
    written = json.loads(attach_provenance(json_content, result.provenance))

    record = written["reanalysis"]
    assert len(record["source_file_sha256"]) == 64
    assert record["original"]["report_id"] == payload["report_id"]
    assert any("enrichment" in line for line in record["not_reproduced"])
    # The report itself is untouched by the provenance record.
    assert written["report_id"] == payload["report_id"]
    assert written["reader_digest"] == json.loads(json_content)["reader_digest"]


def test_the_stored_parser_serves_only_the_requested_source() -> None:
    a = _article("the-hacker-news", "t1", "https://thehackernews.com/1")
    b = _article("bleepingcomputer", "t2", "https://www.bleepingcomputer.com/2")
    parser = StoredParser({a.source: [a], b.source: [b]})

    assert parser.parse_feed(SOURCES["the-hacker-news"]) == [a]
    assert parser.parse_feed(SOURCES["cisa-advisories"]) == []
