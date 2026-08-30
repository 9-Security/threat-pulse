import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc_news_parser import _write_report_pair
from soc_news_parser.evidence import build_manifest
from soc_news_parser.parser import ParseError, ParsedArticle
from soc_news_parser.report import (
    _source_summary,
    collect_report,
    render_markdown,
    serialize_report,
)


def parsed_article(source: str, title: str, body: str) -> ParsedArticle:
    return ParsedArticle(
        source=source,
        title=title,
        url=f"https://example.test/{title.lower().replace(' ', '-')}",
        published_at="2026-08-29T12:00:00+00:00",
        body=body,
        extraction_method="feed:content",
        body_characters=len(body),
        warnings=[],
    )


class FakeParser:
    def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
        name = getattr(source, "name")
        if name == "BleepingComputer":
            raise ParseError("simulated source failure")
        if name == "The Hacker News":
            return [
                parsed_article(
                    name,
                    "First report",
                    """Indicators of Compromise
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
evil[.]example
payload.exe
""",
                ),
                parsed_article(
                    name,
                    "Second report",
                    """Security analysis
The report mentions evil[.]example without characterizing it.
""",
                ),
            ]
        return []


def test_report_counts_unique_confirmed_values_and_failures() -> None:
    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        FakeParser(),  # type: ignore[arg-type]
        ["the-hacker-news", "the-hacker-news", "bleepingcomputer"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )

    assert report.collected_article_count == 2
    assert report.article_count == 1
    assert report.excluded_article_count == 1
    assert report.sources_checked == ["the-hacker-news", "bleepingcomputer"]
    assert report.confirmed_ioc_count == 2
    assert report.confirmed_filename_count == 1
    assert report.subject.endswith("文章數 1 / IoC數 2")
    assert len(report.source_failures) == 1
    assert len(report.report_id) == 64

    markdown = render_markdown(report)
    assert "simulated source failure" not in markdown
    assert "Candidate 唯一值" not in markdown
    assert "正文 SHA-256" not in markdown
    assert "Parser" not in markdown
    assert report.report_id not in markdown
    assert "完整證據、候選值、排除理由與程式診斷" in markdown
    assert "查核來源：2 個" in markdown
    assert "期間內有新文來源：1 個" in markdown
    assert "原文指稱：0 項" in markdown


def test_report_outputs_must_use_different_paths(tmp_path: Path) -> None:
    path = str(tmp_path / "report.out")
    with pytest.raises(ValueError, match="must be different"):
        _write_report_pair(path, path, "{}", "# report")


def test_markdown_escapes_untrusted_title() -> None:
    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        FakeParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )
    report.articles[0] = replace(
        report.articles[0],
        article_title="Report ![tracker](https://evil.example/x.png)",
    )

    markdown = render_markdown(report)
    assert "![tracker]" not in markdown
    assert "\\!\\[tracker\\]" in markdown


def test_reader_summary_removes_feed_footer_and_incomplete_tail() -> None:
    article = parsed_article("SecurityWeek", "Security breach", "Body")
    article.feed_excerpt = (
        "A complete security incident sentence. "
        "An incomplete trailing fragment without punctuation\n"
        "The post Security breach appeared first on SecurityWeek."
    )
    summary = _source_summary(build_manifest(article))

    assert summary == "A complete security incident sentence."
    assert "appeared first" not in summary


def test_reader_summary_keeps_complete_chinese_sentence() -> None:
    article = parsed_article("TWCERT/CC TVN", "資安通報", "Body")
    article.feed_excerpt = (
        "這是一句完整的資安事件說明。後面這段沒有句號所以不應留下"
    )
    summary = _source_summary(build_manifest(article))

    assert summary == "這是一句完整的資安事件說明。"


def test_reader_summary_does_not_treat_decimal_as_sentence_end() -> None:
    article = parsed_article("The Hacker News", "WordPress flaws", "Body")
    article.feed_excerpt = (
        "A complete security incident sentence. "
        "CVE-2026-76581 (CVSS score: 9.8) - An authentication bypass flaw in"
    )
    summary = _source_summary(build_manifest(article))

    assert summary == "A complete security incident sentence."
    assert "CVSS" not in summary


def test_reader_summary_strips_read_more_ellipsis() -> None:
    article = parsed_article("BleepingComputer", "Security breach", "Body")
    article.feed_excerpt = (
        "The latest version of the Brave browser introduces aliases. [...]"
    )
    summary = _source_summary(build_manifest(article))

    assert summary == "The latest version of the Brave browser introduces aliases."
    assert "[...]" not in summary


def test_reader_summary_does_not_truncate_at_abbreviation() -> None:
    article = parsed_article("SecurityWeek", "Security breach", "Body")
    article.feed_excerpt = (
        "Dr. Chen is investigating an active malware incident without a closing mark"
    )
    summary = _source_summary(build_manifest(article))

    assert summary.startswith("Dr. Chen")
    assert "malware incident" in summary


def test_topic_filter_keeps_security_articles_without_iocs() -> None:
    class TopicParser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            return [
                parsed_article(
                    getattr(source, "name"),
                    "Hospitals hit by ransomware campaign",
                    "No indicators are listed in this article.",
                ),
                parsed_article(
                    getattr(source, "name"),
                    "Quarterly earnings beat expectations",
                    "Revenue grew this quarter after a product launch.",
                ),
            ]

    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        TopicParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )

    assert report.collected_article_count == 2
    assert report.article_count == 1
    assert report.excluded_article_count == 1
    assert report.articles[0].article_title == "Hospitals hit by ransomware campaign"
    assert (
        report.excluded_articles[0].article_title
        == "Quarterly earnings beat expectations"
    )
    markdown = render_markdown(report)
    assert "Hospitals hit by ransomware campaign" in markdown
    assert "Quarterly earnings" not in markdown
    assert "IoC：原文未提供明確指標。" in markdown


def test_same_source_keeps_every_same_day_article_with_iocs() -> None:
    class BusySourceParser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            name = getattr(source, "name")
            morning = parsed_article(
                name,
                "Morning ransomware note",
                "Indicators of Compromise\n"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                "shared[.]example\n",
            )
            afternoon = parsed_article(
                name,
                "Afternoon phishing wave",
                "Indicators of Compromise\nshared[.]example\nphish[.]example\n",
            )
            evening = parsed_article(
                name,
                "Evening CVE advisory",
                "CVE-2026-76581 allows unauthenticated takeover.\n",
            )
            morning.published_at = "2026-08-29T08:00:00+00:00"
            afternoon.published_at = "2026-08-29T14:00:00+00:00"
            evening.published_at = "2026-08-29T20:00:00+00:00"
            return [morning, afternoon, evening]

    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        BusySourceParser(),  # type: ignore[arg-type]
        ["bleepingcomputer"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )
    markdown = render_markdown(report)
    titles = [item.article_title for item in report.articles]

    assert report.active_source_count == 1
    assert report.article_count == 3
    assert titles == [
        "Evening CVE advisory",
        "Afternoon phishing wave",
        "Morning ransomware note",
    ]
    assert report.confirmed_ioc_count == 4
    assert "Morning ransomware note" in markdown
    assert "Afternoon phishing wave" in markdown
    assert "Evening CVE advisory" in markdown
    assert markdown.count("### 明確 IoC") == 3
    assert "`shared.example`" in markdown
    assert "`phish.example`" in markdown
    assert "`CVE-2026-76581`" in markdown


def test_reader_report_includes_explicit_cves_and_quoted_claims() -> None:
    class ClaimParser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            return [
                parsed_article(
                    getattr(source, "name"),
                    "Campaign analysis",
                    """Researchers tracked the malware family named LockBit.
The operators used ATT&CK technique T1059.001 during execution.
CVE-2026-76581 allows unauthenticated takeover.
    A feature called Email Aliases is unrelated.
    Related : ATF Confirms Cyber Incident After Ransomware Group Claims Attack
    (Affects all versions up to, and including, 4.16.7.1)
""",
                )
            ]

    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        ClaimParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )
    markdown = render_markdown(report)

    assert report.confirmed_ioc_count == 1
    assert report.confirmed_claim_count == 2
    assert report.subject.endswith("文章數 1 / IoC數 1")
    assert "**CVE**：`CVE-2026-76581`" in markdown
    assert "**惡意程式家族**：`LockBit`" in markdown
    assert "**攻擊技術**：`T1059.001`" in markdown
    assert "**惡意程式家族**：`Email Aliases`" not in markdown
    assert "**惡意程式家族**：`After`" not in markdown
    assert "4.16.7.1" not in markdown
    cve_block = markdown.split("### 明確 IoC", 1)[1].split("## 報告說明", 1)[0]
    assert "Email Aliases" not in cve_block


def test_serialize_report_pairs_json_to_reader_digest() -> None:
    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        FakeParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )
    json_content, markdown = serialize_report(report)
    payload = json.loads(json_content)

    assert report.report_id not in markdown
    assert payload["reader_digest"] == hashlib.sha256(markdown.encode()).hexdigest()
