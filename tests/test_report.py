import hashlib
import json
import os
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc_news_parser import _parse_env_line, _write_report_pair
from soc_news_parser.evidence import build_manifest
from soc_news_parser.parser import ParseError, ParsedArticle
from soc_news_parser.analyst import render_ioc_csv_from_actions
from soc_news_parser.enrich import KEV_URL, CveIntel, EnrichmentReport
from soc_news_parser.report import (
    _canonical_article_url,
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
evil[.]example.com
payload.exe
""",
                ),
                parsed_article(
                    name,
                    "Second report",
                    """Security analysis
The report mentions evil[.]example.com without characterizing it.
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
    assert report.subject.endswith("待修 0 / 待封鎖 1 / 待hunt 2 / 文章數 1")
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
    assert "今日處置清單" in markdown
    assert "### 封鎖" in markdown
    assert "### Hunt" in markdown


def test_report_outputs_must_use_different_paths(tmp_path: Path) -> None:
    path = str(tmp_path / "report.out")
    with pytest.raises(ValueError, match="must be different"):
        _write_report_pair(path, path, "{}", "# report")


def test_write_report_pair_rolls_back_when_second_replace_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"
    json_path.write_text("old-json", encoding="utf-8")
    markdown_path.write_text("old-md", encoding="utf-8")
    original = os.replace

    def flaky_replace(src: str | Path, dst: str | Path) -> None:
        source = Path(src)
        destination = Path(dst)
        if (
            destination.name == "report.md"
            and source.name.startswith(".report.md.")
            and not source.name.endswith(".bak")
        ):
            raise OSError("disk full")
        original(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)

    with pytest.raises(OSError, match="disk full"):
        _write_report_pair(str(json_path), str(markdown_path), "new-json", "new-md")

    assert json_path.read_text(encoding="utf-8") == "old-json"
    assert markdown_path.read_text(encoding="utf-8") == "old-md"


def test_env_line_parser_accepts_export_and_strips_comments() -> None:
    assert _parse_env_line("export RESEND_TO=a@b.com # dest") == (
        "RESEND_TO",
        "a@b.com",
    )
    assert _parse_env_line('RESEND_FROM="SOC <a@b.com>"') == (
        "RESEND_FROM",
        "SOC <a@b.com>",
    )
    assert _parse_env_line("# comment") is None
    assert _parse_env_line("1INVALID=no") is None


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
        article_title="Report ![tracker](https://evil.example.com/x.png)",
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
    # Kept, but as a one-line entry rather than a full section.
    assert "## 其他相關文章" in markdown
    assert "## 1. Hospitals hit by ransomware campaign" not in markdown
    assert "今日沒有可立即修補、封鎖或 hunt 的明確指標。" in markdown
    assert "### 觀察" in markdown


def test_same_source_keeps_every_same_day_article_with_iocs() -> None:
    class BusySourceParser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            name = getattr(source, "name")
            morning = parsed_article(
                name,
                "Morning ransomware note",
                "Indicators of Compromise\n"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
                "shared[.]example.com\n",
            )
            afternoon = parsed_article(
                name,
                "Afternoon phishing wave",
                "Indicators of Compromise\nshared[.]example.com\nphish[.]example.com\n",
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
    assert "`shared.example.com`" in markdown
    assert "`phish.example.com`" in markdown
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
    assert report.subject.endswith("待修 1 / 待封鎖 0 / 待hunt 0 / 文章數 1")
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


def test_tracking_query_and_invalid_port_do_not_break_dedup() -> None:
    class DupParser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            name = getattr(source, "name")
            first = parsed_article(
                name,
                "Shared story",
                "Indicators of Compromise\nevil[.]example.com\n",
            )
            second = parsed_article(
                name,
                "Shared story copy",
                "Indicators of Compromise\nevil[.]example.com\nextra[.]example.com\n",
            )
            broken = parsed_article(
                name,
                "Broken port story",
                "CVE-2026-76581 is listed.\n",
            )
            first.url = "https://example.test/shared?utm_source=rss&id=1"
            second.url = "https://example.test/shared?id=1&fbclid=abc"
            broken.url = "https://example.test:notaport/broken"
            return [first, second, broken]

    generated = datetime(2026, 8, 30, 1, 21, tzinfo=timezone.utc)
    report = collect_report(
        DupParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 8, 29, 1, 21, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )

    assert _canonical_article_url("https://example.test/shared?utm_source=rss&id=1") == (
        "https://example.test/shared?id=1"
    )
    assert report.collected_article_count == 2
    assert report.article_count == 2
    assert report.confirmed_ioc_count == 2
    titles = {item.article_title for item in report.articles}
    assert titles == {"Shared story", "Broken port story"}


class CveParser:
    def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
        if getattr(source, "name") != "The Hacker News":
            return []
        return [
            parsed_article(
                "The Hacker News",
                "Vendor patches an exploited flaw",
                """Indicators of Compromise
CVE-2026-2222
CVE-2026-1111
""",
            )
        ]


def cve_report(enricher):
    generated = datetime(2026, 9, 4, 6, 0, tzinfo=timezone.utc)
    return collect_report(
        CveParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 9, 3, 6, 0, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
        enricher=enricher,
    )


def kev_enricher(manifests):
    return (
        {
            "CVE-2026-1111": CveIntel(
                cve_id="CVE-2026-1111",
                kev=True,
                kev_due_date="2026-09-18",
                cvss_score=9.8,
                cvss_severity="CRITICAL",
                sources=[KEV_URL],
                retrieved_at="2026-09-04T06:00:00+00:00",
            ),
            "CVE-2026-2222": CveIntel(
                cve_id="CVE-2026-2222", cvss_score=5.3, cvss_severity="MEDIUM"
            ),
        },
        EnrichmentReport(
            enabled=True,
            requested_cve_count=2,
            enriched_cve_count=2,
            kev_count=1,
            cvss_count=2,
            kev_catalog_released="2026-09-03T14:00:00.0000Z",
        ),
    )


def test_kev_reaches_the_subject_header_and_board() -> None:
    report = cve_report(kev_enricher)
    markdown = render_markdown(report)

    assert report.kev_count == 1
    assert "待修 2（KEV 1）" in report.subject
    assert "- 其中已知遭利用（CISA KEV）：1 個" in markdown
    assert "`CVE-2026-1111` 【KEV】" in markdown
    assert "CISA KEV 與 NVD；2/2 個 CVE 取得 NVD CVSS" in markdown
    assert "KEV 目錄發布於 2026-09-03" in markdown
    assert report.cve_intel["CVE-2026-1111"]["sources"] == [KEV_URL]
    assert report.enrichment["kev_count"] == 1


def test_report_without_enrichment_says_so_and_still_ships() -> None:
    report = cve_report(None)
    markdown = render_markdown(report)

    assert report.kev_count == 0
    assert report.cve_intel == {}
    assert report.enrichment["enabled"] is False
    assert "CVE 加值：未啟用" in markdown
    assert "【KEV】" not in markdown
    assert "（KEV" not in report.subject


def test_enrichment_errors_are_flagged_to_the_reader() -> None:
    def failing(manifests):
        return {}, EnrichmentReport(
            enabled=True,
            requested_cve_count=2,
            errors=["KEV catalogue unavailable: network is down"],
        )

    markdown = render_markdown(cve_report(failing))

    assert "CVE 加值有 1 項查詢失敗" in markdown


def test_enrichment_moves_the_report_id() -> None:
    assert cve_report(kev_enricher).report_id != cve_report(None).report_id


def test_a_day_without_cves_says_enrichment_ran_with_nothing_to_do() -> None:
    def nothing_to_look_up(manifests):
        return {}, EnrichmentReport(enabled=True)

    markdown = render_markdown(cve_report(nothing_to_look_up))

    assert "CVE 加值：已啟用；今日沒有明確 CVE 需要查詢" in markdown
    assert "未啟用" not in markdown


def blocked_article(title: str) -> ParsedArticle:
    """An article whose body was never retrieved, as a 403 leaves it."""
    return ParsedArticle(
        source="Dark Reading",
        title=title,
        url=f"https://example.test/{title.lower().replace(' ', '-')}",
        published_at="2026-09-03T20:18:00+00:00",
        body="",
        extraction_method="failed",
        body_characters=0,
        warnings=[
            "full article extraction failed; feed excerpt is metadata only",
            "HTTP fetch failed for https://example.test/x: Client error "
            "'403 Forbidden' for url 'https://example.test/x'",
        ],
    )


class BlockedParser:
    def __init__(self, title: str) -> None:
        self.title = title

    def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
        if getattr(source, "name") != "The Hacker News":
            return []
        return [blocked_article(self.title)]


def blocked_report(title: str = "Threat Actors Target Enterprises in Fake Merger Scams"):
    generated = datetime(2026, 9, 4, 6, 0, tzinfo=timezone.utc)
    return collect_report(
        BlockedParser(title),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 9, 3, 6, 0, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )


def test_an_unread_article_is_never_reported_as_having_no_indicators() -> None:
    report = blocked_report()
    markdown = render_markdown(report)

    assert "原文未提供明確指標" not in markdown
    assert "未能取得全文" in markdown
    assert "來源回應 HTTP 403，疑似反機器人阻擋" in markdown
    assert "請人工開啟原文複核" in markdown


def test_an_unread_article_becomes_a_review_action() -> None:
    report = blocked_report()
    actions = report.analyst_brief.actions

    assert [item.action for item in actions] == ["review"]
    assert actions[0].priority == "medium"
    assert report.analyst_brief.unavailable_count == 1
    assert "人工複核" in render_markdown(report)


def test_a_blocked_phishing_headline_is_review_not_observe() -> None:
    # The observe wording claims the article carried no actionable indicator,
    # which cannot be said about a body that was never read.
    report = blocked_report("Hackers Use QR Codes in Phishing Emails to Steal Logins")
    actions = report.analyst_brief.actions

    assert [item.action for item in actions] == ["review"]
    assert report.analyst_brief.monitor_count == 0


def test_review_actions_stay_out_of_the_actionable_csv() -> None:
    report = blocked_report()
    assert [item.action for item in report.analyst_brief.actions] == ["review"]
    csv_text = render_ioc_csv_from_actions(report.analyst_brief.actions)

    assert csv_text.strip().splitlines()[1:] == []
    assert report.analyst_brief.patch_count == 0
    assert report.analyst_brief.block_count == 0
    assert report.analyst_brief.hunt_count == 0


def test_an_unparseable_page_reports_its_own_cause() -> None:
    article = blocked_article("Daily Cyber Security Stormcast For Friday")
    article.warnings = [
        "could not extract a valid article body from https://example.test/x: "
        "no extraction candidates"
    ]

    class Parser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            return [article] if getattr(source, "name") == "The Hacker News" else []

    generated = datetime(2026, 9, 4, 6, 0, tzinfo=timezone.utc)
    report = collect_report(
        Parser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 9, 3, 6, 0, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )

    assert "頁面沒有可解析的正文結構" in render_markdown(report)


class MixedParser:
    def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
        if getattr(source, "name") != "The Hacker News":
            return []
        return [
            parsed_article(
                "The Hacker News",
                "Campaign drops a backdoor",
                """Indicators of Compromise
CVE-2026-1111
evil-c2-host[.]com    C2 server for the second-stage implant
""",
            ),
            parsed_article(
                "The Hacker News",
                "Ransomware crews shift tactics this quarter",
                "A trend piece with no indicators of any kind in the body.",
            ),
        ]


def mixed_report():
    generated = datetime(2026, 9, 4, 6, 0, tzinfo=timezone.utc)
    return collect_report(
        MixedParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 9, 3, 6, 0, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )


def test_articles_without_indicators_collapse_to_one_line_each() -> None:
    report = mixed_report()
    markdown = render_markdown(report)
    lines = markdown.splitlines()

    assert "## 1. Campaign drops a backdoor" in markdown
    assert "## 2. Ransomware crews shift tactics this quarter" not in markdown

    compact = [
        line
        for line in lines
        if line.startswith("- [Ransomware crews shift tactics this quarter]")
    ]
    assert len(compact) == 1
    # The one line still carries source, time and the source's own summary.
    assert "The Hacker News" in compact[0]
    assert "UTC" in compact[0]
    assert "trend piece" in compact[0]
    assert "## 其他相關文章" in markdown


def test_an_unread_article_keeps_its_full_section() -> None:
    # It is not "read with nothing found", so it must not be collapsed away.
    markdown = render_markdown(blocked_report())

    assert "## 1. " in markdown
    assert "未能取得全文" in markdown
    assert "## 其他相關文章" not in markdown


def test_context_is_dropped_when_it_only_repeats_the_indicator() -> None:
    markdown = render_markdown(mixed_report())
    lines = markdown.splitlines()

    # Anchor on the detail section; the duty board lists the same values.
    cve = next(i for i, line in enumerate(lines) if line.startswith("- **CVE**："))
    assert not lines[cve + 1].startswith("  - 上下文：")

    host = next(i for i, line in enumerate(lines) if line.startswith("- **DOMAIN**："))
    assert lines[host + 1].startswith("  - 上下文：")
    assert "C2 server for the second-stage implant" in lines[host + 1]


def test_an_article_with_only_claims_says_which_kind_it_has() -> None:
    class ClaimParser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            if getattr(source, "name") != "The Hacker News":
                return []
            return [
                parsed_article(
                    "The Hacker News",
                    "Malware campaign spreads through fake installers",
                    "Researchers tracked the loader as BraZetsu ransomware, "
                    "but published no indicators.\n",
                )
            ]

    generated = datetime(2026, 9, 4, 6, 0, tzinfo=timezone.utc)
    report = collect_report(
        ClaimParser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 9, 3, 6, 0, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )
    markdown = render_markdown(report)

    assert report.confirmed_claim_count == 1
    # It keeps a full section because 原文指稱 has something to show, so the
    # line above that section must not read as "nothing here".
    assert "## 1. Malware campaign spreads through fake installers" in markdown
    assert "- IoC：原文未提供明確指標。" not in markdown
    assert "無 hash／IP／網域／URL／CVE 類指標；本篇只有原文指稱，見下方。" in markdown
    assert "### 原文指稱" in markdown
