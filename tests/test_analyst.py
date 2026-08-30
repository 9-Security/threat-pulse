from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from soc_news_parser.analyst import (
    article_cvss,
    article_impacts,
    build_actions,
    build_brief,
    build_clusters,
    load_previous_iocs,
    render_ioc_csv,
)
from soc_news_parser.evidence import build_manifest
from soc_news_parser.parser import ParsedArticle
from soc_news_parser.report import collect_report, render_markdown


def _article(
    title: str,
    body: str,
    *,
    url: str | None = None,
    source: str = "Microsoft Security",
    published_at: str = "2026-08-30T08:00:00+00:00",
) -> ParsedArticle:
    slug = title.lower().replace(" ", "-")[:40]
    return ParsedArticle(
        source=source,
        title=title,
        url=url or f"https://www.microsoft.com/en-us/security/blog/{slug}/",
        published_at=published_at,
        body=body,
        extraction_method="feed:content",
        body_characters=len(body),
        warnings=[],
    )


def test_cve_article_is_patch_first() -> None:
    manifest = build_manifest(
        _article(
            "CVE-2024-38063 remote code execution in Windows TCP/IP",
            "Microsoft released updates for CVE-2024-38063. CVSS score: 9.8",
        )
    )
    actions = build_actions(manifest)
    assert [item.action for item in actions] == ["patch"]
    assert actions[0].target == "CVE-2024-38063"
    assert actions[0].priority == "high"
    assert article_cvss(manifest) == 9.8
    assert "remote_code_execution" in {key for key, _ in article_impacts(manifest)}


def test_hash_only_article_is_hunt() -> None:
    actions = build_actions(
        build_manifest(
            _article(
                "Observed SHA-256 in a malware sample",
                "Indicators of Compromise\n"
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            )
        )
    )
    assert [item.action for item in actions] == ["hunt"]
    assert actions[0].target_type == "sha256"


def test_ip_or_domain_is_block() -> None:
    actions = build_actions(
        build_manifest(
            _article(
                "C2 infrastructure observed",
                "The C2 server was observed contacting victims.\n"
                "Indicators of Compromise\n"
                "8.8.8.8\n",
            )
        )
    )
    assert [item.action for item in actions] == ["block"]
    assert actions[0].target == "8.8.8.8"
    assert "command_and_control" in {
        key
        for key, _ in article_impacts(
            build_manifest(
                _article(
                    "C2 infrastructure observed",
                    "The C2 server was observed contacting victims.\n"
                    "Indicators of Compromise\n"
                    "8.8.8.8\n",
                )
            )
        )
    }


def test_topic_article_without_confirmed_iocs_is_observe() -> None:
    actions = build_actions(
        build_manifest(
            _article(
                "Windows security update guidance",
                "Microsoft has released security updates for supported versions.",
            )
        )
    )
    assert [item.action for item in actions] == ["observe"]


def test_related_news_does_not_invent_rce_or_ransomware() -> None:
    manifest = build_manifest(
        _article(
            "Hasbro Data Breach Exposed Employee Personal Information",
            "The company is now disclosing a data breach of personal information.\n"
            "## Latest News\n"
            "In Other News: Log4j RCE Scare\n"
            "Related : ATF Confirms Cyber Incident After Ransomware Group Claims Attack\n",
        )
    )
    keys = {key for key, _ in article_impacts(manifest)}
    assert keys == {"data_breach"}
    assert [item.action for item in build_actions(manifest)] == ["monitor"]


def test_data_breach_without_iocs_is_monitor() -> None:
    actions = build_actions(
        build_manifest(
            _article(
                "Vendor discloses a data breach",
                "The company confirmed a data breach of personal information.",
            )
        )
    )
    assert [item.action for item in actions] == ["monitor"]


def test_same_cve_articles_form_one_cluster() -> None:
    manifests = [
        build_manifest(
            _article(
                "CVE-2024-38063 exploited",
                "CVE-2024-38063 is being exploited.",
                url="https://www.microsoft.com/en-us/security/blog/one/",
            )
        ),
        build_manifest(
            _article(
                "CVE-2024-38063 also covered",
                "CISA added CVE-2024-38063 to the catalog.",
                url="https://www.cisa.gov/news-events/alerts/aa24-001",
                source="CISA",
            )
        ),
    ]
    clusters = build_clusters(manifests)
    overlapping = [item for item in clusters if item.cves == ["CVE-2024-38063"]]
    assert len(overlapping) == 1
    assert overlapping[0].article_urls == [
        "https://www.microsoft.com/en-us/security/blog/one/",
        "https://www.cisa.gov/news-events/alerts/aa24-001",
    ]


def test_analyst_brief_counts_and_sort_order() -> None:
    manifests = [
        build_manifest(
            _article(
                "Background advisory",
                "General Windows security update guidance without indicators.",
                url="https://www.microsoft.com/en-us/security/blog/bg/",
            )
        ),
        build_manifest(
            _article(
                "CVE-2024-1234 remote code execution",
                "CVE-2024-1234 allows remote code execution.",
                url="https://www.microsoft.com/en-us/security/blog/cve/",
            )
        ),
    ]
    brief = build_brief(manifests)
    assert brief.patch_count == 1
    assert brief.monitor_count == 1
    assert brief.actions[0].action == "patch"
    assert brief.actions[1].action == "observe"
    assert brief.priority_line.startswith("今日優先：修補 CVE-2024-1234")
    assert brief.new_ioc_count is None


def test_previous_json_marks_only_new_iocs(tmp_path: Path) -> None:
    previous = {
        "articles": [
            {
                "evidence": [
                    {
                        "status": "confirmed",
                        "indicator_type": "cve",
                        "normalized_value": "CVE-2024-1111",
                    }
                ]
            }
        ]
    }
    path = tmp_path / "yesterday.json"
    path.write_text(json.dumps(previous), encoding="utf-8")
    previous_iocs = load_previous_iocs(str(path))
    brief = build_brief(
        [
            build_manifest(
                _article(
                    "Two CVEs",
                    "CVE-2024-1111 and CVE-2024-2222 were patched.",
                )
            )
        ],
        previous_iocs=previous_iocs,
    )
    by_cve = {item.target: item for item in brief.actions if item.action == "patch"}
    assert by_cve["CVE-2024-1111"].is_new is False
    assert by_cve["CVE-2024-2222"].is_new is True
    assert brief.new_ioc_count == 1
    assert brief.repeat_ioc_count == 1
    assert brief.gone_ioc_count == 0


def test_csv_is_one_confirmed_ioc_per_row() -> None:
    csv_text = render_ioc_csv(
        [
            build_manifest(
                _article(
                    "CVE-2024-1234 and hash",
                    "CVE-2024-1234 is patched.\n"
                    "Indicators of Compromise\n"
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                )
            )
        ]
    )
    lines = [line for line in csv_text.splitlines() if line]
    assert lines[0].startswith("action,priority,is_new,indicator_type")
    assert len(lines) == 3
    assert "CVE-2024-1234" in csv_text
    assert "b" * 64 in csv_text
    assert "patch" in csv_text
    assert "hunt" in csv_text


def test_reader_markdown_has_action_board() -> None:
    class SingleParser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            return [
                _article(
                    "CVE-2024-38063 remote code execution",
                    "Microsoft released updates for CVE-2024-38063. CVSS score: 9.8",
                    source=getattr(source, "name"),
                )
            ]

    generated = datetime(2026, 8, 30, 10, tzinfo=timezone.utc)
    report = collect_report(
        SingleParser(),  # type: ignore[arg-type]
        ["microsoft-security"],
        since=datetime(2026, 8, 29, 10, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
    )
    markdown = render_markdown(report)
    assert "今日處置清單" in markdown
    assert "### 修補" in markdown
    assert "建議：修補" in markdown
    assert "今日優先：修補 CVE-2024-38063" in markdown
    assert report.analyst_brief.patch_count == 1
    assert report.subject.startswith("[SOC] 每日資安新聞 IoC 彙整報告 - 待修 1")
    assert "待封鎖 0" in report.subject
