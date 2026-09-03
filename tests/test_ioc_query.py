from __future__ import annotations

import json
from pathlib import Path

from soc_news_parser.ioc_query import (
    list_report_dates,
    lookup_indicator,
    report_summary,
    search_iocs,
)


def _write_report(folder: Path) -> None:
    payload = {
        "subject": "[SOC] 每日資安新聞 IoC 彙整報告 - 待修 1 / 待封鎖 1 / 待hunt 1 / 文章數 1",
        "article_count": 1,
        "confirmed_ioc_count": 2,
        "window_start": "2026-09-01T22:00:00+00:00",
        "window_end": "2026-09-02T22:00:00+00:00",
        "generated_at": "2026-09-03T06:00:00+08:00",
        "analyst_brief": {
            "priority_line": "今日優先：修補 CVE-2024-38063",
            "patch_count": 1,
            "block_count": 1,
            "hunt_count": 1,
            "monitor_count": 0,
            "new_ioc_count": None,
            "actions": [
                {
                    "action": "patch",
                    "priority": "high",
                    "target_type": "cve",
                    "target": "CVE-2024-38063",
                    "reason": "CVSS 9.8；遠端程式碼執行",
                    "article_title": "Windows TCP/IP RCE",
                    "article_url": "https://www.microsoft.com/security/one",
                },
                {
                    "action": "block",
                    "priority": "medium",
                    "target_type": "domain",
                    "target": "evil.example",
                    "reason": "防火牆／DNS／proxy 封鎖後再 hunt 連線；原文明確記載",
                    "article_title": "Windows TCP/IP RCE",
                    "article_url": "https://www.microsoft.com/security/one",
                },
            ],
        },
        "articles": [
            {
                "article_title": "Windows TCP/IP RCE",
                "article_url": "https://www.microsoft.com/security/one",
                "evidence": [
                    {
                        "indicator_type": "cve",
                        "normalized_value": "CVE-2024-38063",
                        "raw_value": "CVE-2024-38063",
                        "status": "confirmed",
                        "reason_codes": ["explicit_cve_identifier"],
                        "section": "body",
                        "context": "CVE-2024-38063 remote code execution",
                    },
                    {
                        "indicator_type": "domain",
                        "normalized_value": "evil.example",
                        "raw_value": "evil[.]example",
                        "status": "confirmed",
                        "reason_codes": ["explicit_ioc_section"],
                        "section": "Indicators of Compromise",
                        "context": "evil[.]example",
                    },
                    {
                        "indicator_type": "domain",
                        "normalized_value": "noise.example",
                        "raw_value": "noise.example",
                        "status": "candidate",
                        "reason_codes": ["context_requires_human_review"],
                        "section": "body",
                        "context": "noise.example mentioned in prose",
                    },
                ],
            }
        ],
    }
    folder.mkdir(parents=True)
    (folder / "daily-evidence.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def test_lists_and_summarizes_latest_report(tmp_path: Path) -> None:
    older = tmp_path / "2026-09-01"
    newer = tmp_path / "2026-09-03"
    _write_report(older)
    _write_report(newer)
    dates = list_report_dates(tmp_path)
    assert [item["date"] for item in dates] == ["2026-09-03", "2026-09-01"]
    summary = report_summary(root=tmp_path)
    assert summary["date"] == "2026-09-03"
    assert summary["patch_count"] == 1
    assert summary["priority_line"].startswith("今日優先")


def test_search_skips_candidates_and_can_filter_action(tmp_path: Path) -> None:
    _write_report(tmp_path / "2026-09-03")
    found = search_iocs("evil", root=tmp_path)
    assert found["count"] == 1
    assert found["items"][0]["normalized_value"] == "evil.example"
    assert found["items"][0]["action"] == "block"
    blocked = search_iocs(action="block", root=tmp_path)
    assert [item["normalized_value"] for item in blocked["items"]] == ["evil.example"]
    cves = search_iocs(indicator_type="cve", root=tmp_path)
    assert [item["normalized_value"] for item in cves["items"]] == ["CVE-2024-38063"]


def test_lookup_matches_defanged_raw_value(tmp_path: Path) -> None:
    _write_report(tmp_path / "2026-09-03")
    found = lookup_indicator("evil[.]example", root=tmp_path)
    assert found["count"] == 1
    assert found["items"][0]["status"] == "confirmed"
    assert found["items"][0]["action"] == "block"
