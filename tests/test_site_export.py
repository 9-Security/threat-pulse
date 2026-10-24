import json
from datetime import datetime, timezone

import pytest

from soc_news_parser.site_export import (
    PAGE_SIZE,
    build_document,
    d1_query_from_env,
    write_document,
)

NOW = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)


class FakeD1:
    """Answers the three table reads the exporter makes, paging like D1 would."""

    def __init__(self, indicators=(), samples=(), feeds=()):
        self.tables = {
            "indicators": list(indicators),
            "sample_indicators": list(samples),
            "feed_indicators": list(feeds),
        }
        self.sql: list[str] = []

    def __call__(self, sql: str) -> list[dict]:
        self.sql.append(sql)
        table = next(name for name in self.tables if f" FROM {name} " in sql)
        offset = int(sql.rsplit("OFFSET ", 1)[1])
        return self.tables[table][offset : offset + PAGE_SIZE]


def _news(value="evil.example.test", day="2026-10-20", url="https://news.example/a", **over):
    row = {
        "type": "domain",
        "value": value,
        "report_date": day,
        "action": "block",
        "priority": "high",
        "reason": "named as C2",
        "kev": None,
        "cvss_score": None,
        "cvss_severity": None,
        "source": "The Hacker News",
        "article_title": "Story",
        "article_url": url,
    }
    row.update(over)
    return row


def test_news_sample_and_feed_sides_merge_into_one_entry():
    fake = FakeD1(
        indicators=[_news()],
        samples=[
            {"type": "domain", "value": "evil.example.test", "sha256": "a" * 64,
             "integration": "config_extractor", "first_seen_at": "2026-10-01T10:00:00Z"},
            {"type": "domain", "value": "evil.example.test", "sha256": "b" * 64,
             "integration": "strings", "first_seen_at": "2026-10-02T10:00:00Z"},
        ],
        feeds=[{"source": "threatfox", "type": "domain", "value": "evil.example.test",
                "threat_type": "botnet_cc", "malware": "AgentTesla",
                "first_seen": "2026-09-30T00:00:00Z", "last_seen": "2026-10-23T00:00:00Z"}],
    )

    document = build_document(fake, now=NOW)

    assert document["indicator_count"] == 1
    item = document["indicators"][0]
    assert item["sides"] == ["feed", "news", "sample"]
    assert item["action"] == "block"
    assert item["first_seen"] == "2026-09-30"
    assert item["last_seen"] == "2026-10-23"
    assert item["news"]["articles"] == 1
    assert item["samples"]["count"] == 2
    assert item["samples"]["latest_analysis"] == "2026-10-02"
    assert item["samples"]["integrations"] == ["config_extractor", "strings"]
    assert item["samples"]["example_url"].endswith("/s/" + "a" * 64)
    assert item["feeds"] == [{"source": "threatfox", "threat_type": "botnet_cc", "malware": "AgentTesla"}]
    assert document["counts"] == {"news": 1, "sample": 1, "feed": 1}


def test_news_lists_every_publisher_that_named_the_value():
    fake = FakeD1(indicators=[
        _news(day="2026-10-01", url="https://a.example/1", source="BleepingComputer"),
        _news(day="2026-10-02", url="https://b.example/2", source="The Hacker News"),
        _news(day="2026-10-03", url="https://a.example/3", source="BleepingComputer"),
    ])

    news = build_document(fake, now=NOW)["indicators"][0]["news"]

    assert news["publishers"] == ["BleepingComputer", "The Hacker News"]
    assert news["publisher_count"] == 2
    assert news["articles"] == 3


def test_latest_news_row_decides_action_and_citation():
    fake = FakeD1(indicators=[
        _news(day="2026-10-01", url="https://news.example/old", action="monitor"),
        _news(day="2026-10-20", url="https://news.example/new", action="block"),
    ])

    item = build_document(fake, now=NOW)["indicators"][0]

    assert item["action"] == "block"
    assert item["news"]["url"] == "https://news.example/new"
    assert item["news"]["articles"] == 2


def test_only_confirmed_news_rows_are_read():
    fake = FakeD1()
    build_document(fake, now=NOW)
    news_sql = [s for s in fake.sql if " FROM indicators " in s]
    assert news_sql and all("status = 'confirmed'" in s for s in news_sql)


def test_paging_reads_every_row_past_one_page():
    rows = [_news(value=f"h{i}.example.test", url=f"https://news.example/{i}") for i in range(PAGE_SIZE + 5)]
    document = build_document(FakeD1(indicators=rows), now=NOW)
    assert document["indicator_count"] == PAGE_SIZE + 5


def test_no_context_body_or_raw_value_is_written(tmp_path):
    row = _news()
    row.update(context="SECRET SENTENCE", canonical_body="FULL ARTICLE TEXT", raw_value="hxxp://evil")
    document = build_document(FakeD1(indicators=[row]), now=NOW)
    out = write_document(document, tmp_path / "iocs.json")
    text = out.read_text(encoding="utf-8")
    assert "SECRET SENTENCE" not in text
    assert "FULL ARTICLE TEXT" not in text
    assert "hxxp://evil" not in text


def test_write_is_atomic_and_world_readable(tmp_path):
    document = build_document(FakeD1(), now=NOW)
    out = tmp_path / "site" / "iocs.json"
    write_document(document, out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == 2
    assert not list(out.parent.glob("*.tmp"))
    assert out.stat().st_mode & 0o044 == 0o044


def test_d1_query_requires_credentials(monkeypatch):
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_ACCOUNT_ID", raising=False)
    from soc_news_parser.site_export import ExportError

    with pytest.raises(ExportError, match="must be set"):
        d1_query_from_env()


def test_newest_day_per_side_is_reported_for_freshness():
    fake = FakeD1(
        indicators=[_news(day="2026-10-20")],
        samples=[{"type": "domain", "value": "x.example.test", "sha256": "c" * 64,
                  "integration": "strings", "first_seen_at": "2026-10-22T08:00:00Z"}],
        feeds=[{"source": "feodo", "type": "ip", "value": "203.0.113.9", "threat_type": None,
                "malware": None, "first_seen": "2026-10-01T00:00:00Z",
                "last_seen": "2026-10-23T00:00:00Z"}],
    )
    newest = build_document(fake, now=NOW)["newest_by_side"]
    assert newest == {"news": "2026-10-20", "sample": "2026-10-22", "feed": "2026-10-23"}


def _runner_with(monkeypatch, handler):
    import httpx

    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "test-token")
    monkeypatch.setenv("CLOUDFLARE_ACCOUNT_ID", "test-account")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return d1_query_from_env(client)


def test_d1_non_json_body_is_an_export_error(monkeypatch):
    import httpx

    from soc_news_parser.site_export import ExportError

    run = _runner_with(monkeypatch, lambda request: httpx.Response(200, text="<html>oops</html>"))
    with pytest.raises(ExportError, match="non-JSON"):
        run("SELECT 1")


def test_d1_rejected_query_is_an_export_error(monkeypatch):
    import httpx

    from soc_news_parser.site_export import ExportError

    run = _runner_with(monkeypatch, lambda request: httpx.Response(200, json={"success": False}))
    with pytest.raises(ExportError, match="rejected"):
        run("SELECT 1")


def test_d1_unexpected_shape_is_an_export_error(monkeypatch):
    import httpx

    from soc_news_parser.site_export import ExportError

    run = _runner_with(monkeypatch, lambda request: httpx.Response(200, json={"success": True, "result": []}))
    with pytest.raises(ExportError, match="unexpected response shape"):
        run("SELECT 1")


def test_d1_returns_rows_on_success(monkeypatch):
    import httpx

    rows = [{"value": "a.example"}]
    body = {"success": True, "result": [{"results": rows}]}
    run = _runner_with(monkeypatch, lambda request: httpx.Response(200, json=body))
    assert run("SELECT 1") == rows
