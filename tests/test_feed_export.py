import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from soc_news_parser.evidence import _normalize
from soc_news_parser.feed_export import (
    FeedError,
    FeedResult,
    collect_feeds,
    fetch_feodo,
    fetch_threatfox,
    parse_feodo,
    parse_threatfox,
    render_sql,
    summary_of,
)

SCHEMA = Path(__file__).resolve().parents[1] / "deploy" / "d1" / "schema.sql"
NOW = datetime(2026, 10, 22, 6, 0, tzinfo=timezone.utc)

THREATFOX = {
    "query_status": "ok",
    "data": [
        {"id": 101, "ioc": "45.33.70.70:8443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
         "malware": "win.vidar", "malware_printable": "Vidar", "confidence_level": 100,
         "first_seen": "2026-10-21 04:15:48 UTC", "last_seen": None, "is_compromised": False},
        # The same address on a second port, seen later: one row, the later sighting.
        {"id": 102, "ioc": "45.33.70.70:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
         "malware_printable": "Vidar", "confidence_level": 90,
         "first_seen": "2026-10-21 09:00:00 UTC", "last_seen": "2026-10-22 01:00:00 UTC"},
        {"id": 103, "ioc": "Panel.C2Host.example", "ioc_type": "domain", "threat_type": "botnet_cc",
         "malware_printable": "Lumma", "confidence_level": 75, "first_seen": "2026-10-20 00:00:00 UTC"},
        {"id": 104, "ioc": "https://drop.example/x/payload.bin", "ioc_type": "url",
         "threat_type": "payload_delivery", "malware_printable": "QakBot", "confidence_level": 100,
         "first_seen": "2026-10-20 00:00:00 UTC"},
        {"id": 105, "ioc": "A" * 64, "ioc_type": "sha256_hash", "threat_type": "payload",
         "malware_printable": "QakBot", "confidence_level": 100, "first_seen": "2026-10-20 00:00:00 UTC"},
        # Dropped: a hacked legitimate site, low confidence, a private address, a
        # hash of the wrong length, and an IOC type nobody queries by value.
        {"id": 106, "ioc": "https://hacked-bakery.example/wp/x.php", "ioc_type": "url",
         "threat_type": "payload_delivery", "confidence_level": 100,
         "first_seen": "2026-10-20 00:00:00 UTC", "is_compromised": True},
        {"id": 107, "ioc": "45.33.80.80:80", "ioc_type": "ip:port", "threat_type": "botnet_cc",
         "confidence_level": 50, "first_seen": "2026-10-20 00:00:00 UTC"},
        {"id": 108, "ioc": "10.0.0.5:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
         "confidence_level": 100, "first_seen": "2026-10-20 00:00:00 UTC"},
        {"id": 109, "ioc": "abc123", "ioc_type": "md5_hash", "threat_type": "payload",
         "confidence_level": 100, "first_seen": "2026-10-20 00:00:00 UTC"},
        {"id": 110, "ioc": "something", "ioc_type": "envelope_from", "threat_type": "botnet_cc",
         "confidence_level": 100, "first_seen": "2026-10-20 00:00:00 UTC"},
    ],
}
FEODO = [
    {"ip_address": "45.33.10.10", "port": 8080, "status": "online", "malware": "QakBot",
     "first_seen": "2026-10-01 00:00:00", "last_online": "2026-10-21"},
    {"ip_address": "192.168.1.1", "port": 443, "status": "online", "malware": "x",
     "first_seen": "2026-10-01 00:00:00"},
]


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(SCHEMA.read_text(encoding="utf-8"))
    return conn


def _apply(conn: sqlite3.Connection, sql: str) -> int:
    """Run one push; returns rows changed in feed_indicators (what D1 bills as writes)."""
    before = conn.total_changes
    state_rows = sql.count("INSERT OR REPLACE INTO feed_state")
    conn.executescript(sql)
    return conn.total_changes - before - state_rows


def _rows(conn: sqlite3.Connection) -> dict[tuple[str, str], tuple]:
    out = {}
    for row in conn.execute(
        "SELECT source, value, indicator_type, threat_type, malware, port, first_seen, last_seen "
        "FROM feed_indicators"
    ):
        out[(row[0], row[1])] = row[2:]
    return out


def test_threatfox_keeps_confident_listed_infrastructure_only():
    rows = {(i.indicator_type, i.value): i for i in parse_threatfox(THREATFOX)}
    assert set(rows) == {
        ("ip", "45.33.70.70"),
        ("domain", _normalize("Panel.C2Host.example", "domain")),
        ("url", _normalize("https://drop.example/x/payload.bin", "url")),
        ("sha256", "a" * 64),
    }
    ip = rows[("ip", "45.33.70.70")]
    assert (ip.port, ip.last_seen, ip.malware, ip.reference) == (
        443, "2026-10-22T01:00:00Z", "Vidar", "https://threatfox.abuse.ch/ioc/102/")
    assert rows[("url", _normalize("https://drop.example/x/payload.bin", "url"))].threat_type == "payload_delivery"
    domain = rows[("domain", _normalize("Panel.C2Host.example", "domain"))]
    assert domain.registrable_lc == "c2host.example" and domain.first_seen == "2026-10-20T00:00:00Z"


def test_threatfox_refusal_is_an_error_and_no_result_is_empty():
    assert parse_threatfox({"query_status": "no_result"}) == ()
    with pytest.raises(FeedError):
        parse_threatfox({"query_status": "unknown_auth_key"})
    with pytest.raises(FeedError):
        parse_threatfox(["not", "an", "object"])


def test_feodo_rows():
    (row,) = parse_feodo(FEODO)
    assert (row.source, row.indicator_type, row.value, row.port, row.malware, row.threat_type) == (
        "feodo", "ip", "45.33.10.10", 8080, "QakBot", "botnet_cc")


def test_push_writes_only_what_changed():
    conn = _db()
    feeds = [FeedResult("threatfox", parse_threatfox(THREATFOX), listed=10),
             FeedResult("feodo", parse_feodo(FEODO), listed=2)]
    assert _apply(conn, render_sql(feeds, now=NOW)) > 0
    assert len(_rows(conn)) == 5
    # The same lists again: Feodo is replaced as a set (1 delete + 1 insert),
    # ThreatFox's unchanged rows write nothing.
    assert _apply(conn, render_sql(feeds, now=NOW)) == 2
    # ThreatFox sees the domain again: exactly that row changes.
    moved = json.loads(json.dumps(THREATFOX))
    moved["data"][2]["last_seen"] = "2026-10-22 05:00:00 UTC"
    changed = [FeedResult("threatfox", parse_threatfox(moved))]
    assert _apply(conn, render_sql(changed, now=NOW)) == 1
    state = dict(conn.execute("SELECT source, ok FROM feed_state"))
    assert state == {"threatfox": 1, "feodo": 1}


def test_rows_expire_thirty_days_after_last_seen():
    conn = _db()
    _apply(conn, render_sql([FeedResult("threatfox", parse_threatfox(THREATFOX))], now=NOW))
    later = datetime(2026, 11, 20, 0, 30, tzinfo=timezone.utc)  # 30 days after 10-21
    _apply(conn, render_sql([], now=later))
    # first_seen 10-20 and never re-seen: gone. Last seen 10-22: still kept.
    assert set(v for _, v in _rows(conn)) == {"45.33.70.70"}


def test_a_failed_source_keeps_its_rows_and_says_so():
    conn = _db()
    _apply(conn, render_sql([FeedResult("threatfox", parse_threatfox(THREATFOX)),
                             FeedResult("feodo", parse_feodo(FEODO))], now=NOW))
    _apply(conn, render_sql([FeedResult("threatfox", error="ThreatFox HTTP 503"),
                             FeedResult("feodo", error="unreachable")], now=NOW))
    assert len(_rows(conn)) == 5
    state = {r[0]: r[1:] for r in conn.execute("SELECT source, ok, error FROM feed_state")}
    assert state["threatfox"] == (0, "ThreatFox HTTP 503") and state["feodo"] == (0, "unreachable")


def test_values_with_quotes_are_escaped():
    conn = _db()
    tricky = {"query_status": "ok", "data": [
        {"id": 1, "ioc": "https://x.example/a'b", "ioc_type": "url", "threat_type": "payload_delivery",
         "malware_printable": "O'Brien", "confidence_level": 100, "first_seen": "2026-10-21 00:00:00 UTC"}]}
    _apply(conn, render_sql([FeedResult("threatfox", parse_threatfox(tricky))], now=NOW))
    assert [r[2] for r in _rows(conn).values()] == ["O'Brien"]


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_threatfox_needs_a_key_and_feodo_does_not():
    def handler(request: httpx.Request) -> httpx.Response:
        assert "feodotracker" in str(request.url)
        return httpx.Response(200, json=FEODO)
    results = {r.source: r for r in collect_feeds(auth_key="", client=_client(handler))}
    assert results["threatfox"].error == "ABUSE_CH_AUTH_KEY is not set"
    assert results["feodo"].ok and len(results["feodo"].indicators) == 1
    assert summary_of(list(results.values()))["any_ok"] is True


def test_threatfox_request_carries_the_key_and_the_window():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["key"] = request.headers.get("Auth-Key")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=THREATFOX)
    result = fetch_threatfox(_client(handler), "k3y")
    assert seen == {"key": "k3y", "body": {"query": "get_iocs", "days": 7}}
    assert result.ok and result.listed == 10 and len(result.indicators) == 4


def test_http_failures_become_source_errors():
    result = fetch_feodo(_client(lambda request: httpx.Response(503)))
    assert not result.ok and "503" in (result.error or "")
