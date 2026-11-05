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
    ET_COMPROMISED_URL,
    collect_feeds,
    feodo_indicators,
    fetch_et_compromised,
    parse_et_compromised,
    fetch_watchlist,
    parse_watchlist,
    render_sql,
    summary_of,
    threatfox_indicators,
)

SCHEMA = Path(__file__).resolve().parents[1] / "deploy" / "d1" / "schema.sql"
NOW = datetime(2026, 10, 22, 6, 0, tzinfo=timezone.utc)


def _tf(ioc_id, ioc_type, value, *, port=None, threat_type="botnet_cc", malware="", confidence=100,
        first_seen="2026-10-20 00:00:00 UTC", last_seen=""):
    """A ThreatFox row as the analyser serves it: port split off, abuse.ch's own stamps kept."""
    return {"source": "threatfox", "ioc_type": ioc_type, "value": value, "port": port,
            "threat_type": threat_type, "malware": malware, "first_seen": first_seen,
            "last_seen": last_seen, "ioc_id": ioc_id, "confidence": confidence,
            "last_listed_epoch": 1_793_000_000.0}


THREATFOX = [
    _tf(101, "ip", "45.33.70.70", port=8443, malware="Vidar", first_seen="2026-10-21 04:15:48 UTC"),
    # The same address on a second port, seen later: one row, the later sighting.
    _tf(102, "ip", "45.33.70.70", port=443, malware="Vidar", confidence=90,
        first_seen="2026-10-21 09:00:00 UTC", last_seen="2026-10-22 01:00:00 UTC"),
    _tf(103, "domain", "Panel.C2Host.example", malware="Lumma", confidence=75),
    _tf(104, "url", "https://drop.example/x/payload.bin", threat_type="payload_delivery", malware="QakBot"),
    _tf(105, "sha256", "A" * 64, threat_type="payload", malware="QakBot"),
    # Dropped: low confidence, a non-numeric confidence, a private address, a hash
    # of the wrong length, and an IOC type nobody queries by value.
    _tf(107, "ip", "45.33.80.80", port=80, confidence=50),
    _tf(111, "domain", "nan-confidence.example", confidence="high"),
    _tf(108, "ip", "10.0.0.5", port=443),
    _tf(109, "md5", "abc123", threat_type="payload"),
    _tf(110, "envelope_from", "something"),
]
FEODO = [
    {"source": "feodo", "ioc_type": "ip", "value": "45.33.10.10", "port": 8080, "malware": "QakBot",
     "first_seen": "2026-10-01 00:00:00", "last_seen": "2026-10-21", "status": "online"},
    {"source": "feodo", "ioc_type": "ip", "value": "192.168.1.1", "port": 443, "malware": "x",
     "first_seen": "2026-10-01 00:00:00"},
]
URLHAUS = [{"source": "urlhaus", "ioc_type": "domain", "value": "drop.example"}]


def _watchlist(*, threatfox_ok=True, feodo_ok=True):
    return {
        "generated_at": "2026-10-22T06:00:00Z",
        "sources": {
            "threatfox": {"ok": threatfox_ok, "count": len(THREATFOX), "listed_now": 9,
                          **({} if threatfox_ok else {"error": "ThreatFox HTTP 401: unknown_auth_key"})},
            "feodo": {"ok": feodo_ok, "count": 2, "listed_now": 2},
            "urlhaus": {"ok": True, "count": 1, "listed_now": 1},
        },
        "items": THREATFOX + FEODO + URLHAUS,
    }


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
    rows = {(i.indicator_type, i.value): i for i in threatfox_indicators(THREATFOX)}
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


def test_feodo_rows():
    (row,) = feodo_indicators(FEODO)
    assert (row.source, row.indicator_type, row.value, row.port, row.malware, row.threat_type) == (
        "feodo", "ip", "45.33.10.10", 8080, "QakBot", "botnet_cc")


def test_watchlist_gives_one_result_per_source_and_ignores_urlhaus():
    results = {r.source: r for r in parse_watchlist(_watchlist())}
    assert set(results) == {"threatfox", "feodo"}
    assert results["threatfox"].listed == 9 and len(results["threatfox"].indicators) == 4
    assert len(results["feodo"].indicators) == 1


def test_a_source_failing_at_the_analyser_is_an_error_here():
    results = {r.source: r for r in parse_watchlist(_watchlist(threatfox_ok=False))}
    assert not results["threatfox"].ok and "unknown_auth_key" in (results["threatfox"].error or "")
    assert results["threatfox"].indicators == ()  # the analyser's last rows are not written as current
    assert results["feodo"].ok


def test_an_answer_that_is_not_a_watchlist_raises():
    for body in ({"detail": "Invalid or missing API key"}, ["not", "an", "object"], {"sources": {}, "items": 3}):
        with pytest.raises(FeedError):
            parse_watchlist(body)
    missing = parse_watchlist({"sources": {}, "items": []})
    assert all(not r.ok for r in missing)


def test_push_writes_only_what_changed():
    conn = _db()
    feeds = parse_watchlist(_watchlist())
    assert _apply(conn, render_sql(feeds, now=NOW)) > 0
    assert len(_rows(conn)) == 5
    # The same lists again: Feodo is replaced as a set (1 delete + 1 insert),
    # ThreatFox's unchanged rows write nothing.
    assert _apply(conn, render_sql(feeds, now=NOW)) == 2
    # ThreatFox sees the domain again: exactly that row changes.
    moved = json.loads(json.dumps(THREATFOX))
    moved[2]["last_seen"] = "2026-10-22 05:00:00 UTC"
    changed = [FeedResult("threatfox", threatfox_indicators(moved))]
    assert _apply(conn, render_sql(changed, now=NOW)) == 1
    state = dict(conn.execute("SELECT source, ok FROM feed_state"))
    assert state == {"threatfox": 1, "feodo": 1}


def test_rows_expire_thirty_days_after_last_seen():
    conn = _db()
    _apply(conn, render_sql([FeedResult("threatfox", threatfox_indicators(THREATFOX))], now=NOW))
    later = datetime(2026, 11, 20, 0, 30, tzinfo=timezone.utc)  # 30 days after 10-21
    _apply(conn, render_sql([], now=later))
    # first_seen 10-20 and never re-seen: gone. Last seen 10-22: still kept.
    assert set(v for _, v in _rows(conn)) == {"45.33.70.70"}


def test_rows_past_retention_are_never_written():
    # The analyser keeps a ThreatFox row 30 days after it was last LISTED; by its own
    # stamps it can already be past our retention. Inserting it only to expire it in
    # the same batch would spend D1 writes for nothing.
    later = datetime(2026, 11, 20, 0, 30, tzinfo=timezone.utc)
    conn = _db()
    assert _apply(conn, render_sql([FeedResult("threatfox", threatfox_indicators(THREATFOX))], now=later)) == 1
    assert set(v for _, v in _rows(conn)) == {"45.33.70.70"}
    # Feodo is a mirrored set, never filtered by age (its list has been frozen for months).
    _apply(conn, render_sql([FeedResult("feodo", feodo_indicators(FEODO))], now=later))
    assert ("feodo", "45.33.10.10") in _rows(conn)


def test_a_failed_source_keeps_its_rows_and_says_so():
    conn = _db()
    _apply(conn, render_sql(parse_watchlist(_watchlist()), now=NOW))
    _apply(conn, render_sql([FeedResult("threatfox", error="analyser: threatfox upstream failing"),
                             FeedResult("feodo", error="unreachable")], now=NOW))
    assert len(_rows(conn)) == 5
    state = {r[0]: r[1:] for r in conn.execute("SELECT source, ok, error FROM feed_state")}
    assert state["threatfox"] == (0, "analyser: threatfox upstream failing")
    assert state["feodo"] == (0, "unreachable")


def test_values_with_quotes_are_escaped():
    conn = _db()
    tricky = [_tf(1, "url", "https://x.example/a'b", threat_type="payload_delivery", malware="O'Brien",
                  first_seen="2026-10-21 00:00:00 UTC")]
    _apply(conn, render_sql([FeedResult("threatfox", threatfox_indicators(tricky))], now=NOW))
    assert [r[2] for r in _rows(conn).values()] == ["O'Brien"]


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


ET_LIST = "# compromised hosts\n45.33.70.70\n91.240.118.222\n10.0.0.9\n\n45.33.70.70\nnot-an-ip\n"


def _routes(watchlist=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == ET_COMPROMISED_URL:
            return httpx.Response(200, text=ET_LIST)
        if watchlist is None:
            raise AssertionError("no analyser request without a key")
        return httpx.Response(200, json=watchlist)
    return handler


def test_without_an_analyser_key_abuse_ch_says_so_and_et_still_lands():
    results = {r.source: r for r in collect_feeds(base_url="http://analyser.test", api_key="", client=_client(_routes()))}
    assert results["threatfox"].error == results["feodo"].error == "ANALYZER_API_KEY is not set"
    assert results["et_compromised"].ok
    assert summary_of(list(results.values()))["any_ok"] is True


def test_the_request_goes_to_the_analyser_with_its_key_and_never_to_abuse_ch():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == ET_COMPROMISED_URL:
            assert "X-API-Key" not in request.headers, "the analyser key never goes to a third party"
            return httpx.Response(200, text=ET_LIST)
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("X-API-Key")
        return httpx.Response(200, json=_watchlist())
    results = collect_feeds(base_url="http://127.0.0.1:18080/", api_key="k3y", client=_client(handler))
    assert seen == {"url": "http://127.0.0.1:18080/api/threat-intel/watchlist", "key": "k3y"}
    assert "abuse.ch" not in seen["url"]
    assert [r.source for r in results] == ["threatfox", "feodo", "et_compromised"]
    assert summary_of(results)["any_ok"] is True


def test_http_failures_become_every_sources_error():
    results = fetch_watchlist(_client(lambda request: httpx.Response(503)), "http://analyser.test", "k3y")
    assert [r.source for r in results] == ["threatfox", "feodo"]
    assert all(not r.ok and "503" in (r.error or "") for r in results)


def test_et_list_keeps_distinct_public_addresses():
    rows = parse_et_compromised(ET_LIST, seen_at="2026-11-05T08:00:00Z")
    assert [r.value for r in rows] == ["45.33.70.70", "91.240.118.222"]
    assert all(r.source == "et_compromised" and r.threat_type == "compromised" for r in rows)
    assert rows[0].first_seen == "2026-11-05T08:00:00Z" and rows[0].reference == ET_COMPROMISED_URL


def test_et_answers_that_are_not_the_list_are_errors():
    for body in ("", "# only comments\n", "<html><body>blocked</body></html>", "10.0.0.1\n192.168.0.1\n"):
        with pytest.raises(FeedError):
            parse_et_compromised(body, seen_at="2026-11-05T08:00:00Z")
    result = fetch_et_compromised(_client(lambda request: httpx.Response(503)), seen_at="x")
    assert not result.ok and "503" in (result.error or "")


def test_et_push_writes_only_what_changed_and_keeps_first_seen():
    conn = _db()
    first = [FeedResult("et_compromised", parse_et_compromised(ET_LIST, seen_at="2026-11-05T00:00:00Z"))]
    assert _apply(conn, render_sql(first, now=NOW)) == 2
    # The same list a day later: nothing is written, and first_seen stays the first sighting.
    again = [FeedResult("et_compromised", parse_et_compromised(ET_LIST, seen_at="2026-11-06T00:00:00Z"))]
    assert _apply(conn, render_sql(again, now=NOW)) == 0
    assert _rows(conn)[("et_compromised", "45.33.70.70")][4] == "2026-11-05T00:00:00Z"  # first_seen
    # One address leaves, one arrives: exactly two rows change.
    moved = [FeedResult("et_compromised", parse_et_compromised("45.33.70.70\n185.220.101.7\n", seen_at="2026-11-07T00:00:00Z"))]
    assert _apply(conn, render_sql(moved, now=NOW)) == 2
    assert {v for (src, v) in _rows(conn) if src == "et_compromised"} == {"45.33.70.70", "185.220.101.7"}


def test_a_failed_et_read_keeps_its_rows():
    conn = _db()
    _apply(conn, render_sql([FeedResult("et_compromised", parse_et_compromised(ET_LIST, seen_at="x"))], now=NOW))
    _apply(conn, render_sql([FeedResult("et_compromised", error="HTTP 503")], now=NOW))
    assert {v for (src, v) in _rows(conn) if src == "et_compromised"} == {"45.33.70.70", "91.240.118.222"}
    assert dict(conn.execute("SELECT source, ok FROM feed_state")) == {"et_compromised": 0}
