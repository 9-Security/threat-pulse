"""The feed side of the corpus: values abuse.ch lists as malicious infrastructure.

The news side holds what a publisher wrote down; the sample side holds what the
malware analyser found inside a file. Neither holds the live blocklists the rest
of the industry checks first: ThreatFox (C2 servers, payload delivery, payload
hashes) and Feodo Tracker (botnet C2 addresses). This exporter reads them and
renders SQL for the same D1 database, into tables of their own, because "abuse.ch
lists this" is a third kind of claim: curated by a third party, current, and
without the context an article gives.

abuse.ch is not called from here. The malware analyser on this host holds the one
abuse.ch key and serves every row it fetched at GET /api/threat-intel/watchlist
(X-API-Key); this exporter reads that over the loopback, like export-samples does.
The rows keep abuse.ch's own fields (first/last seen, ThreatFox id, threat type), so
what lands in D1 is what reading abuse.ch directly produced.

What is kept
  * ThreatFox `get_iocs` for the last 7 days (the API maximum), confidence >= 75,
    rows ThreatFox marks `is_compromised` (a hacked legitimate site) dropped. Every
    threat type is kept and recorded, so an answer says whether a value is a C2
    server or a download location.
  * The Feodo Tracker IP blocklist, mirrored as is: it is a live list, and an
    address it drops has been taken down.

Rows cost writes, so a refresh writes only what changed. ThreatFox rows are
upserted with a no-op guard (an unchanged row writes nothing) and expire
RETENTION_DAYS after ThreatFox last saw them (`last_seen`, or `first_seen` when it
never re-saw them). The 7-day API window therefore becomes a 30-day corpus. A
source that cannot be read writes nothing for itself, so its previous rows stay;
expiry still runs, so a long outage cannot keep dead infrastructure forever.

The analyser keeps a ThreatFox row 30 days after it was last listed, and a failing
source's last rows. A row the analyser reports as failing upstream is treated as an
unreadable source here, and a row older than the retention window is never written
(it would be inserted and expired in the same batch, spending writes for nothing).

Normalisation is the news side's own (`_normalize`, `registrable_domain`,
`_is_public_address`), for the reason sample_export.py gives: a value normalised
differently on one side hits there and misses here.

The analyser's API key comes from ANALYZER_API_KEY and its address from ANALYZER_URL
(default the loopback). abuse.ch offers its API under fair use; for-profit use may
need its commercial terms.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Sequence

import httpx

from .evidence import _normalize
from .parser import _is_public_address
from .publicsuffix import registrable_domain
from .sample_export import ANALYZER_BASE_URL, BATCH_ROWS, _row, _text

WATCHLIST_PATH = "/api/threat-intel/watchlist"
SOURCES = ("threatfox", "feodo")
THREATFOX_IOC_URL = "https://threatfox.abuse.ch/ioc/{id}/"
FEODO_REFERENCE = "https://feodotracker.abuse.ch/browse/host/{ip}/"
MIN_CONFIDENCE = 75
RETENTION_DAYS = 30
MAX_VALUE_CHARS = 512
# The watchlist answer is a few MB; the cap is the guard against a broken or
# hostile response, not a working limit.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
# A stale analyser cache refreshes abuse.ch before it answers.
TIMEOUT_SECONDS = 240.0

THREATFOX_TYPES = frozenset({"ip", "domain", "url", "md5", "sha1", "sha256"})

FEED_INDICATOR_COLUMNS = (
    "source, indicator_type, value, threat_type, malware, confidence, port, "
    "first_seen, last_seen, reference, registrable_lc"
)


@dataclass(frozen=True)
class FeedIndicator:
    """One value one feed lists."""

    source: str
    indicator_type: str
    value: str
    threat_type: str | None
    malware: str | None
    confidence: int | None
    port: int | None
    first_seen: str
    last_seen: str | None
    reference: str | None
    registrable_lc: str | None


@dataclass(frozen=True)
class FeedResult:
    """What one source answered: its indicators, or why it could not be read."""

    source: str
    indicators: tuple[FeedIndicator, ...] = ()
    error: str | None = None
    listed: int = 0  # rows the source returned before filtering, for the journal

    @property
    def ok(self) -> bool:
        return self.error is None


class FeedError(RuntimeError):
    """A source could not be read, or answered with something other than data."""


def _stamp(value: Any) -> str | None:
    """abuse.ch's 'YYYY-MM-DD HH:MM:SS[ UTC]' as ISO 8601 UTC, so stamps compare as text."""
    text = _text(value)
    if not text:
        return None
    text = text.removesuffix(" UTC").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _usable(indicator_type: str, value: str) -> bool:
    if not value or len(value) > MAX_VALUE_CHARS:
        return False
    if indicator_type == "ip":
        return _is_public_address(value)
    return True


def _indicator(
    source: str,
    indicator_type: str,
    raw: str,
    *,
    threat_type: str | None,
    malware: str | None,
    confidence: int | None,
    port: int | None,
    first_seen: str | None,
    last_seen: str | None,
    reference: str | None,
) -> FeedIndicator | None:
    if indicator_type in ("md5", "sha1", "sha256"):
        value = raw.strip().lower()
        if len(value) != {"md5": 32, "sha1": 40, "sha256": 64}[indicator_type]:
            return None
    else:
        value = _normalize(raw, indicator_type)
    if not first_seen or not _usable(indicator_type, value):
        return None
    return FeedIndicator(
        source=source,
        indicator_type=indicator_type,
        value=value,
        threat_type=threat_type,
        malware=malware,
        confidence=confidence,
        port=port,
        first_seen=first_seen,
        last_seen=last_seen,
        reference=reference,
        registrable_lc=(registrable_domain(value) or None) if indicator_type == "domain" else None,
    )


def _keep_latest(best: dict[Any, FeedIndicator], key: Any, found: FeedIndicator) -> None:
    current = best.get(key)
    # One value listed twice (two ports, two reports): keep the most recent sighting.
    if current is None or (found.last_seen or found.first_seen) > (current.last_seen or current.first_seen):
        best[key] = found


def threatfox_indicators(rows: Sequence[dict[str, Any]]) -> tuple[FeedIndicator, ...]:
    """Confident ThreatFox rows as the analyser serves them (port split off, hacked sites dropped)."""
    best: dict[tuple[str, str], FeedIndicator] = {}
    for row in rows:
        indicator_type = _text(row.get("ioc_type"))
        raw = _text(row.get("value"))
        if indicator_type not in THREATFOX_TYPES or not raw:
            continue
        try:
            confidence = int(row.get("confidence") or 0)
        except (TypeError, ValueError):
            continue
        if confidence < MIN_CONFIDENCE:
            continue
        port, ioc_id = row.get("port"), row.get("ioc_id")
        found = _indicator(
            "threatfox",
            indicator_type,
            raw,
            threat_type=_text(row.get("threat_type")),
            malware=_text(row.get("malware")),
            confidence=confidence,
            port=port if isinstance(port, int) else None,
            first_seen=_stamp(row.get("first_seen")),
            last_seen=_stamp(row.get("last_seen")),
            reference=THREATFOX_IOC_URL.format(id=ioc_id) if isinstance(ioc_id, int) else None,
        )
        if found is not None:
            _keep_latest(best, (found.indicator_type, found.value.lower()), found)
    return tuple(best[key] for key in sorted(best))


def feodo_indicators(rows: Sequence[dict[str, Any]]) -> tuple[FeedIndicator, ...]:
    best: dict[str, FeedIndicator] = {}
    for row in rows:
        raw = _text(row.get("value"))
        if row.get("ioc_type") != "ip" or not raw:
            continue
        port = row.get("port")
        found = _indicator(
            "feodo",
            "ip",
            raw,
            threat_type="botnet_cc",
            malware=_text(row.get("malware")),
            confidence=None,
            port=port if isinstance(port, int) else None,
            first_seen=_stamp(row.get("first_seen")),
            last_seen=_stamp(row.get("last_seen")),
            reference=FEODO_REFERENCE.format(ip=raw),
        )
        if found is not None:
            best[found.value] = found
    return tuple(best[key] for key in sorted(best))


BUILDERS: dict[str, Callable[[Sequence[dict[str, Any]]], tuple[FeedIndicator, ...]]] = {
    "threatfox": threatfox_indicators,
    "feodo": feodo_indicators,
}


def parse_watchlist(body: Any) -> list[FeedResult]:
    """One FeedResult per source. Raises FeedError when the answer is not a watchlist."""
    if not isinstance(body, dict) or not isinstance(body.get("items"), list) or not isinstance(
        body.get("sources"), dict
    ):
        raise FeedError("analyser watchlist: the answer is not a watchlist")
    results: list[FeedResult] = []
    for name in SOURCES:
        state = body["sources"].get(name)
        if not isinstance(state, dict):
            results.append(FeedResult(name, error=f"the analyser serves no {name} source"))
            continue
        if state.get("ok") is not True:
            # The analyser could not read abuse.ch and is serving its last rows: that
            # is a failing source, not a current one.
            reason = str(state.get("error") or "unknown error")[:160]
            results.append(FeedResult(name, error=f"analyser: {name} upstream failing: {reason}"))
            continue
        rows = [r for r in body["items"] if isinstance(r, dict) and r.get("source") == name]
        listed = state.get("listed_now")
        results.append(
            FeedResult(name, BUILDERS[name](rows), listed=listed if isinstance(listed, int) else len(rows))
        )
    return results


def _read_json(client: httpx.Client, method: str, url: str, **kwargs: Any) -> Any:
    try:
        with client.stream(method, url, **kwargs) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise FeedError(f"{url}: response larger than {MAX_RESPONSE_BYTES} bytes")
                chunks.append(chunk)
        return json.loads(b"".join(chunks))
    except (httpx.HTTPError, ValueError) as error:
        raise FeedError(f"{url}: {error}") from error


def fetch_watchlist(client: httpx.Client, base_url: str, api_key: str | None) -> list[FeedResult]:
    """Every source from one analyser call; any failure is every source's error."""
    if not api_key:
        return [FeedResult(name, error="ANALYZER_API_KEY is not set") for name in SOURCES]
    try:
        body = _read_json(client, "GET", base_url.rstrip("/") + WATCHLIST_PATH, headers={"X-API-Key": api_key})
        return parse_watchlist(body)
    except FeedError as error:
        return [FeedResult(name, error=str(error)[:200]) for name in SOURCES]


def collect_feeds(
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    client: httpx.Client | None = None,
) -> list[FeedResult]:
    """Read every source through the analyser. One source failing never stops the other."""
    url = base_url or os.environ.get("ANALYZER_URL", "").strip() or ANALYZER_BASE_URL
    key = api_key if api_key is not None else os.environ.get("ANALYZER_API_KEY", "").strip()
    own = client or httpx.Client(timeout=TIMEOUT_SECONDS, headers={"user-agent": "threat-pulse feed export"})
    try:
        return fetch_watchlist(own, url, key)
    finally:
        if client is None:
            own.close()


def render_sql(
    results: Sequence[FeedResult],
    *,
    exported_at: str | None = None,
    now: datetime | None = None,
    retention_days: int = RETENTION_DAYS,
) -> str:
    """Statements only, no transaction: D1 runs a file as one batch.

    ThreatFox rows: an upsert that writes only when a stored row would change, and
    an expiry delete. Feodo rows: replaced as a set, since the list is small and
    an address it no longer lists has been taken down. A failed source writes no
    rows; `feed_state` records every source's outcome, last, in the same batch.
    """
    moment = now or datetime.now(timezone.utc)
    stamp = exported_at or moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff = (moment - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = ["-- feed side of the corpus (abuse.ch); values and attribution only."]
    for result in results:
        rows = [
            (
                i.source,
                i.indicator_type,
                i.value,
                i.threat_type,
                i.malware,
                i.confidence,
                i.port,
                i.first_seen,
                i.last_seen,
                i.reference,
                i.registrable_lc,
            )
            for i in result.indicators
            # Only ThreatFox expires by age; Feodo is mirrored as a set.
            if i.source != "threatfox" or (i.last_seen or i.first_seen) >= cutoff
        ]
        if result.source == "feodo" and result.ok:
            lines.append("DELETE FROM feed_indicators WHERE source = 'feodo';")
        if result.ok:
            for start in range(0, len(rows), BATCH_ROWS):
                lines.append(f"INSERT INTO feed_indicators ({FEED_INDICATOR_COLUMNS}) VALUES")
                lines.append(",\n".join(_row(row) for row in rows[start : start + BATCH_ROWS]) + UPSERT_CLAUSE)
    lines.append(
        "DELETE FROM feed_indicators WHERE source = 'threatfox' "
        f"AND coalesce(last_seen, first_seen) < '{cutoff}';"
    )
    for result in results:
        lines.append(
            "INSERT OR REPLACE INTO feed_state (source, exported_at, ok, kept, listed, error) VALUES"
        )
        lines.append(
            _row((result.source, stamp, result.ok, len(result.indicators), result.listed, result.error)) + ";"
        )
    return "\n".join(lines) + "\n"


UPSERT_CLAUSE = (
    " ON CONFLICT(source, indicator_type, value) DO UPDATE SET"
    " threat_type = excluded.threat_type, malware = excluded.malware,"
    " confidence = excluded.confidence, port = excluded.port,"
    " first_seen = excluded.first_seen, last_seen = excluded.last_seen,"
    " reference = excluded.reference, registrable_lc = excluded.registrable_lc"
    " WHERE feed_indicators.last_seen IS NOT excluded.last_seen"
    " OR feed_indicators.malware IS NOT excluded.malware"
    " OR feed_indicators.confidence IS NOT excluded.confidence"
    " OR feed_indicators.threat_type IS NOT excluded.threat_type"
    " OR feed_indicators.port IS NOT excluded.port;"
)


def summary_of(results: Sequence[FeedResult]) -> dict[str, Any]:
    """For the journal: what each source answered, and whether anything was read."""
    return {
        "sources": {
            r.source: {"ok": r.ok, "listed": r.listed, "kept": len(r.indicators), "error": r.error}
            for r in results
        },
        "rows": sum(len(r.indicators) for r in results),
        "any_ok": any(r.ok for r in results),
    }
