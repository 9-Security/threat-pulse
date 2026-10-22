"""The feed side of the corpus: values abuse.ch lists as malicious infrastructure.

The news side holds what a publisher wrote down; the sample side holds what the
malware analyser found inside a file. Neither holds the live blocklists the rest
of the industry checks first: ThreatFox (C2 servers, payload delivery, payload
hashes) and Feodo Tracker (botnet C2 addresses). This exporter reads them and
renders SQL for the same D1 database, into tables of their own, because "abuse.ch
lists this" is a third kind of claim: curated by a third party, current, and
without the context an article gives.

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

Normalisation is the news side's own (`_normalize`, `registrable_domain`,
`_is_public_address`), for the reason sample_export.py gives: a value normalised
differently on one side hits there and misses here.

ThreatFox needs a free abuse.ch Auth-Key (ABUSE_CH_AUTH_KEY). abuse.ch offers the
API under fair use; for-profit use may need its commercial terms.
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
from .sample_export import BATCH_ROWS, _row, _text

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
THREATFOX_IOC_URL = "https://threatfox.abuse.ch/ioc/{id}/"
FEODO_REFERENCE = "https://feodotracker.abuse.ch/browse/host/{ip}/"
THREATFOX_DAYS = 7
MIN_CONFIDENCE = 75
RETENTION_DAYS = 30
MAX_VALUE_CHARS = 512
# A 7-day get_iocs answer is about 12 MB; the cap is the guard against a broken
# or hostile response, not a working limit.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
TIMEOUT_SECONDS = 90.0

THREATFOX_TYPES = {
    "ip:port": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
}

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


def parse_threatfox(body: Any) -> tuple[FeedIndicator, ...]:
    """Confident, non-compromised ThreatFox rows. Raises FeedError on a refused query."""
    if not isinstance(body, dict):
        raise FeedError("ThreatFox: the answer is not a JSON object")
    status = body.get("query_status")
    if status == "no_result":
        return ()
    if status != "ok":
        # unknown_auth_key, illegal_days and the like: the query was refused, which
        # is not the same as the feed being empty.
        raise FeedError(f"ThreatFox query_status: {str(status)[:80]}")
    best: dict[tuple[str, str], FeedIndicator] = {}
    for row in body.get("data") or []:
        if not isinstance(row, dict) or row.get("is_compromised"):
            continue
        indicator_type = THREATFOX_TYPES.get(str(row.get("ioc_type") or ""))
        raw = _text(row.get("ioc"))
        if not indicator_type or not raw:
            continue
        try:
            confidence = int(row.get("confidence_level") or 0)
        except (TypeError, ValueError):
            continue
        if confidence < MIN_CONFIDENCE:
            continue
        port = None
        if indicator_type == "ip" and raw.count(":") == 1:
            raw, port_text = raw.split(":", 1)
            port = int(port_text) if port_text.isdigit() else None
        ioc_id = row.get("id")
        found = _indicator(
            "threatfox",
            indicator_type,
            raw,
            threat_type=_text(row.get("threat_type")),
            malware=_text(row.get("malware_printable")) or _text(row.get("malware")),
            confidence=confidence,
            port=port,
            first_seen=_stamp(row.get("first_seen")),
            last_seen=_stamp(row.get("last_seen")),
            reference=THREATFOX_IOC_URL.format(id=ioc_id) if ioc_id else None,
        )
        if found is None:
            continue
        key = (found.indicator_type, found.value.lower())
        current = best.get(key)
        # One value listed twice (two ports, two reports): keep the most recent sighting.
        if current is None or (found.last_seen or found.first_seen) > (current.last_seen or current.first_seen):
            best[key] = found
    return tuple(best[key] for key in sorted(best))


def parse_feodo(body: Any) -> tuple[FeedIndicator, ...]:
    if not isinstance(body, list):
        raise FeedError("Feodo Tracker: the answer is not a JSON list")
    best: dict[str, FeedIndicator] = {}
    for row in body:
        if not isinstance(row, dict):
            continue
        raw = _text(row.get("ip_address"))
        if not raw:
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
            last_seen=_stamp(row.get("last_online")),
            reference=FEODO_REFERENCE.format(ip=raw),
        )
        if found is not None:
            best[found.value] = found
    return tuple(best[key] for key in sorted(best))


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


def fetch_threatfox(client: httpx.Client, auth_key: str | None) -> FeedResult:
    if not auth_key:
        return FeedResult("threatfox", error="ABUSE_CH_AUTH_KEY is not set")
    try:
        body = _read_json(
            client,
            "POST",
            THREATFOX_API_URL,
            json={"query": "get_iocs", "days": THREATFOX_DAYS},
            headers={"Auth-Key": auth_key},
        )
        listed = len(body.get("data") or []) if isinstance(body, dict) else 0
        return FeedResult("threatfox", parse_threatfox(body), listed=listed)
    except FeedError as error:
        return FeedResult("threatfox", error=str(error)[:200])


def fetch_feodo(client: httpx.Client) -> FeedResult:
    try:
        body = _read_json(client, "GET", FEODO_URL)
        return FeedResult("feodo", parse_feodo(body), listed=len(body) if isinstance(body, list) else 0)
    except FeedError as error:
        return FeedResult("feodo", error=str(error)[:200])


def collect_feeds(
    *,
    auth_key: str | None = None,
    client: httpx.Client | None = None,
    fetchers: dict[str, Callable[[], FeedResult]] | None = None,
) -> list[FeedResult]:
    """Read every source. One source failing never stops the other."""
    if fetchers is None:
        own = client or httpx.Client(
            timeout=TIMEOUT_SECONDS, headers={"user-agent": "threat-pulse feed export"}
        )
        key = auth_key if auth_key is not None else os.environ.get("ABUSE_CH_AUTH_KEY", "").strip()
        fetchers = {"threatfox": lambda: fetch_threatfox(own, key), "feodo": lambda: fetch_feodo(own)}
        try:
            return [fetch() for fetch in fetchers.values()]
        finally:
            if client is None:
                own.close()
    return [fetch() for fetch in fetchers.values()]


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
