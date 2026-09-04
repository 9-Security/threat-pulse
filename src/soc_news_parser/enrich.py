"""CVE enrichment from CISA KEV and NVD.

Enrichment is third-party assertion, not something the article said. It is kept
in its own record with its own provenance so a reader can tell the two apart:
the evidence manifest still only reports what the source explicitly wrote.

Every lookup is cached on disk, so a rerun on the same day makes no request and
a second day only queries CVEs it has not seen.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from .parser import ParseError

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_HOST = "cisa.gov"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HOST = "services.nvd.nist.gov"

# NVD publishes 5 requests per rolling 30s without an API key and 50 with one.
# Stay a little under both so a slow clock cannot trip the limit.
NVD_RATE_WITHOUT_KEY = (4, 30.0)
NVD_RATE_WITH_KEY = (45, 30.0)

KEV_TTL = timedelta(hours=20)
# A scored CVE rarely moves; one still "Awaiting Analysis" is re-checked daily.
NVD_TTL_SCORED = timedelta(days=7)
NVD_TTL_UNSCORED = timedelta(hours=20)

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

Fetcher = Callable[[str, tuple[str, ...], dict[str, str] | None], bytes]


@dataclass(frozen=True)
class CveIntel:
    """What KEV and NVD assert about one CVE, with where each part came from."""

    cve_id: str
    kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_known_ransomware: bool | None = None
    cvss_score: float | None = None
    cvss_severity: str | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    nvd_status: str | None = None
    sources: list[str] = field(default_factory=list)
    retrieved_at: str | None = None

    @property
    def has_data(self) -> bool:
        return self.kev or self.cvss_score is not None or self.nvd_status is not None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EnrichmentReport:
    """Whether enrichment ran, what it covered, and what went wrong."""

    enabled: bool
    requested_cve_count: int = 0
    enriched_cve_count: int = 0
    kev_count: int = 0
    cvss_count: int = 0
    kev_catalog_version: str | None = None
    kev_catalog_released: str | None = None
    cache_hits: int = 0
    lookups: int = 0
    errors: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_stamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class EnrichmentCache:
    """Disk cache keyed by CVE id, plus one slot for the KEV catalogue."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)

    def _path(self, name: str) -> Path:
        return self.directory / name

    def read_entry(self, name: str) -> tuple[dict[str, Any], datetime] | None:
        """The stored document and when it was written, without judging age."""
        path = self._path(name)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        stored = _parse_stamp(payload.get("cached_at"))
        data = payload.get("data")
        if stored is None or not isinstance(data, dict):
            return None
        return data, stored

    def read(self, name: str, ttl: timedelta, *, now: datetime) -> dict[str, Any] | None:
        entry = self.read_entry(name)
        if entry is None:
            return None
        data, stored = entry
        return data if now - stored <= ttl else None

    def write(self, name: str, data: dict[str, Any], *, now: datetime) -> None:
        path = self._path(name)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(f"{path.suffix}.tmp")
            temporary.write_text(
                json.dumps(
                    {"cached_at": now.isoformat(), "data": data},
                    ensure_ascii=False,
                ),
                encoding="utf-8",
                newline="\n",
            )
            temporary.replace(path)
        except OSError:
            # A cache that cannot be written is a slow run, not a failed one.
            return


class _RateLimiter:
    """Sliding-window limiter; `sleeper` is injected so tests never wait."""

    def __init__(
        self,
        allowance: int,
        window: float,
        *,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.allowance = allowance
        self.window = window
        self.sleeper = sleeper
        self.clock = clock
        self._calls: list[float] = []

    def wait(self) -> None:
        now = self.clock()
        self._calls = [item for item in self._calls if now - item < self.window]
        if len(self._calls) >= self.allowance:
            delay = self.window - (now - self._calls[0])
            if delay > 0:
                self.sleeper(delay)
                now = self.clock()
                self._calls = [item for item in self._calls if now - item < self.window]
        self._calls.append(self.clock())


def fetcher_for(parser: Any) -> Fetcher:
    """Borrow an already-open NewsParser: HTTPS, host allowlist, public IPs only."""

    def fetch(
        url: str, allowed_hosts: tuple[str, ...], headers: dict[str, str] | None
    ) -> bytes:
        return parser._get(url, allowed_hosts=allowed_hosts, headers=headers).content

    return fetch


def default_fetcher(timeout: float = 25.0) -> tuple[Fetcher, Callable[[], None]]:
    """Open a parser of our own, for callers that do not already hold one."""
    from .parser import NewsParser

    parser = NewsParser(timeout=timeout)
    return fetcher_for(parser), parser.close


def _load_kev(
    *,
    fetcher: Fetcher,
    cache: EnrichmentCache,
    now: datetime,
    errors: list[str],
) -> dict[str, Any]:
    cached = cache.read("kev.json", KEV_TTL, now=now)
    if cached is not None:
        return cached
    try:
        raw = fetcher(KEV_URL, (KEV_HOST,), None)
        payload = json.loads(raw.decode("utf-8"))
    except (ParseError, ValueError, UnicodeDecodeError) as error:
        errors.append(f"KEV catalogue unavailable: {error}")
        return {}
    if not isinstance(payload, dict):
        errors.append("KEV catalogue is not a JSON object")
        return {}
    cache.write("kev.json", payload, now=now)
    return payload


def _kev_index(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list):
        return {}
    index: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cveID")
        if isinstance(cve_id, str) and CVE_ID_RE.match(cve_id):
            index[cve_id.upper()] = entry
    return index


def _best_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None, str | None]:
    """Prefer the newest CVSS version NVD published for this CVE."""
    for key, version in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        primary = next(
            (
                item
                for item in entries
                if isinstance(item, dict) and item.get("type") == "Primary"
            ),
            next((item for item in entries if isinstance(item, dict)), None),
        )
        if primary is None:
            continue
        data = primary.get("cvssData")
        if not isinstance(data, dict):
            continue
        score = data.get("baseScore")
        if not isinstance(score, (int, float)):
            continue
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        return (
            float(score),
            str(severity).upper() if severity else None,
            str(data.get("version") or version),
            data.get("vectorString") if isinstance(data.get("vectorString"), str) else None,
        )
    return None, None, None, None


def _nvd_fields(payload: dict[str, Any]) -> dict[str, Any]:
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list) or not entries:
        return {}
    record = entries[0]
    cve = record.get("cve") if isinstance(record, dict) else None
    if not isinstance(cve, dict):
        return {}
    metrics = cve.get("metrics")
    score, severity, version, vector = (
        _best_cvss(metrics) if isinstance(metrics, dict) else (None, None, None, None)
    )
    status = cve.get("vulnStatus")
    return {
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_version": version,
        "cvss_vector": vector,
        "nvd_status": str(status) if isinstance(status, str) else None,
    }


def _load_nvd(
    cve_id: str,
    *,
    fetcher: Fetcher,
    cache: EnrichmentCache,
    limiter: _RateLimiter,
    api_key: str | None,
    now: datetime,
    errors: list[str],
    stats: dict[str, int],
) -> dict[str, Any] | None:
    name = f"nvd/{cve_id}.json"
    entry = cache.read_entry(name)
    if entry is not None:
        cached, stored = entry
        # A scored record stays usable for a week; one still awaiting analysis
        # is re-checked the next day.
        ttl = NVD_TTL_SCORED if cached.get("cvss_score") is not None else NVD_TTL_UNSCORED
        if now - stored <= ttl:
            stats["cache_hits"] += 1
            return cached
    limiter.wait()
    stats["lookups"] += 1
    headers = {"apiKey": api_key} if api_key else None
    try:
        raw = fetcher(f"{NVD_URL}?cveId={cve_id}", (NVD_HOST,), headers)
        payload = json.loads(raw.decode("utf-8"))
    except (ParseError, ValueError, UnicodeDecodeError) as error:
        errors.append(f"{cve_id}: NVD lookup failed: {error}")
        return None
    if not isinstance(payload, dict):
        errors.append(f"{cve_id}: NVD response is not a JSON object")
        return None
    fields = _nvd_fields(payload)
    if not fields:
        # A CVE NVD has not ingested yet; cache the miss so the next run of the
        # day does not ask again.
        fields = {"nvd_status": "Unknown"}
    cache.write(name, fields, now=now)
    return fields


def enrich_cves(
    cve_ids: Iterable[str],
    *,
    fetcher: Fetcher,
    cache_dir: str | Path,
    api_key: str | None = None,
    now: datetime | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[dict[str, CveIntel], EnrichmentReport]:
    """Look up KEV membership and NVD CVSS for each CVE.

    Never raises for a network or data problem: whatever could not be resolved
    is recorded in the returned report and the CVE is simply left un-enriched.
    """
    moment = now or _utcnow()
    stamp = moment.isoformat()
    wanted = sorted({item.upper() for item in cve_ids if CVE_ID_RE.match(item)})
    errors: list[str] = []
    if not wanted:
        return {}, EnrichmentReport(enabled=True, errors=errors)

    cache = EnrichmentCache(cache_dir)
    kev_payload = _load_kev(fetcher=fetcher, cache=cache, now=moment, errors=errors)
    kev = _kev_index(kev_payload)
    limiter = _RateLimiter(
        *(NVD_RATE_WITH_KEY if api_key else NVD_RATE_WITHOUT_KEY),
        sleeper=sleeper,
        clock=clock,
    )
    stats = {"cache_hits": 0, "lookups": 0}

    intel: dict[str, CveIntel] = {}
    for cve_id in wanted:
        entry = kev.get(cve_id)
        nvd = _load_nvd(
            cve_id,
            fetcher=fetcher,
            cache=cache,
            limiter=limiter,
            api_key=api_key,
            now=moment,
            errors=errors,
            stats=stats,
        )
        sources: list[str] = []
        if entry:
            sources.append(KEV_URL)
        if nvd:
            sources.append(f"{NVD_URL}?cveId={cve_id}")
        ransomware = (entry or {}).get("knownRansomwareCampaignUse")
        record = CveIntel(
            cve_id=cve_id,
            kev=bool(entry),
            kev_date_added=(entry or {}).get("dateAdded") or None,
            kev_due_date=(entry or {}).get("dueDate") or None,
            kev_known_ransomware=(
                ransomware.strip().lower() == "known"
                if isinstance(ransomware, str) and ransomware.strip()
                else None
            ),
            cvss_score=(nvd or {}).get("cvss_score"),
            cvss_severity=(nvd or {}).get("cvss_severity"),
            cvss_version=(nvd or {}).get("cvss_version"),
            cvss_vector=(nvd or {}).get("cvss_vector"),
            nvd_status=(nvd or {}).get("nvd_status"),
            sources=sources,
            retrieved_at=stamp,
        )
        if record.has_data:
            intel[cve_id] = record

    report = EnrichmentReport(
        enabled=True,
        requested_cve_count=len(wanted),
        enriched_cve_count=len(intel),
        kev_count=sum(1 for item in intel.values() if item.kev),
        cvss_count=sum(1 for item in intel.values() if item.cvss_score is not None),
        kev_catalog_version=(
            str(kev_payload.get("catalogVersion"))
            if kev_payload.get("catalogVersion")
            else None
        ),
        kev_catalog_released=(
            str(kev_payload.get("dateReleased"))
            if kev_payload.get("dateReleased")
            else None
        ),
        cache_hits=stats["cache_hits"],
        lookups=stats["lookups"],
        errors=errors,
        sources=[KEV_URL, NVD_URL],
    )
    return intel, report


def disabled_report() -> EnrichmentReport:
    return EnrichmentReport(enabled=False)


def collect_cve_ids(manifests: Sequence[Any]) -> list[str]:
    """Every confirmed CVE across the day's manifests."""
    found: set[str] = set()
    for manifest in manifests:
        for evidence in getattr(manifest, "evidence", []) or []:
            if (
                getattr(evidence, "status", "") == "confirmed"
                and getattr(evidence, "indicator_type", "") == "cve"
            ):
                found.add(str(evidence.normalized_value).upper())
    return sorted(found)
