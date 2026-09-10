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
# Enrichment is an enhancement; the report is the deliverable. Without a budget a
# slow day takes the whole run down with it: on 2026-09-09 a window with 348 new
# CVEs spent 43 minutes inside NVD's unauthenticated 5-per-30s limit, overran the
# unit timeout, and was killed -- losing 32 already-collected articles for a day
# that cannot be collected again. A deadline turns that into some missing CVSS
# scores. With an API key the same 348 take about four minutes, so this ceiling
# is reached only when something is wrong.
NVD_BUDGET_SECONDS = 900.0
NVD_RATE_WITHOUT_KEY = (4, 30.0)
NVD_RATE_WITH_KEY = (45, 30.0)

# EPSS answers a question neither KEV nor CVSS does. KEV is "already exploited";
# CVSS is "how bad if it is". EPSS is the probability of exploitation in the next
# thirty days, which is what actually orders a patch list. On 2026-09-10, 68% of
# the 345 non-KEV CVEs shared a CVSS score with another -- 33 at 9.8, 47 at 8.8,
# 52 at 7.8 -- so severity alone left 132 of them in arbitrary order.
#
# Queried in batches rather than by the daily bulk file: that file decompresses
# to 10.7 MiB against this project's 12 MiB ceiling and grows every day, so it
# would break on a date nobody chose. Batches fetch only the CVEs in the report.
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_HOST = "api.first.org"
EPSS_BATCH = 100
# Scores are recomputed daily, so yesterday's is stale by definition.
EPSS_TTL = timedelta(hours=20)

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
    # Probability of exploitation in the next 30 days, and where that sits among
    # all scored CVEs. The percentile travels with the score because the raw
    # number moves when the model version does.
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None
    sources: list[str] = field(default_factory=list)
    retrieved_at: str | None = None

    @property
    def has_data(self) -> bool:
        return (
            self.kev
            or self.cvss_score is not None
            or self.nvd_status is not None
            or self.epss_score is not None
        )

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
    epss_count: int = 0
    kev_catalog_version: str | None = None
    kev_catalog_released: str | None = None
    cache_hits: int = 0
    lookups: int = 0
    # Counted apart from `errors`: the budget appends one message, and rendering
    # len(errors) told the analyst "1 lookup failed" when hundreds went
    # unqueried. Only CVEs that ended with no data at all are counted -- one
    # served from a stale cache entry lost its refresh, not its score.
    skipped_cve_count: int = 0
    stale_cache_hits: int = 0
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


def _load_epss(
    cve_ids: Sequence[str],
    *,
    fetcher: Fetcher,
    cache: EnrichmentCache,
    now: datetime,
    errors: list[str],
    stats: dict[str, int],
) -> dict[str, dict[str, Any]]:
    """EPSS scores for the CVEs in this report, cached per CVE and fetched in
    batches for whatever is left.

    A CVE absent from the answer is cached as a miss, so a report that repeats it
    tomorrow does not ask again. EPSS carries no entry for a CVE it has not
    scored yet, and that is a fact about the CVE rather than a failed lookup.
    """
    scores: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for cve_id in cve_ids:
        cached = cache.read(f"epss/{cve_id}.json", EPSS_TTL, now=now)
        if cached is None:
            missing.append(cve_id)
            continue
        stats["epss_cache_hits"] += 1
        if cached.get("epss_score") is not None:
            scores[cve_id] = cached

    for start in range(0, len(missing), EPSS_BATCH):
        batch = missing[start : start + EPSS_BATCH]
        stats["epss_lookups"] += 1
        try:
            raw = fetcher(f"{EPSS_URL}?cve={','.join(batch)}", (EPSS_HOST,), None)
            payload = json.loads(raw.decode("utf-8"))
        except (ParseError, ValueError, UnicodeDecodeError) as error:
            errors.append(f"EPSS lookup failed for {len(batch)} CVEs: {error}")
            continue
        rows = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            errors.append("EPSS response has no data array")
            continue

        answered: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            cve_id = str(row.get("cve") or "").upper()
            try:
                record = {
                    "epss_score": float(row["epss"]),
                    "epss_percentile": float(row["percentile"]),
                    "epss_date": str(row.get("date") or "") or None,
                }
            except (KeyError, TypeError, ValueError):
                continue
            answered[cve_id] = record
        for cve_id in batch:
            record = answered.get(cve_id, {"epss_score": None})
            cache.write(f"epss/{cve_id}.json", record, now=now)
            if record.get("epss_score") is not None:
                scores[cve_id] = record
    return scores


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
    cache_only: bool = False,
) -> dict[str, Any] | None:
    name = f"nvd/{cve_id}.json"
    stale: dict[str, Any] | None = None
    entry = cache.read_entry(name)
    if entry is not None:
        cached, stored = entry
        # A scored record stays usable for a week; one still awaiting analysis
        # is re-checked the next day.
        ttl = NVD_TTL_SCORED if cached.get("cvss_score") is not None else NVD_TTL_UNSCORED
        if now - stored <= ttl:
            stats["cache_hits"] += 1
            return cached
        stale = cached
    if cache_only:
        # The time budget is spent, so the rate-limited request stops. Anything
        # on disk is still served, including a record past its refresh age: the
        # only alternative here is no score at all, and last week's 9.8 ranks a
        # CVE far better than a null does. Refreshing it is what has been given
        # up, not knowing it.
        if stale is not None:
            stats["stale_hits"] += 1
            return stale
        return None
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
    budget_seconds: float | None = NVD_BUDGET_SECONDS,
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
    stats = {
        "cache_hits": 0,
        "lookups": 0,
        "stale_hits": 0,
        # Kept apart from the NVD counters. Sharing them would report four
        # batched EPSS calls as four NVD lookups and make the rate-limit
        # arithmetic in the journal impossible to follow.
        "epss_cache_hits": 0,
        "epss_lookups": 0,
    }
    # One batched pass before the per-CVE loop. EPSS is not rate limited the way
    # NVD is, so it sits outside the time budget: 327 CVEs cost four requests.
    epss = _load_epss(
        wanted, fetcher=fetcher, cache=cache, now=moment, errors=errors, stats=stats
    )

    intel: dict[str, CveIntel] = {}
    started = clock()
    budget_spent = False
    budget_cut_at: int | None = None
    unqueried = 0
    for index, cve_id in enumerate(wanted):
        entry = kev.get(cve_id)
        # KEV came from one request for the whole catalogue and is what the patch
        # list ranks on, so it keeps being applied to every CVE below. Only the
        # per-CVE NVD request stops, and cached NVD records are still served.
        if (
            not budget_spent
            and budget_seconds is not None
            and clock() - started >= budget_seconds
        ):
            budget_spent = True
            budget_cut_at = index
        nvd = _load_nvd(
            cve_id,
            fetcher=fetcher,
            cache=cache,
            limiter=limiter,
            api_key=api_key,
            now=moment,
            errors=errors,
            stats=stats,
            cache_only=budget_spent,
        )
        if budget_spent and nvd is None:
            # Past the cut-off with nothing on disk either: this one really did
            # go without. A cached hit above is not counted here.
            unqueried += 1
        sources: list[str] = []
        if entry:
            sources.append(KEV_URL)
        if nvd:
            sources.append(f"{NVD_URL}?cveId={cve_id}")
        epss_record = epss.get(cve_id) or {}
        if epss_record:
            sources.append(EPSS_URL)
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
            epss_score=epss_record.get("epss_score"),
            epss_percentile=epss_record.get("epss_percentile"),
            epss_date=epss_record.get("epss_date"),
            sources=sources,
            retrieved_at=stamp,
        )
        if record.has_data:
            intel[cve_id] = record

    if budget_cut_at is not None:
        errors.append(
            f"NVD requests stopped after {budget_seconds:.0f}s at CVE "
            f"{budget_cut_at + 1} of {len(wanted)}; {unqueried} ended with no "
            f"score, {stats['stale_hits']} were served from a cache entry past "
            "its refresh age. KEV still applied to all. Set NVD_API_KEY to "
            "raise the request rate."
        )

    report = EnrichmentReport(
        enabled=True,
        requested_cve_count=len(wanted),
        enriched_cve_count=len(intel),
        kev_count=sum(1 for item in intel.values() if item.kev),
        cvss_count=sum(1 for item in intel.values() if item.cvss_score is not None),
        epss_count=sum(1 for item in intel.values() if item.epss_score is not None),
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
        skipped_cve_count=unqueried,
        stale_cache_hits=stats["stale_hits"],
        errors=errors,
        sources=[KEV_URL, NVD_URL, EPSS_URL],
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
