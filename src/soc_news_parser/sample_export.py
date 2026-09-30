"""The sample side of the corpus: values the malware analyser found in a file.

The analyser at malware.nine-security.com holds what this collector cannot: a
file, and what static analysis says about it. Its indicators are read here and
pushed to the same D1 database the news side uses, so one lookup can answer from
both -- while saying which side answered, because the two claims differ in
strength.

**Read over the analyser's HTTP API, not its database.** Its Postgres runs in a
container with no published port, the API already restricts every listing to
`visibility = 'public'`, and going through it means this exporter holds no
credential for, and takes no lock on, the production database of a live public
service. Unauthenticated reads are capped at 120 a minute per address, so
requests are paced under that.

Normalisation is the news side's own: `_normalize` from `evidence` and
`registrable_domain` from `publicsuffix`. Anything else and the same domain would
hit on one side and miss on the other, which is the failure a merged lookup makes
hardest to notice.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Sequence

import httpx

from .evidence import _hash_type, _normalize
from .parser import _is_public_address
from .publicsuffix import registrable_domain

ANALYZER_BASE_URL = "http://127.0.0.1:18080"
REPORT_URL_TEMPLATE = "https://malware.nine-security.com/s/{sha256}"

# Unauthenticated reads are limited to 120 a minute per address. Staying under it
# rather than at it leaves room for a human using the site from the same host.
REQUESTS_PER_MINUTE = 90

# The analyser's feed caps a page at 100.
PAGE_SIZE = 100

# A value longer than this is not an indicator anyone will submit; the analyser's
# `strings` integration occasionally emits very long paths.
MAX_VALUE_CHARS = 512

# Types served by value. `hash` is split by length so a caller's md5 meets the
# same type name the news side uses. `mutex`, `path`, `email` and `registry` have
# no news-side counterpart and are answered by the sample side alone.
PASSTHROUGH_TYPES = frozenset({"domain", "ip", "url", "mutex", "path", "email", "registry"})


@dataclass(frozen=True)
class SampleIndicator:
    """One value found in one sample."""

    sha256: str
    indicator_type: str
    value: str
    confidence: int
    integration: str | None
    tags: tuple[str, ...]
    first_seen_at: str
    registrable_lc: str | None


@dataclass(frozen=True)
class SampleAnalysis:
    """One analysed sample: how to reach it by any hash, and what it is."""

    sha256: str
    md5: str | None
    sha1: str | None
    size_bytes: int | None
    file_type: str | None
    submitted_at: str | None
    finished_at: str | None
    verdict: str | None
    verdict_score: int | None
    family: str | None
    family_confidence: int | None
    attack_techniques: tuple[str, ...]
    ioc_total: int | None
    indicators: tuple[SampleIndicator, ...]

    @property
    def report_url(self) -> str:
        return REPORT_URL_TEMPLATE.format(sha256=self.sha256)


class AnalyzerError(RuntimeError):
    """The analyser could not be read. One sample's failure is not this."""


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _served_type(kind: str, value: str) -> str | None:
    """The type name this value is served under, or None to drop it."""
    if kind == "hash":
        try:
            return _hash_type(value)
        except KeyError:
            # Not a hash length anyone queries -- imphash, ssdeep and the like
            # arrive here and are not looked up by value.
            return None
    return kind if kind in PASSTHROUGH_TYPES else None


def _usable(indicator_type: str, value: str) -> bool:
    """Whether the service could ever answer about this value.

    A private or reserved address is refused at query time, so holding one is
    holding something unreachable. Everything else is kept: an exclusion is the
    query's job, and `excluded_values` already answers it for both sides.
    """
    if not value or len(value) > MAX_VALUE_CHARS:
        return False
    if indicator_type == "ip":
        return _is_public_address(value)
    return True


class AnalyzerClient:
    """The analyser's public read API, paced under its rate limit."""

    def __init__(
        self,
        base_url: str = ANALYZER_BASE_URL,
        *,
        client: httpx.Client | None = None,
        page_size: int = PAGE_SIZE,
        requests_per_minute: int = REQUESTS_PER_MINUTE,
        sleep: Callable[[float], None] = time.sleep,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(
            timeout=timeout, headers={"user-agent": "threat-pulse sample export"}
        )
        self.page_size = max(1, min(page_size, PAGE_SIZE))
        self._interval = 60.0 / requests_per_minute if requests_per_minute > 0 else 0.0
        self._sleep = sleep
        self._last_call = 0.0
        self.failures: list[str] = []

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> AnalyzerClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        if self._interval:
            waited = time.monotonic() - self._last_call
            if 0 <= waited < self._interval:
                self._sleep(self._interval - waited)
        self._last_call = time.monotonic()
        try:
            response = self.client.get(f"{self.base_url}{path}", params=params)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise AnalyzerError(f"{path}: {error}") from error

    def recent(
        self, *, stop_at: str | None = None, max_samples: int | None = None
    ) -> Iterator[dict[str, Any]]:
        """Finished public jobs, newest first, until `stop_at` is reached.

        The feed is ordered by `finished_at` descending, so a run stops at the
        last run's high water mark instead of reading the whole corpus again.
        """
        seen = 0
        offset = 0
        while True:
            payload = self._get(
                "/api/feed/recent", {"limit": self.page_size, "offset": offset}
            )
            items = payload.get("items") if isinstance(payload, dict) else payload
            if not isinstance(items, list) or not items:
                return
            for item in items:
                if not isinstance(item, dict) or not _text(item.get("sha256")):
                    continue
                finished = _text(item.get("finished_at")) or _text(item.get("submitted_at"))
                if stop_at and finished and finished <= stop_at:
                    return
                yield item
                seen += 1
                if max_samples is not None and seen >= max_samples:
                    return
            offset += len(items)

    def sample_of(self, sample_id: str) -> dict[str, Any]:
        """The sample's own record, which is the only place md5 and sha1 appear.

        The feed carries sha256 alone, so without this a caller could not arrive
        by md5 -- the one lookup the news side can never answer. Sample ids come
        from the public feed, so this never asks for a sample the feed withheld.
        """
        payload = self._get(f"/api/samples/{sample_id}")
        return payload if isinstance(payload, dict) else {}

    def indicators_of(self, job_id: str) -> list[dict[str, Any]]:
        payload = self._get(f"/api/jobs/{job_id}/iocs", {"limit": 2000})
        return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []

    def summary_of(self, job_id: str) -> dict[str, Any]:
        payload = self._get(f"/api/jobs/{job_id}/threat-intel-summary")
        return payload if isinstance(payload, dict) else {}

    def techniques_of(self, job_id: str) -> tuple[str, ...]:
        payload = self._get(f"/api/jobs/{job_id}/attack-summary")
        techniques = payload.get("techniques") if isinstance(payload, dict) else None
        if not isinstance(techniques, list):
            return ()
        ids: list[str] = []
        for entry in techniques:
            found = _text(entry.get("technique_id") or entry.get("id")) if isinstance(entry, dict) else _text(entry)
            if found and found not in ids:
                ids.append(found)
        return tuple(ids)


def _indicators_for(
    sha256: str, rows: Sequence[dict[str, Any]]
) -> tuple[SampleIndicator, ...]:
    """Normalised indicators for one sample, strongest reading of each value kept.

    The analyser records a value once per extraction, so the same domain can
    arrive from `config_extractor` and from `strings`. The row kept is the one
    with the highest confidence, because that is the claim the answer makes.
    """
    best: dict[tuple[str, str], SampleIndicator] = {}
    for row in rows:
        raw = _text(row.get("value"))
        kind = _text(row.get("ioc_type"))
        if not raw or not kind:
            continue
        served = _served_type(kind, raw)
        if served is None:
            continue
        value = _normalize(raw, served)
        if not _usable(served, value):
            continue
        tags = row.get("tags")
        indicator = SampleIndicator(
            sha256=sha256,
            indicator_type=served,
            value=value,
            confidence=int(row.get("confidence") or 0),
            integration=_text(row.get("source_integration_id")),
            tags=tuple(str(tag) for tag in tags) if isinstance(tags, list) else (),
            first_seen_at=_text(row.get("first_seen_at")) or "",
            registrable_lc=(registrable_domain(value) or None) if served == "domain" else None,
        )
        key = (served, value.lower())
        current = best.get(key)
        if current is None or indicator.confidence > current.confidence:
            best[key] = indicator
    return tuple(best[key] for key in sorted(best))


def collect_samples(
    client: AnalyzerClient,
    *,
    stop_at: str | None = None,
    max_samples: int | None = None,
) -> list[SampleAnalysis]:
    """Read new samples and their indicators.

    A sample whose summary cannot be read is still exported, with its indicators
    and no summary: the values are the part a lookup needs, and losing them
    because one endpoint failed would be the worse outcome. The failure is
    recorded on the client so the caller can report it.
    """
    samples: list[SampleAnalysis] = []
    for item in client.recent(stop_at=stop_at, max_samples=max_samples):
        sha256 = _text(item.get("sha256"))
        job_id = _text(item.get("job_id"))
        if not sha256 or not job_id:
            continue
        try:
            rows = client.indicators_of(job_id)
        except AnalyzerError as error:
            client.failures.append(f"indicators {sha256[:12]}: {error}")
            continue
        summary: dict[str, Any] = {}
        techniques: tuple[str, ...] = ()
        try:
            summary = client.summary_of(job_id)
            techniques = client.techniques_of(job_id)
        except AnalyzerError as error:
            client.failures.append(f"summary {sha256[:12]}: {error}")
        record: dict[str, Any] = {}
        sample_id = _text(item.get("sample_id"))
        if sample_id:
            try:
                record = client.sample_of(sample_id)
            except AnalyzerError as error:
                client.failures.append(f"sample {sha256[:12]}: {error}")
        verdict = item.get("verdict") if isinstance(item.get("verdict"), dict) else {}
        samples.append(
            SampleAnalysis(
                sha256=sha256.lower(),
                md5=(_text(record.get("md5")) or "").lower() or None,
                sha1=(_text(record.get("sha1")) or "").lower() or None,
                size_bytes=next(
                    (v for v in (record.get("size_bytes"), item.get("size_bytes")) if isinstance(v, int)),
                    None,
                ),
                file_type=_text(item.get("file_type")) or _text(record.get("mime")),
                submitted_at=_text(item.get("submitted_at")) or _text(record.get("uploaded_at")),
                finished_at=_text(item.get("finished_at")),
                verdict=_text(summary.get("verdict_label")) or _text(verdict.get("label")),
                verdict_score=summary.get("verdict_score") if isinstance(summary.get("verdict_score"), int) else None,
                family=_text(summary.get("family")),
                family_confidence=summary.get("family_confidence")
                if isinstance(summary.get("family_confidence"), int)
                else None,
                attack_techniques=techniques,
                ioc_total=summary.get("ioc_total") if isinstance(summary.get("ioc_total"), int) else None,
                indicators=_indicators_for(sha256.lower(), rows),
            )
        )
    return samples


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"


def _row(values: Sequence[Any]) -> str:
    return "(" + ", ".join(_sql_literal(item) for item in values) + ")"


SAMPLE_ANALYSIS_COLUMNS = (
    "sha256, md5, sha1, size_bytes, file_type, submitted_at, finished_at, "
    "verdict, verdict_score, family, family_confidence, attack_techniques, "
    "ioc_total, report_url, ingested_at"
)
SAMPLE_INDICATOR_COLUMNS = (
    "sha256, indicator_type, value, confidence, integration, tags, "
    "first_seen_at, registrable_lc"
)

# One statement per 200 rows: D1 runs the file as one batch and a single
# statement with thousands of tuples is what its parser chokes on first.
BATCH_ROWS = 200


def _insert_batches(rows: Sequence[Sequence[Any]], table: str, columns: str) -> list[str]:
    lines: list[str] = []
    for start in range(0, len(rows), BATCH_ROWS):
        chunk = rows[start : start + BATCH_ROWS]
        lines.append(f"INSERT OR REPLACE INTO {table} ({columns}) VALUES")
        lines.append(",\n".join(_row(row) for row in chunk) + ";")
    return lines


def high_water_of(samples: Sequence[SampleAnalysis], previous: str | None = None) -> str | None:
    """The newest `finished_at` consumed, so the next run reads only what is new."""
    stamps = [s.finished_at for s in samples if s.finished_at]
    if previous:
        stamps.append(previous)
    return max(stamps) if stamps else None


def render_sql(
    samples: Sequence[SampleAnalysis],
    *,
    exported_at: str | None = None,
    high_water: str | None = None,
    analyzer: str = REPORT_URL_TEMPLATE.split("/s/")[0],
) -> str:
    """Statements only, no transaction: D1 runs a file as one batch.

    Every write is an upsert keyed on the sample, so re-running an export that
    already landed changes nothing. `sample_state` is written last and in the
    same batch, so the freshness the service reports cannot describe a push that
    failed.
    """
    stamp = exported_at or datetime.now(timezone.utc).isoformat()
    analysis_rows = [
        (
            s.sha256,
            s.md5,
            s.sha1,
            s.size_bytes,
            s.file_type,
            s.submitted_at,
            s.finished_at,
            s.verdict,
            s.verdict_score,
            s.family,
            s.family_confidence,
            json.dumps(list(s.attack_techniques), ensure_ascii=False) if s.attack_techniques else None,
            s.ioc_total,
            s.report_url,
            stamp,
        )
        for s in samples
    ]
    indicator_rows = [
        (
            i.sha256,
            i.indicator_type,
            i.value,
            i.confidence,
            i.integration,
            json.dumps(list(i.tags), ensure_ascii=False) if i.tags else None,
            i.first_seen_at,
            i.registrable_lc,
        )
        for s in samples
        for i in s.indicators
    ]
    lines = [
        f"-- sample side of the corpus: {len(analysis_rows)} sample(s), "
        f"{len(indicator_rows)} indicator(s); no file contents.",
    ]
    lines.extend(_insert_batches(analysis_rows, "sample_analysis", SAMPLE_ANALYSIS_COLUMNS))
    lines.extend(_insert_batches(indicator_rows, "sample_indicators", SAMPLE_INDICATOR_COLUMNS))
    lines.append(
        "INSERT OR REPLACE INTO sample_state "
        "(id, exported_at, high_water, added_samples, added_indicators, analyzer) VALUES"
    )
    lines.append(
        _row((1, stamp, high_water, len(analysis_rows), len(indicator_rows), analyzer)) + ";"
    )
    return "\n".join(lines) + "\n"
