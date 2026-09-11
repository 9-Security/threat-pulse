"""Consecutive-failure tracking for the collector's sources.

A source that stops answering is not an outage anyone sees. The report still
goes out, the run still exits zero, and the only record is a field in that day's
JSON that nobody reads. CISA's advisory feed returned 403 for four consecutive
days; the report for the fourth went out carrying a single patch item and no
alert was raised, because the one alert this host had fires on the corpus
failing to grow and the corpus grew fine.

One failed day is usually a timeout and mailing about it teaches the reader to
ignore the mail. What is worth saying is that a source has failed every day
since some date, so streaks are counted from the newest report backwards and any
success ends one.

Repeats are spaced rather than suppressed: a streak is reported when it reaches
the threshold and again each time it doubles. That needs no stored state -- the
archive is the state -- and it keeps a long outage visible without sending the
same mail every morning.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .ioc_query import REPORT_DATE_RE, REPORT_FILENAME, reports_root
from .sources import SOURCES

# Two days, because one is a timeout and two is a pattern. A source that fails
# every day is not urgent -- the report goes out without it -- but it must not be
# able to stay broken silently, which is what happened.
FAILURE_STREAK_THRESHOLD = 2

# How far back to read. Long enough to see a streak that started over a holiday,
# short enough that the check costs nothing on a host with a year of archive.
DEFAULT_LOOKBACK_DAYS = 21


@dataclass(frozen=True)
class SourceStreak:
    """One source's run of consecutive failures, newest report first."""

    key: str
    name: str
    days: int
    since: str
    """The oldest date in the unbroken run -- the first report that lost it."""
    dates: tuple[str, ...]
    last_error: str

    @property
    def should_notify(self) -> bool:
        return _is_notify_point(self.days)


def _is_notify_point(days: int, threshold: int = FAILURE_STREAK_THRESHOLD) -> bool:
    """True at the threshold and at each doubling of it.

    With the default that is days 2, 4, 8, 16 -- two mails for a four-day outage
    and five for a month of one, instead of thirty.
    """
    if days < threshold:
        return False
    quotient, remainder = divmod(days, threshold)
    if remainder:
        return False
    # A power of two multiple of the threshold.
    return quotient & (quotient - 1) == 0


def _read_days(reports_dir: str | Path | None, lookback: int) -> list[tuple[str, dict[str, Any]]]:
    """The newest `lookback` reports, newest first.

    A date whose JSON cannot be read is left out entirely rather than treated as
    a silent success: a day we cannot read is a day we know nothing about, and
    joining the two sides of it would report a streak that was never observed.
    """
    base = reports_root(reports_dir)
    if not base.is_dir():
        return []
    days: list[tuple[str, dict[str, Any]]] = []
    for folder in sorted(base.iterdir(), reverse=True):
        if len(days) >= lookback:
            break
        if not REPORT_DATE_RE.match(folder.name) or not folder.is_dir():
            continue
        evidence = folder / REPORT_FILENAME
        if not evidence.is_file():
            continue
        try:
            payload = json.loads(evidence.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if isinstance(payload, dict):
            days.append((folder.name, payload))
    return days


def _one_line(text: str, limit: int = 240) -> str:
    """Errors carry their own newlines -- httpx appends a documentation link.

    Left as they are they break the indentation of the mail body and turn a
    three-line summary into a wall, so they are collapsed to one line and cut.
    """
    collapsed = " ".join(text.split())
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1].rstrip() + "…"


def _failures_of(payload: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Which sources failed on one day, by key.

    An entry with no `source_key` is dropped: the key is what a streak is
    counted on, and two days cannot be joined on a name that may be blank.
    """
    failed: dict[str, dict[str, str]] = {}
    for entry in payload.get("source_failures") or []:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("source_key") or "").strip()
        if not key:
            continue
        failed[key] = {
            "name": _one_line(str(entry.get("source_name") or ""), 120),
            "error": _one_line(str(entry.get("error") or "")),
        }
    return failed


def source_streaks(
    reports_dir: str | Path | None = None,
    *,
    lookback: int = DEFAULT_LOOKBACK_DAYS,
) -> list[SourceStreak]:
    """Every source currently failing, longest streak first.

    A streak has to reach the newest report to count. A source that failed on
    Monday and Tuesday and recovered on Wednesday is working, and reporting it
    would be reporting history.
    """
    days = _read_days(reports_dir, lookback)
    if not days:
        return []

    newest_failures = _failures_of(days[0][1])
    streaks: list[SourceStreak] = []
    for key in newest_failures:
        dates: list[str] = []
        error = newest_failures[key]["error"]
        name = newest_failures[key]["name"]
        for date, payload in days:
            failed = _failures_of(payload)
            if key not in failed:
                # It answered that day, or was not on that day's list at all.
                # Either way the unbroken run of observed failures ends here:
                # a day with no evidence of failure is not a failing day, and a
                # source dropped from the registry and re-added later must not
                # carry a streak across the gap.
                break
            dates.append(date)
            # The newest message is the one kept -- `since` already says when the
            # run started, so what the mail is missing is what is wrong now. Days
            # are walked newest first, so only fill in what the newest day left
            # blank rather than letting an older day overwrite it.
            error = error or failed[key]["error"]
            name = name or failed[key]["name"]
        registered = SOURCES.get(key)
        streaks.append(
            SourceStreak(
                key=key,
                name=name or (registered.name if registered else key),
                days=len(dates),
                since=dates[-1],
                dates=tuple(dates),
                last_error=error,
            )
        )
    streaks.sort(key=lambda item: (-item.days, item.key))
    return streaks


def render_alert(streaks: list[SourceStreak], *, hostname: str = "") -> str:
    """The mail body, or "" when nothing is due.

    Streaks below the threshold are still listed once something else is due, so
    the reader sees the whole picture rather than one source out of three.
    """
    due = [item for item in streaks if item.should_notify]
    if not due:
        return ""

    lines = [
        "A source the collector reads has failed on every run since the date below.",
        "The daily report still goes out; it goes out missing this source's articles,",
        "and a day that is collected without them cannot be collected again later.",
        "",
    ]
    for item in due:
        lines.append(f"{item.name} ({item.key})")
        lines.append(f"  failing for {item.days} consecutive reports, since {item.since}")
        lines.append(f"  last error: {item.last_error or '(no message recorded)'}")
        lines.append("")

    others = [item for item in streaks if not item.should_notify]
    if others:
        lines.append("Also failing on the most recent report, not yet at a reporting point:")
        for item in others:
            lines.append(f"  {item.name} ({item.key}): {item.days} day(s), since {item.since}")
        lines.append("")

    lines.append(
        f"Reported at {FAILURE_STREAK_THRESHOLD} consecutive days and at each doubling "
        f"({FAILURE_STREAK_THRESHOLD}, {FAILURE_STREAK_THRESHOLD * 2}, "
        f"{FAILURE_STREAK_THRESHOLD * 4}, ...), so silence after this is not recovery."
    )
    if hostname:
        lines.append(f"host: {hostname}")
    return "\n".join(lines)


def render_summary(streaks: list[SourceStreak], *, total_sources: int | None = None) -> str:
    """What the journal gets every day, due or not."""
    total = len(SOURCES) if total_sources is None else total_sources
    if not streaks:
        return f"source health: all {total} sources answered on the most recent report"
    parts = [
        f"{item.key}={item.days}d{'!' if item.should_notify else ''}" for item in streaks
    ]
    return (
        f"source health: {len(streaks)} of {total} failing on the most recent report "
        f"({', '.join(parts)}); ! marks a streak being reported"
    )
