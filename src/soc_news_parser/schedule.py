from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_TIMEZONE = "Asia/Taipei"
DEFAULT_CLOCK = "06:00"


def parse_clock(value: str) -> tuple[int, int]:
    parts = value.strip().split(":")
    if len(parts) != 2:
        raise ValueError("time must be HH:MM")
    hour = int(parts[0])
    minute = int(parts[1])
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        raise ValueError("time must be HH:MM")
    return hour, minute


def load_zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as error:
        raise ValueError(f"unknown timezone: {name}") from error


def current_slot(
    now: datetime,
    *,
    timezone_name: str = DEFAULT_TIMEZONE,
    clock: str = DEFAULT_CLOCK,
) -> datetime:
    zone = load_zone(timezone_name)
    hour, minute = parse_clock(clock)
    local = now.astimezone(zone)
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if local < candidate:
        candidate -= timedelta(days=1)
    return candidate


def next_slot(
    now: datetime,
    *,
    timezone_name: str = DEFAULT_TIMEZONE,
    clock: str = DEFAULT_CLOCK,
) -> datetime:
    zone = load_zone(timezone_name)
    hour, minute = parse_clock(clock)
    local = now.astimezone(zone)
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if local >= candidate:
        candidate += timedelta(days=1)
    return candidate


def slot_window(slot: datetime, hours: int) -> tuple[datetime, datetime]:
    if hours <= 0:
        raise ValueError("hours must be greater than zero")
    until = slot.astimezone(timezone.utc)
    return until - timedelta(hours=hours), until


def slot_date_key(slot: datetime, timezone_name: str) -> str:
    return slot.astimezone(load_zone(timezone_name)).date().isoformat()


def report_directory(
    output_dir: str | Path, slot: datetime, timezone_name: str
) -> Path:
    return Path(output_dir).expanduser() / slot_date_key(slot, timezone_name)


def report_paths(
    output_dir: str | Path, slot: datetime, timezone_name: str
) -> tuple[Path, Path, Path]:
    folder = report_directory(output_dir, slot, timezone_name)
    return (
        folder / "daily-evidence.json",
        folder / "daily-report.md",
        folder / "iocs.csv",
    )


def find_previous_json(
    output_dir: str | Path, slot: datetime, timezone_name: str
) -> Path | None:
    previous_slot = slot - timedelta(days=1)
    path = report_directory(output_dir, previous_slot, timezone_name) / "daily-evidence.json"
    return path if path.is_file() else None
