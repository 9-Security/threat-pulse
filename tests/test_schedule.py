from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from soc_news_parser.schedule import (
    current_slot,
    find_previous_json,
    next_slot,
    report_paths,
    slot_window,
)


TAIPEI = ZoneInfo("Asia/Taipei")


def test_current_slot_before_six_uses_yesterday() -> None:
    now = datetime(2026, 8, 30, 5, 59, tzinfo=TAIPEI)
    slot = current_slot(now)
    assert slot == datetime(2026, 8, 29, 6, 0, tzinfo=TAIPEI)


def test_current_slot_at_six_uses_today() -> None:
    now = datetime(2026, 8, 30, 6, 0, tzinfo=TAIPEI)
    slot = current_slot(now)
    assert slot == datetime(2026, 8, 30, 6, 0, tzinfo=TAIPEI)


def test_next_slot_after_six_is_tomorrow() -> None:
    now = datetime(2026, 8, 30, 6, 0, tzinfo=TAIPEI)
    assert next_slot(now) == datetime(2026, 8, 31, 6, 0, tzinfo=TAIPEI)


def test_slot_window_is_previous_24_hours() -> None:
    slot = datetime(2026, 8, 30, 6, 0, tzinfo=TAIPEI)
    since, until = slot_window(slot, 24)
    assert until.isoformat() == "2026-08-29T22:00:00+00:00"
    assert since.isoformat() == "2026-08-28T22:00:00+00:00"


def test_previous_json_comes_from_prior_date_folder(tmp_path: Path) -> None:
    slot = datetime(2026, 8, 30, 6, 0, tzinfo=TAIPEI)
    yesterday = tmp_path / "2026-08-29"
    yesterday.mkdir()
    previous = yesterday / "daily-evidence.json"
    previous.write_text("{}", encoding="utf-8")
    json_path, markdown_path, csv_path = report_paths(tmp_path, slot, "Asia/Taipei")
    assert json_path == tmp_path / "2026-08-30" / "daily-evidence.json"
    assert markdown_path.name == "daily-report.md"
    assert csv_path.name == "iocs.csv"
    assert find_previous_json(tmp_path, slot, "Asia/Taipei") == previous
    assert find_previous_json(tmp_path, slot.replace(day=31), "Asia/Taipei") is None
