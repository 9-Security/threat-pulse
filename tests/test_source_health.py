import json
from pathlib import Path

from soc_news_parser.source_health import (
    FAILURE_STREAK_THRESHOLD,
    _is_notify_point,
    render_alert,
    render_summary,
    source_streaks,
)


def _day(root: Path, date: str, failures: list[tuple[str, str, str]]) -> None:
    folder = root / date
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "daily-evidence.json").write_text(
        json.dumps(
            {
                "sources_checked": ["the-hacker-news", "cisa-advisories", "dark-reading"],
                "source_failures": [
                    {"source_key": key, "source_name": name, "error": error}
                    for key, name, error in failures
                ],
                "articles": [],
            }
        ),
        encoding="utf-8",
    )


CISA = ("cisa-advisories", "CISA Cybersecurity Advisories", "HTTP 403 Forbidden")
DARK = ("dark-reading", "Dark Reading", "The read operation timed out")


def test_a_streak_must_reach_the_newest_report(tmp_path: Path) -> None:
    """A source that recovered is working, and reporting it reports history.

    This is the whole reason the check reads backwards from today rather than
    counting failures in a window: two failures last week and a success since is
    a source that is fine.
    """
    root = tmp_path / "reports"
    _day(root, "2026-09-04", [CISA])
    _day(root, "2026-09-05", [CISA])
    _day(root, "2026-09-06", [])  # recovered
    _day(root, "2026-09-07", [DARK])

    streaks = source_streaks(root)

    assert [item.key for item in streaks] == ["dark-reading"]
    assert streaks[0].days == 1
    assert streaks[0].since == "2026-09-07"


def test_the_streak_stops_at_the_last_success(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    _day(root, "2026-09-04", [CISA])
    _day(root, "2026-09-05", [])  # the last day it worked
    _day(root, "2026-09-06", [CISA])
    _day(root, "2026-09-07", [CISA])

    streaks = source_streaks(root)

    assert streaks[0].days == 2
    assert streaks[0].dates == ("2026-09-07", "2026-09-06")
    assert streaks[0].since == "2026-09-06"


def test_the_reported_error_is_the_current_one(tmp_path: Path) -> None:
    """`since` already says when it started; the mail needs what is wrong now."""
    root = tmp_path / "reports"
    _day(root, "2026-09-06", [("cisa-advisories", "CISA", "HTTP 403 Forbidden")])
    _day(root, "2026-09-07", [("cisa-advisories", "CISA", "connect timeout")])

    assert source_streaks(root)[0].last_error == "connect timeout"


def test_a_day_that_cannot_be_read_is_not_a_silent_success(tmp_path: Path) -> None:
    """An unreadable day is a day we know nothing about.

    Treating it as a failure would invent a streak; treating it as a success
    would end a real one. It is left out, so the days either side of it are
    adjacent -- the streak it reports was observed on reports that exist.
    """
    root = tmp_path / "reports"
    _day(root, "2026-09-05", [CISA])
    _day(root, "2026-09-06", [CISA])
    (root / "2026-09-06" / "daily-evidence.json").write_text("{not json", encoding="utf-8")
    _day(root, "2026-09-07", [CISA])

    streaks = source_streaks(root)

    assert streaks[0].days == 2
    assert streaks[0].dates == ("2026-09-07", "2026-09-05")


def test_a_source_missing_from_a_days_failures_ends_the_streak(tmp_path: Path) -> None:
    """Dropped from the registry is not the same as failing.

    A source removed for a week and added back would otherwise show a streak
    spanning days on which it was never even attempted.
    """
    root = tmp_path / "reports"
    _day(root, "2026-09-05", [CISA])
    (root / "2026-09-06").mkdir(parents=True)
    (root / "2026-09-06" / "daily-evidence.json").write_text(
        json.dumps({"sources_checked": ["the-hacker-news"], "source_failures": []}),
        encoding="utf-8",
    )
    _day(root, "2026-09-07", [CISA])

    assert source_streaks(root)[0].days == 1


def test_notification_points_are_the_threshold_and_its_doublings() -> None:
    """Two mails for a four-day outage, five for a month -- not thirty.

    A daily mail about a state the operator already knows about is how the alert
    that matters becomes one more thing to filter.
    """
    due = [n for n in range(1, 40) if _is_notify_point(n)]

    assert due == [2, 4, 8, 16, 32]
    assert _is_notify_point(1) is False
    assert _is_notify_point(3) is False
    assert _is_notify_point(6) is False  # a multiple of the threshold, not a doubling


def test_nothing_is_sent_below_the_threshold(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    _day(root, "2026-09-07", [CISA])

    assert render_alert(source_streaks(root)) == ""


def test_the_alert_names_the_source_the_date_and_the_error(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    _day(root, "2026-09-06", [CISA])
    _day(root, "2026-09-07", [CISA, DARK])

    body = render_alert(source_streaks(root), hostname="wendy-lab")

    assert "CISA Cybersecurity Advisories (cisa-advisories)" in body
    assert "2 consecutive reports, since 2026-09-06" in body
    assert "HTTP 403 Forbidden" in body
    assert "wendy-lab" in body
    # The one-day failure rides along so the reader sees the whole picture.
    assert "dark-reading" in body.split("not yet at a reporting point:")[1]
    # Silence after a mail must not be read as recovery.
    assert "silence after this is not recovery" in body


def test_the_daily_summary_says_all_clear_when_nothing_failed(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    _day(root, "2026-09-07", [])

    assert "all" in render_summary(source_streaks(root))
    assert render_alert(source_streaks(root)) == ""


def test_an_empty_archive_is_not_an_error(tmp_path: Path) -> None:
    assert source_streaks(tmp_path / "nothing-here") == []
    assert render_alert([]) == ""


def test_threshold_is_two(tmp_path: Path) -> None:
    """Named so a change to it has to be deliberate: one day is a timeout."""
    assert FAILURE_STREAK_THRESHOLD == 2


def test_a_multiline_error_does_not_break_the_mail_body(tmp_path: Path) -> None:
    """httpx appends a documentation link on its own line."""
    root = tmp_path / "reports"
    noisy = "HTTP fetch failed: 403 Forbidden\nFor more information check: https://example.org"
    _day(root, "2026-09-06", [("cisa-advisories", "CISA", noisy)])
    _day(root, "2026-09-07", [("cisa-advisories", "CISA", noisy)])

    body = render_alert(source_streaks(root))

    assert "\n" not in body.split("last error: ")[1].split("\n")[0].strip()
    for line in body.splitlines():
        assert len(line) < 300
    assert "For more information check" in body
