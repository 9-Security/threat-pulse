import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc_news_parser.export_d1 import (
    MAX_STATEMENT_BYTES,
    export_report,
    render_sql,
    report_date_for,
)
from soc_news_parser.enrich import CveIntel, EnrichmentReport
from soc_news_parser.parser import ParsedArticle
from soc_news_parser.report import collect_report

SCHEMA = Path("deploy/d1/schema.sql")


def _article(title: str, body: str) -> ParsedArticle:
    return ParsedArticle(
        source="The Hacker News",
        title=title,
        url=f"https://example.test/{title.lower().replace(' ', '-')}",
        published_at="2026-09-03T10:00:00+00:00",
        body=body,
        extraction_method="feed:content",
        body_characters=len(body),
        warnings=[],
        publisher_hosts=("example.test",),
    )


def _report(articles: list[ParsedArticle], enricher=None):
    class Parser:
        def parse_feed(self, source: object, **_: object) -> list[ParsedArticle]:
            return articles if getattr(source, "name") == "The Hacker News" else []

    generated = datetime(2026, 9, 4, 22, 0, tzinfo=timezone.utc)
    return collect_report(
        Parser(),  # type: ignore[arg-type]
        ["the-hacker-news"],
        since=datetime(2026, 9, 3, 22, 0, tzinfo=timezone.utc),
        until=generated,
        generated_at=generated,
        enricher=enricher,
    )


def _load(sql: str) -> sqlite3.Connection:
    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA.read_text(encoding="utf-8"))
    db.executescript(sql)
    return db


BODY = """Indicators of Compromise
CVE-2026-1111
evil-c2-host[.]com    C2 server for the second-stage implant
2fd4e1c67a2d28fced849ee1bb76e7391b93eb12ae2214f6e04a0d8a5c3f8f21
"""


def test_export_carries_indicators_but_never_the_article_body() -> None:
    report = _report([_article("Campaign drops a backdoor", BODY)])
    payload = json.loads(json.dumps(report.to_dict()))
    sql = render_sql(payload, "2026-09-05", ingested_at="2026-09-05T00:00:00+00:00")

    body_line = "C2 server for the second-stage implant"
    assert "canonical_body" not in sql
    # The whole body must not travel; a short context citation may.
    assert BODY not in sql

    db = _load(sql)
    values = {row[0] for row in db.execute("SELECT value FROM indicators")}
    assert "cve-2026-1111".upper() in {v.upper() for v in values}
    assert "evil-c2-host.com" in values

    context = db.execute(
        "SELECT context FROM indicators WHERE value = 'evil-c2-host.com'"
    ).fetchone()[0]
    assert body_line in context


def test_the_report_row_records_the_board_counts() -> None:
    report = _report([_article("Campaign drops a backdoor", BODY)])
    payload = json.loads(json.dumps(report.to_dict()))
    db = _load(render_sql(payload, "2026-09-05"))

    row = db.execute(
        "SELECT article_count, block_count, patch_count, hunt_count FROM reports"
    ).fetchone()
    assert row == (
        report.article_count,
        report.analyst_brief.block_count,
        report.analyst_brief.patch_count,
        report.analyst_brief.hunt_count,
    )


def test_kev_and_cvss_travel_with_the_indicator() -> None:
    def enricher(manifests):
        return (
            {
                "CVE-2026-1111": CveIntel(
                    cve_id="CVE-2026-1111",
                    kev=True,
                    kev_due_date="2026-09-18",
                    cvss_score=9.8,
                    cvss_severity="CRITICAL",
                )
            },
            EnrichmentReport(enabled=True, kev_catalog_version="2026.09.04"),
        )

    report = _report([_article("Campaign drops a backdoor", BODY)], enricher)
    payload = json.loads(json.dumps(report.to_dict()))
    db = _load(render_sql(payload, "2026-09-05"))

    row = db.execute(
        "SELECT kev, kev_due_date, cvss_score, cvss_severity, action, priority"
        "  FROM indicators WHERE value = 'CVE-2026-1111'"
    ).fetchone()
    assert row == (1, "2026-09-18", 9.8, "CRITICAL", "patch", "high")


def test_re_pushing_a_day_repairs_it_rather_than_duplicating() -> None:
    report = _report([_article("Campaign drops a backdoor", BODY)])
    payload = json.loads(json.dumps(report.to_dict()))
    sql = render_sql(payload, "2026-09-05")

    db = _load(sql)
    first = db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    db.executescript(sql)
    assert db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == first

    # A day that loses an indicator must not keep the stale row.
    smaller = _report([_article("Campaign drops a backdoor", "Indicators of Compromise\nCVE-2026-1111\n")])
    db.executescript(render_sql(json.loads(json.dumps(smaller.to_dict())), "2026-09-05"))
    assert db.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] < first


def test_statements_stay_under_the_d1_size_limit() -> None:
    many = "Indicators of Compromise\n" + "".join(
        f"host-{index}[.]example[.]com    long descriptive column {'x' * 260}\n"
        for index in range(300)
    )
    report = _report([_article("Wide indicator table", many)])
    sql = render_sql(json.loads(json.dumps(report.to_dict())), "2026-09-05")

    statements = [s for s in sql.split(";") if s.strip() and not s.strip().startswith("--")]
    assert len(statements) > 2, "the fixture should need several batches"
    assert max(len(s) for s in statements) <= MAX_STATEMENT_BYTES
    assert "BEGIN TRANSACTION" not in sql  # D1 runs a file as one batch
    _load(sql)  # and it still loads


def test_the_date_key_follows_the_report_folder_not_utc() -> None:
    payload = {"window_end": "2026-09-04T22:00:00+00:00"}
    # 22:00Z is 06:00 the next day in Taipei, which is how folders are named.
    assert report_date_for(payload) == "2026-09-05"


def test_a_dated_folder_wins_over_any_derivation(tmp_path: Path) -> None:
    folder = tmp_path / "2026-08-30"
    folder.mkdir()
    path = folder / "daily-evidence.json"
    report = _report([_article("Campaign drops a backdoor", BODY)])
    path.write_text(json.dumps(report.to_dict()), encoding="utf-8", newline="\n")

    assert "'2026-08-30'" in export_report(path)


def test_a_report_json_that_is_not_an_object_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "daily-evidence.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="not an object"):
        export_report(path)
