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


def test_benign_basis_reaches_the_database(tmp_path: Path) -> None:
    """The rule that held a value back has to survive the export.

    It was carried on the action and then dropped at the D1 boundary, so the
    consumer the field exists for could still only substring-match a Chinese
    reason string. Asserted through a real SQLite load of the shipped schema,
    because "the column is in the INSERT list" is what was true before and was
    not enough.
    """
    report = _report(
        [
            _article(
                "Mixed indicators listed",
                "Researchers listed the infrastructure.\n"
                "Indicators of Compromise\n"
                "8.8.8.8\n"
                "github.io\n"
                "evil-c2.com\n",
            )
        ]
    )
    sql = render_sql(json.loads(json.dumps(report.to_dict())), "2026-09-04")

    db = sqlite3.connect(":memory:")
    db.executescript(SCHEMA.read_text(encoding="utf-8"))
    db.executescript(sql)
    rows = dict(
        db.execute(
            "SELECT value, benign_basis FROM indicators WHERE indicator_type IN ('ip','domain')"
        ).fetchall()
    )

    assert rows["8.8.8.8"] == "public_resolver_registry"
    assert rows["github.io"] == "domain_boundary_rule"
    # A value that was never held back carries no basis, so a consumer reading
    # the field cannot mistake "blocked outright" for "demoted for some reason".
    assert rows["evil-c2.com"] is None


CONTRACT_BODY = """Indicators of Compromise
CVE-2026-1111
evil-c2-host[.]com    C2 server for the second-stage implant
login.a.b.evil.co.uk    phishing login page
10.0.0.5    internal staging host
192.168.1.9    the printer the operator used
"""


def _contract_payload(enricher=None) -> dict:
    report = _report([_article("Campaign drops a backdoor", CONTRACT_BODY)], enricher)
    return json.loads(json.dumps(report.to_dict()))


def test_publication_date_and_registrable_domain_travel() -> None:
    db = _load(render_sql(_contract_payload(), "2026-09-05"))
    rows = {
        value: (published, registrable)
        for value, published, registrable in db.execute(
            "SELECT value, published_at, registrable_lc FROM indicators"
        )
    }
    assert rows["evil-c2-host.com"] == ("2026-09-03T10:00:00+00:00", "evil-c2-host.com")
    assert rows["login.a.b.evil.co.uk"][1] == "evil.co.uk", "stops at the public suffix"
    cve = next(v for v in rows if v.upper() == "CVE-2026-1111")
    assert rows[cve] == ("2026-09-03T10:00:00+00:00", None), "only domains get a registrable key"


def test_exclusions_travel_with_their_reasons_and_are_repaired_on_re_push() -> None:
    payload = _contract_payload()
    sql = render_sql(payload, "2026-09-05")
    db = _load(sql)
    excluded = {
        value: json.loads(codes)
        for value, codes in db.execute("SELECT value, reason_codes FROM excluded_values")
    }
    assert "non_public_ip" in excluded["10.0.0.5"]
    assert "non_public_ip" in excluded["192.168.1.9"]
    confirmed = {row[0] for row in db.execute("SELECT value FROM indicators")}
    assert not set(excluded) & confirmed, "this fixture has no value both confirmed and excluded"

    db.executescript(sql)
    assert db.execute("SELECT COUNT(*) FROM excluded_values").fetchone()[0] == len(excluded)


def test_cve_records_travel_with_provenance_and_sources_failed_is_recorded() -> None:
    def enricher(manifests):
        return (
            {
                "CVE-2026-1111": CveIntel(
                    cve_id="CVE-2026-1111",
                    kev=True,
                    kev_due_date="2026-09-18",
                    cvss_score=9.8,
                    cvss_severity="CRITICAL",
                    sources=["https://www.cisa.gov/kev.json"],
                )
            },
            EnrichmentReport(enabled=True, kev_catalog_version="2026.09.04"),
        )

    payload = _contract_payload(enricher)
    payload["source_failures"] = [
        {"source_key": "recorded-future", "error": "timed out"},
        {"source_key": "recorded-future", "error": "timed out again"},
    ]
    db = _load(render_sql(payload, "2026-09-05"))

    cve_id, record = db.execute("SELECT cve_id, record FROM cve_intel").fetchone()
    record = json.loads(record)
    assert cve_id == "CVE-2026-1111"
    assert record["kev"] is True and record["cvss_score"] == 9.8
    assert record["sources"] == ["https://www.cisa.gov/kev.json"]
    assert json.loads(db.execute("SELECT sources_failed FROM reports").fetchone()[0]) == ["recorded-future"]


def _folder(root: Path, day: str, payload: dict) -> Path:
    folder = root / day
    folder.mkdir(parents=True)
    path = folder / "daily-evidence.json"
    path.write_text(json.dumps(payload), encoding="utf-8", newline="\n")
    return path


def test_corpus_state_is_the_offline_bundles_version(tmp_path: Path) -> None:
    from soc_news_parser.snapshot import build_snapshot

    root = tmp_path / "reports"
    path = _folder(root, "2026-09-05", _contract_payload())
    db = _load(export_report(path, corpus_state_from=root))

    snapshot = build_snapshot(root)
    state = db.execute(
        "SELECT corpus_version, days, first_date, last_date, confirmed_values, excluded_values FROM corpus_state"
    ).fetchone()
    assert state == (
        snapshot["corpus_version"],
        1,
        "2026-09-05",
        "2026-09-05",
        snapshot["corpus"]["confirmed_values"],
        snapshot["corpus"]["excluded_values"],
    )
    # What D1 holds is what the snapshot counted.
    assert db.execute("SELECT COUNT(DISTINCT value_lc) FROM indicators").fetchone()[0] == state[4]
    assert db.execute("SELECT COUNT(DISTINCT value_lc) FROM excluded_values").fetchone()[0] == state[5]


def test_corpus_state_refuses_a_folder_without_the_day(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    _folder(root, "2026-09-04", _contract_payload())
    elsewhere = _folder(tmp_path / "other", "2026-09-05", _contract_payload())
    with pytest.raises(ValueError, match="not a report day"):
        export_report(elsewhere, corpus_state_from=root)


def test_the_shipped_migration_matches_the_schema(tmp_path: Path) -> None:
    """A database built before 004 and migrated must accept the new push."""
    old = sqlite3.connect(":memory:")
    old.executescript(
        """
        CREATE TABLE schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE reports (report_date TEXT PRIMARY KEY, report_id TEXT NOT NULL, subject TEXT,
            window_start TEXT, window_end TEXT, generated_at TEXT,
            article_count INTEGER NOT NULL DEFAULT 0, confirmed_ioc_count INTEGER NOT NULL DEFAULT 0,
            patch_count INTEGER NOT NULL DEFAULT 0, block_count INTEGER NOT NULL DEFAULT 0,
            hunt_count INTEGER NOT NULL DEFAULT 0, kev_count INTEGER NOT NULL DEFAULT 0,
            unavailable_count INTEGER NOT NULL DEFAULT 0, priority_line TEXT, enrichment_json TEXT,
            ingested_at TEXT NOT NULL);
        CREATE TABLE indicators (report_date TEXT NOT NULL, indicator_type TEXT NOT NULL,
            value TEXT NOT NULL, raw_value TEXT, status TEXT NOT NULL, action TEXT, priority TEXT,
            reason TEXT, kev INTEGER, kev_due_date TEXT, cvss_score REAL, cvss_severity TEXT,
            source TEXT, article_title TEXT, article_url TEXT NOT NULL, section TEXT, context TEXT,
            value_lc TEXT GENERATED ALWAYS AS (lower(value)) VIRTUAL, benign_basis TEXT,
            epss_score REAL, epss_percentile REAL,
            PRIMARY KEY (report_date, indicator_type, value, article_url));
        """
    )
    old.executescript(Path("deploy/d1/migrations/004-contract-data.sql").read_text(encoding="utf-8"))
    old.executescript(render_sql(_contract_payload(), "2026-09-05"))
    assert old.execute("SELECT COUNT(*) FROM excluded_values").fetchone()[0] >= 2
    assert old.execute("SELECT id FROM schema_migrations").fetchone()[0] == "004-contract-data"
