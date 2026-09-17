-- What the offline bundle carries and the hosted service did not: publication
-- dates, exclusions, CVE records with provenance, per-day source failures, and
-- the corpus_version the bundle would have.
--
-- Additive. Existing rows get NULLs until their day is re-pushed with the new
-- exporter; the service treats a missing corpus_state as "version unknown".
ALTER TABLE indicators ADD COLUMN published_at TEXT;
ALTER TABLE indicators ADD COLUMN registrable_lc TEXT;
CREATE INDEX IF NOT EXISTS idx_indicators_registrable ON indicators(registrable_lc);

ALTER TABLE reports ADD COLUMN sources_failed TEXT;

CREATE TABLE IF NOT EXISTS excluded_values (
    report_date    TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    value          TEXT NOT NULL,
    reason_codes   TEXT NOT NULL,
    value_lc TEXT GENERATED ALWAYS AS (lower(value)) VIRTUAL,
    PRIMARY KEY (report_date, value),
    FOREIGN KEY (report_date) REFERENCES reports(report_date) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_excluded_value_lc ON excluded_values(value_lc);

CREATE TABLE IF NOT EXISTS cve_intel (
    report_date TEXT NOT NULL,
    cve_id      TEXT NOT NULL,
    record      TEXT NOT NULL,
    PRIMARY KEY (cve_id, report_date),
    FOREIGN KEY (report_date) REFERENCES reports(report_date) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS corpus_state (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    corpus_version   TEXT NOT NULL,
    days             INTEGER NOT NULL,
    first_date       TEXT,
    last_date        TEXT,
    confirmed_values INTEGER NOT NULL,
    excluded_values  INTEGER NOT NULL,
    cve_records      INTEGER NOT NULL,
    publisher_count  INTEGER NOT NULL,
    psl_version      TEXT,
    computed_at      TEXT NOT NULL
);

INSERT OR REPLACE INTO schema_migrations (id, applied_at)
VALUES ('004-contract-data', datetime('now'));
