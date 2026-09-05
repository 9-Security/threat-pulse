-- Cloudflare D1 (SQLite) schema for the IoC MCP service.
--
-- What is deliberately absent: canonical_body. Article full text belongs to 26
-- publishers, several of whom restrict redistribution, and nothing the service
-- answers needs it. Indicator values are facts, the actions and reasons are our
-- own analysis, and KEV/NVD data is public domain. `context` is a verbatim
-- source sentence, so it is stored but only released to a token whose scope
-- allows it - see tokens.scopes.

CREATE TABLE IF NOT EXISTS reports (
    report_date         TEXT PRIMARY KEY,
    report_id           TEXT NOT NULL,
    subject             TEXT,
    window_start        TEXT,
    window_end          TEXT,
    generated_at        TEXT,
    article_count       INTEGER NOT NULL DEFAULT 0,
    confirmed_ioc_count INTEGER NOT NULL DEFAULT 0,
    patch_count         INTEGER NOT NULL DEFAULT 0,
    block_count         INTEGER NOT NULL DEFAULT 0,
    hunt_count          INTEGER NOT NULL DEFAULT 0,
    kev_count           INTEGER NOT NULL DEFAULT 0,
    unavailable_count   INTEGER NOT NULL DEFAULT 0,
    priority_line       TEXT,
    enrichment_json     TEXT,
    ingested_at         TEXT NOT NULL
);

-- One row per (day, indicator, article). The same value reported by two
-- articles keeps both rows, as the daily report does, so a reader can still see
-- every source that named it.
CREATE TABLE IF NOT EXISTS indicators (
    report_date     TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    value           TEXT NOT NULL,
    raw_value       TEXT,
    status          TEXT NOT NULL,
    action          TEXT,
    priority        TEXT,
    reason          TEXT,
    kev             INTEGER,
    kev_due_date    TEXT,
    cvss_score      REAL,
    cvss_severity   TEXT,
    source          TEXT,
    article_title   TEXT,
    article_url     TEXT NOT NULL,
    section         TEXT,
    context         TEXT,
    -- Lookups arrive lower-cased from a log. Comparing LOWER(value) would make
    -- SQLite ignore the index and scan the table, so the folded form is stored.
    value_lc TEXT GENERATED ALWAYS AS (lower(value)) VIRTUAL,
    PRIMARY KEY (report_date, indicator_type, value, article_url),
    FOREIGN KEY (report_date) REFERENCES reports(report_date) ON DELETE CASCADE
);

-- Exact lookup by value is the hot path: an agent pulls indicators out of a log
-- and asks about each one. Parent-host matching issues one lookup per label, so
-- it rides the same index.
CREATE INDEX IF NOT EXISTS idx_indicators_value
    ON indicators(value_lc);
CREATE INDEX IF NOT EXISTS idx_indicators_type_value
    ON indicators(indicator_type, value);
CREATE INDEX IF NOT EXISTS idx_indicators_action_date
    ON indicators(action, report_date);
CREATE INDEX IF NOT EXISTS idx_indicators_date
    ON indicators(report_date);

-- Bearer tokens, one row per client, so a leak revokes one caller rather than
-- everyone. Only the hash is stored; the token itself is shown once at issue.
CREATE TABLE IF NOT EXISTS tokens (
    token_sha256 TEXT PRIMARY KEY,
    label        TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT 'read',
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    revoked_at   TEXT,
    last_used_at TEXT,
    call_count   INTEGER NOT NULL DEFAULT 0
);
