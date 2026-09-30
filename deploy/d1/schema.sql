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
    ingested_at         TEXT NOT NULL,
    -- JSON array of the source keys that failed that day. A value absent because
    -- its publisher could not be read is not the same as one nobody reported.
    sources_failed      TEXT
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
    -- Probability of exploitation in the next 30 days. KEV says "already"; CVSS
    -- says "how bad"; this is the one that orders a patch list of near-identical
    -- severities.
    epss_score      REAL,
    epss_percentile REAL,
    source          TEXT,
    article_title   TEXT,
    article_url     TEXT NOT NULL,
    section         TEXT,
    context         TEXT,
    -- Which rule held this back from the block list, when one did. Without it a
    -- consumer has to substring-match a Chinese reason string to tell a public
    -- resolver from a registry boundary.
    benign_basis    TEXT,
    -- The article's own publication date, as the publisher states it.
    published_at    TEXT,
    -- Registrable domain of a domain value (PSL), for finding values beneath a
    -- submitted domain without scanning. NULL for every other type.
    registrable_lc  TEXT,
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
CREATE INDEX IF NOT EXISTS idx_indicators_registrable
    ON indicators(registrable_lc);

-- Values the pipeline saw and ruled out, one row per value per day, with every
-- reason given that day. "We looked and ruled this out" is a different answer
-- from "we have never seen this".
CREATE TABLE IF NOT EXISTS excluded_values (
    report_date    TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    value          TEXT NOT NULL,
    reason_codes   TEXT NOT NULL,   -- JSON array
    value_lc TEXT GENERATED ALWAYS AS (lower(value)) VIRTUAL,
    PRIMARY KEY (report_date, value),
    FOREIGN KEY (report_date) REFERENCES reports(report_date) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_excluded_value_lc ON excluded_values(value_lc);

-- The day's KEV/CVSS/EPSS record per CVE, verbatim, with its provenance. The
-- newest day's record is the one served.
CREATE TABLE IF NOT EXISTS cve_intel (
    report_date TEXT NOT NULL,
    cve_id      TEXT NOT NULL,      -- upper case
    record      TEXT NOT NULL,      -- JSON object
    PRIMARY KEY (cve_id, report_date),
    FOREIGN KEY (report_date) REFERENCES reports(report_date) ON DELETE CASCADE
);

-- One row: the corpus_version an offline bundle built from the same report folder
-- would carry, and the days it covers. Written in the same batch as each day's
-- push. The service reports the version only while D1 holds exactly these days.
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
    call_count   INTEGER NOT NULL DEFAULT 0,
    -- Per-token quotas on tool calls. NULL means the Worker's default; 0 suspends
    -- the token without revoking it.
    rate_per_minute INTEGER,
    rate_per_day    INTEGER
);

-- Quota counters: one row per token per UTC minute (`m:YYYY-MM-DDTHH:MM`) or day
-- (`d:YYYY-MM-DD`). Token hash, time and counts only - never a submitted value.
-- Minute rows are dropped by the next daily check, day rows after 90 days.
CREATE TABLE IF NOT EXISTS token_usage (
    token_sha256 TEXT NOT NULL,
    bucket       TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    rejected     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_sha256, bucket)
);

-- The sample side of the corpus: what the malware analyser found inside a file.
--
-- Kept in its own tables rather than merged into `indicators`. "We hold this
-- file and our analysis found this value in it" and "a publisher wrote this
-- value down" are claims of different strength, and a caller must be able to
-- tell them apart. Measured on 2026-09-30, the two corpora share nothing: 1,242
-- news values against 8,141 analyser values matched 9 times, every one of them
-- noise (github.com, ipinfo.io, login.microsoftonline.com), and no hash matched
-- at all. Merging them would produce one undifferentiated list that is longer
-- and less precise.
--
-- Written by `soc-news-parser export-samples`, which reads the analyser's own
-- HTTP API. Values are normalised by the same code as the news side, so a
-- lookup cannot hit on one side and miss on the other. Existing databases get
-- these tables from deploy/d1/migrations/005-sample-corpus.sql.

CREATE TABLE IF NOT EXISTS sample_indicators (
    sha256          TEXT NOT NULL,
    indicator_type  TEXT NOT NULL,
    value           TEXT NOT NULL,
    confidence      INTEGER NOT NULL DEFAULT 0,
    -- Which integration extracted it. A C2 address from `config_extractor` and
    -- a hostname `strings` happened to find are not the same finding, and the
    -- answer says which one it was.
    integration     TEXT,
    tags            TEXT,
    first_seen_at   TEXT NOT NULL,
    -- Registrable domain, for finding values beneath a submitted domain without
    -- scanning; NULL for every type but `domain`, as on the news side.
    registrable_lc  TEXT,
    value_lc TEXT GENERATED ALWAYS AS (lower(value)) VIRTUAL,
    PRIMARY KEY (sha256, indicator_type, value)
);

CREATE INDEX IF NOT EXISTS idx_sample_indicators_value
    ON sample_indicators(value_lc);
CREATE INDEX IF NOT EXISTS idx_sample_indicators_registrable
    ON sample_indicators(registrable_lc);

-- One row per analysed sample: the hashes that let a caller arrive by md5 or
-- sha1 and leave with the sha256, and the analyser's own summary of the file.
CREATE TABLE IF NOT EXISTS sample_analysis (
    sha256            TEXT PRIMARY KEY,
    md5               TEXT,
    sha1              TEXT,
    size_bytes        INTEGER,
    file_type         TEXT,
    submitted_at      TEXT,
    finished_at       TEXT,
    verdict           TEXT,
    verdict_score     INTEGER,
    family            TEXT,
    family_confidence INTEGER,
    attack_techniques TEXT,
    ioc_total         INTEGER,
    -- The report stays readable after the sample blob is gone: retention only
    -- deletes the file on disk, never the analysis.
    report_url        TEXT NOT NULL,
    ingested_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sample_analysis_md5 ON sample_analysis(md5);
CREATE INDEX IF NOT EXISTS idx_sample_analysis_sha1 ON sample_analysis(sha1);
CREATE INDEX IF NOT EXISTS idx_sample_analysis_family ON sample_analysis(family);

-- Where the last export stopped. The analyser produces samples continuously
-- while the news side arrives once a day, so the sample side carries its own
-- freshness and the service reports both.
CREATE TABLE IF NOT EXISTS sample_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    exported_at       TEXT NOT NULL,
    high_water        TEXT,
    added_samples     INTEGER NOT NULL DEFAULT 0,
    added_indicators  INTEGER NOT NULL DEFAULT 0,
    analyzer          TEXT
);
