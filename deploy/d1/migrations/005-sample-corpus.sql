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
-- lookup cannot hit on one side and miss on the other.

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

INSERT OR REPLACE INTO schema_migrations (id, applied_at)
VALUES ('005-sample-corpus', datetime('now'));
