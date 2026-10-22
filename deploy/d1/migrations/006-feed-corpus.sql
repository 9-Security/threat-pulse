-- The feed side of the corpus: what abuse.ch lists as malicious infrastructure.
--
-- Its own tables, as the sample side has its own, because "a curated third-party
-- blocklist lists this" is a third kind of claim. It is current and specific to
-- infrastructure, and it carries none of the context an article gives. A caller
-- must be able to tell it from "a publisher wrote this down" and from "our
-- analyser found this inside a file".
--
-- Written by `soc-news-parser export-feeds`: ThreatFox get_iocs (7 days,
-- confidence >= 75, compromised legitimate sites dropped) and the Feodo Tracker
-- blocklist. ThreatFox rows expire 30 days after ThreatFox last saw them, so the
-- table holds about a month while each refresh writes only what changed.

CREATE TABLE IF NOT EXISTS feed_indicators (
    source          TEXT NOT NULL,          -- 'threatfox' | 'feodo'
    indicator_type  TEXT NOT NULL,          -- ip, domain, url, md5, sha1, sha256
    value           TEXT NOT NULL,
    -- botnet_cc, payload_delivery, payload, ...: a C2 server and a download
    -- location are different answers, and the caller is told which.
    threat_type     TEXT,
    malware         TEXT,
    confidence      INTEGER,                -- ThreatFox's own; NULL for Feodo
    port            INTEGER,
    first_seen      TEXT NOT NULL,          -- ISO 8601 UTC
    last_seen       TEXT,
    reference       TEXT,                   -- the entry on abuse.ch
    -- Registrable domain, for finding values beneath a submitted domain without
    -- scanning; NULL for every type but `domain`, as on the other two sides.
    registrable_lc  TEXT,
    value_lc TEXT GENERATED ALWAYS AS (lower(value)) VIRTUAL,
    PRIMARY KEY (source, indicator_type, value)
);

CREATE INDEX IF NOT EXISTS idx_feed_indicators_value
    ON feed_indicators(value_lc);
CREATE INDEX IF NOT EXISTS idx_feed_indicators_registrable
    ON feed_indicators(registrable_lc);
CREATE INDEX IF NOT EXISTS idx_feed_indicators_seen
    ON feed_indicators(source, last_seen, first_seen);

-- One row per source: when it was last read and whether that worked. A source
-- that failed keeps its previous rows; this row is how the service says so.
CREATE TABLE IF NOT EXISTS feed_state (
    source       TEXT PRIMARY KEY,
    exported_at  TEXT NOT NULL,
    ok           INTEGER NOT NULL,
    kept         INTEGER NOT NULL DEFAULT 0,   -- rows kept after filtering
    listed       INTEGER NOT NULL DEFAULT 0,   -- rows the source returned
    error        TEXT
);

INSERT OR REPLACE INTO schema_migrations (id, applied_at)
VALUES ('006-feed-corpus', datetime('now'));
