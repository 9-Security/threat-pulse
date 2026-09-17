-- Per-token quotas on tool calls, and the counters that enforce them.
--
-- The MSSP asked for per-minute and per-day quotas before a hosted pilot. They are
-- enforced by the Worker with one conditional upsert per bucket, so a counter
-- never passes its limit. NULL limits mean the Worker's defaults; 0 suspends a
-- token without revoking it.
--
-- The counters hold a token hash, a UTC time bucket and two integers. No
-- submitted value is ever written here.
ALTER TABLE tokens ADD COLUMN rate_per_minute INTEGER;
ALTER TABLE tokens ADD COLUMN rate_per_day INTEGER;

CREATE TABLE IF NOT EXISTS token_usage (
    token_sha256 TEXT NOT NULL,
    bucket       TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    rejected     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (token_sha256, bucket)
);

INSERT OR REPLACE INTO schema_migrations (id, applied_at)
VALUES ('003-token-quotas', datetime('now'));
