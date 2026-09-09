-- The ledger. Without it the only way to know whether a database has a given
-- migration is for someone to run a pragma query by hand and read it correctly,
-- which is the same manual-check dependency this directory exists to remove.
--
-- Safe to run repeatedly.
CREATE TABLE IF NOT EXISTS schema_migrations (
    id         TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- 001 was applied to production by hand on 2026-09-08, before this ledger
-- existed. Recording it here keeps that database's history honest rather than
-- leaving it looking unmigrated.
INSERT OR IGNORE INTO schema_migrations (id, applied_at)
SELECT '001-benign-basis', '2026-09-08T13:00:00+00:00'
WHERE EXISTS (
    SELECT 1 FROM pragma_table_info('indicators') WHERE name = 'benign_basis'
);
