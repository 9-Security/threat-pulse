-- EPSS: probability of exploitation in the next 30 days, and its percentile.
--
-- KEV answers "already exploited" and CVSS "how bad if it is"; neither orders a
-- patch list whose entries share a severity. On 2026-09-10, 68% of the 345
-- non-KEV CVEs shared a CVSS score with another -- 33 at 9.8, 47 at 8.8, 52 at
-- 7.8 -- leaving 132 of them sorted by CVE number.
--
-- Additive and nullable. NULL means EPSS has not scored that CVE, which is not
-- the same as a probability of zero, so nothing reads a missing value as low.
ALTER TABLE indicators ADD COLUMN epss_score REAL;
ALTER TABLE indicators ADD COLUMN epss_percentile REAL;

INSERT OR REPLACE INTO schema_migrations (id, applied_at)
VALUES ('002-epss', datetime('now'));
