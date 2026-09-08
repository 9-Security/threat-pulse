-- Applied to the production database on 2026-09-08.
--
-- Which rule held an indicator back from the block list, when one did. Without
-- it a consumer has to substring-match a Chinese reason string to tell a public
-- resolver from a registry boundary, which is what the reviewers asked us to
-- stop requiring.
--
-- Additive and nullable: rows written before this migration keep NULL, which
-- reads correctly as "no rule held this back".
ALTER TABLE indicators ADD COLUMN benign_basis TEXT;
