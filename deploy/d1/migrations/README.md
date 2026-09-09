# D1 migrations

`schema.sql` uses `CREATE TABLE IF NOT EXISTS`, which does nothing to a table
that already exists. Adding a column to `schema.sql` therefore updates a fresh
database and silently skips every running one — and the next daily push, whose
`INSERT` now names the column, fails against the table that never got it.

That is not hypothetical: `benign_basis` was added to `schema.sql` and merged,
and the live database would have rejected the following morning's push. The
failure alert would have caught it, which is not the same as it not happening.

## Applying

Each database records what it has applied, so this does not depend on anyone
remembering. `000-migrations-table.sql` creates the ledger and is safe to run on
a database that already has it.

```bash
cd deploy/worker
set -a && . ./.env && set +a

# Once per database.
npx wrangler d1 execute soc-iocs --remote --file ../d1/migrations/000-migrations-table.sql

# What this database has already applied.
npx wrangler d1 execute soc-iocs --remote \
  --command "SELECT id, applied_at FROM schema_migrations ORDER BY id;"
```

Then, for each file not listed, apply it and record it in the same batch — D1
runs a file as one statement batch, so the two cannot come apart:

```bash
npx wrangler d1 execute soc-iocs --remote --file ../d1/migrations/001-benign-basis.sql
```

SQLite has no `ADD COLUMN IF NOT EXISTS`, so re-running a migration fails with
`duplicate column name`. That error is the ledger doing its job by other means,
but check the table first rather than relying on it.

## After a migration that adds a served field

**Redeploy the Worker.** A column the daily push writes is not a field the MCP
response carries until the Worker that projects it is deployed:

```bash
npx wrangler deploy
```

`001` is the case that showed this up: applying it alone leaves `benign_basis`
written to every row and absent from every response.

## Column order differs between a fresh and a migrated database

`ALTER TABLE ADD COLUMN` appends, while `schema.sql` lists the column where it
belongs logically. So `pragma_table_info` returns:

```
fresh    ... section, context, benign_basis, value_lc
migrated ... section, context, value_lc, benign_basis
```

Cosmetic — every `INSERT` names its columns and every read is keyed by name —
but worth knowing before concluding a migration did not land.
