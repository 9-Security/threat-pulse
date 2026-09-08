# D1 migrations

`schema.sql` uses `CREATE TABLE IF NOT EXISTS`, which does nothing to a table
that already exists. Adding a column to `schema.sql` therefore updates a fresh
database and silently skips every running one — and the next daily push, whose
`INSERT` now names the column, fails against the table that never got it.

That is not hypothetical: `benign_basis` was added to `schema.sql` and merged,
and the live database would have rejected the following morning's push. The
failure alert would have caught it, which is not the same as it not happening.

So every column added to `schema.sql` gets a numbered file here, applied once to
each existing database:

```bash
cd deploy/worker
set -a && . ./.env && set +a
npx wrangler d1 execute soc-iocs --remote --file ../d1/migrations/001-benign-basis.sql
```

Check before assuming a database is current:

```bash
npx wrangler d1 execute soc-iocs --remote \
  --command "SELECT name FROM pragma_table_info('indicators') ORDER BY cid;"
```

A fresh database created from `schema.sql` already contains everything here and
needs none of these files.
