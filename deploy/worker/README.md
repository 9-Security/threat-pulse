# IoC MCP service on Cloudflare Workers + D1

Serves the confirmed indicators from the daily SOC reports to external LLMs and
agents over MCP. D1 is SQLite, so this is the SQLite index the local file-based
MCP never had — cross-date lookup, parent-domain matching and batch queries all
become indexed reads instead of parsing every daily JSON.

There is no host to run. The daily GitHub Actions job pushes a day's indicators
in; the Worker only reads them.

## What travels, and what does not

`canonical_body` never leaves the audit JSON. It is 26 publishers' full article
text, several of them under redistribution terms, and no query needs it. What
does travel:

| kept | why it is safe to serve |
|---|---|
| indicator values | facts, not authorship |
| action, priority, reason | this project's own analysis |
| KEV, CVSS | CISA and NVD, public domain |
| article title and URL | a citation, and it sends traffic to the publisher |
| `context` | a verbatim source sentence, capped at 300 characters, and released only to a token holding the `context` scope |

A token with only `read` gets every hit and every citation, but no source
sentence — it can follow the link and read it at the publisher.

## Credentials

`wrangler login` requests fifteen OAuth scopes, including Pages, Queues and AI,
where this needs two. A scoped API token is both tighter and easier to hand to
CI. Create one under My Profile → API Tokens → Create Custom Token with:

| permission | why |
|---|---|
| Account → Workers Scripts → Edit | deploy the Worker |
| Account → D1 → Edit | push each day's indicators |
| Account → Account Settings → Read | resolve the account |

Keep it out of the repo and out of your shell history — `deploy/worker/.env` is
gitignored:

```bash
printf 'CLOUDFLARE_API_TOKEN=%s\n' "$TOKEN" > deploy/worker/.env
printf 'CLOUDFLARE_ACCOUNT_ID=%s\n' "$ACCOUNT_ID" >> deploy/worker/.env
```

`CLOUDFLARE_ACCOUNT_ID` is not optional: without it wrangler enumerates
`/memberships`, which a minimally scoped token cannot do, and `d1 create` fails
with `Authentication error [code: 10000]`.

## First deploy

```bash
cd deploy/worker
npm install
set -a && . ./.env && set +a
npx wrangler d1 create soc-iocs          # paste database_id into wrangler.toml
npm run schema                           # applies ../d1/schema.sql
npx wrangler deploy
```

Issue a token — only its SHA-256 is stored, so keep the value you generate:

```bash
TOKEN="$(openssl rand -hex 32)"
HASH="$(printf %s "$TOKEN" | sha256sum | cut -d' ' -f1)"
npx wrangler d1 execute soc-iocs --command \
  "INSERT INTO tokens (token_sha256, label, scopes, created_at)
   VALUES ('$HASH', 'analyst laptop', 'read context', '$(date -u +%FT%TZ)');"
echo "$TOKEN"   # shown once
```

Revoke one without touching the others:

```bash
npx wrangler d1 execute soc-iocs --command \
  "UPDATE tokens SET revoked_at = datetime('now') WHERE label = 'analyst laptop';"
```

## Pushing a day

```bash
uv run soc-news-parser export-d1 \
  --json-report reports/2026-09-05/daily-evidence.json \
  --output /tmp/2026-09-05.sql
npx wrangler d1 execute soc-iocs --remote --file /tmp/2026-09-05.sql
```

Re-pushing a day repairs it: the file deletes that day's rows first, so a
corrected report replaces the old one rather than doubling it.

## Client configuration

```json
{
  "mcpServers": {
    "iocs": {
      "url": "https://soc-iocs-mcp.<your-subdomain>.workers.dev/mcp",
      "headers": { "Authorization": "Bearer ${env:SOC_IOC_MCP_TOKEN}" }
    }
  }
}
```

## Tools

| tool | what it answers |
|---|---|
| `list_reports` | which days are loaded, with their counts |
| `get_report_summary` | one day's subject, window, priority line, counts |
| `search_confirmed_iocs` | text/action/type search across every day |
| `lookup_ioc` | one value across every day, parent domains included |
| `lookup_iocs` | up to 100 values at once — the ones pulled out of a log |

`lookup_iocs` is the one built for log triage. For each value it returns
`matched_on`, `exact`, `first_seen`, `last_seen` and `seen_on`, so an agent can
say "the parent domain of this host has been on the block list since 2026-09-04"
rather than implying an exact hit it did not get.

## Local development

No Cloudflare account needed:

```bash
npm run schema:local
npx wrangler d1 execute soc-iocs --local --file /tmp/2026-09-05.sql
npx wrangler dev --local
```

Seed a local token the same way, with `--local` added.
