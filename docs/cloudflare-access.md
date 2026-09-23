# Cloudflare access and endpoints

Every credential this project uses on Cloudflare, what each one may do, where it
lives, and how to check it. Plus the addresses the service answers on.

**Status 2026-09-23:** three tokens, each checked by calling the API with it. See
[Current state](#current-state).

Two different things are called "token" here, and they are not related:

- **Cloudflare API tokens** administer the account: deploy the Worker, write to the
  database. Made in the Cloudflare dashboard.
- **Client tokens** let a consumer call the service. They are rows in the database,
  issued with `token-admin.mjs`, and are covered by [`token-runbook.md`](token-runbook.md).

---

## Cloudflare API tokens

| token | may | must not | lives on |
|---|---|---|---|
| **host (D1 only)** | read and write the database | deploy or read the Worker, read its secrets, read analytics, see zones | the collecting host, `/home/threatpulse/threat-pulse.env`, mode 0600 |
| **deploy (workstation)** | deploy the Worker, read its versions, secret names and analytics, query the database, start a live tail | — | the operator's workstation only, `deploy/worker/.env` |
| **another service's DNS/tunnel token** | whatever that service needs | **any Workers, D1 or Account Analytics permission** | not ours; it is the other service's |

The split exists because the collecting host is shared, and Cloudflare's Workers
permissions apply to a whole account rather than to one Worker: any token with
Workers Scripts on this account can replace this service with one that records what
callers send. So the shared host holds nothing but database access.

### Making the host token

Dashboard → My Profile → API Tokens → Create Token → Create Custom Token.

- Permissions: **Account · D1 · Edit**, and nothing else.
- Account Resources: Include · this account.
- Put it in `/home/threatpulse/threat-pulse.env` as `CLOUDFLARE_API_TOKEN`, keeping
  the file owned by `threatpulse` at mode 0600. Edit it with
  `ssh -t wendy-lab sudoedit /home/threatpulse/threat-pulse.env`, which preserves
  both and keeps the value off the command line.

### Making the deploy token

Same place, template **Edit Cloudflare Workers**, plus:

- **Account · D1 · Edit** — the schema, migrations and the token table;
- **Account · Account Analytics · Read** — CPU and request measurements.

Zone permissions are only needed to manage the custom domain from `wrangler.toml`.
The domain is attached already, so they can be left out; if they are kept, scope them
to `nine-security.com` alone.

Write it to `deploy/worker/.env` on the workstation:

```
CLOUDFLARE_API_TOKEN=...
CLOUDFLARE_ACCOUNT_ID=...
```

Both are required: without the account id, wrangler enumerates memberships, which a
narrow token cannot do, and fails with `Authentication error [code: 10000]`.

### Checking a token

```bash
# From the workstation, against deploy/worker/.env
node -e "
const env=Object.fromEntries(require('fs').readFileSync('.env','utf8').split(/\r?\n/).filter(l=>l.includes('=')).map(l=>[l.slice(0,l.indexOf('=')).trim(),l.slice(l.indexOf('=')+1).trim()]));
fetch('https://api.cloudflare.com/client/v4/user/tokens/verify',{headers:{authorization:'Bearer '+env.CLOUDFLARE_API_TOKEN}})
  .then(r=>r.json()).then(j=>console.log(j.success?j.result.status:j.errors));"
```

The host token is checked the same way through `systemd-run` with the service's
`EnvironmentFile`, so the value is never typed or printed.

**A token cannot read its own name.** Listing tokens needs *API Tokens · Read*, which
none of these has, and the verify endpoint returns only an id and a status. That id is
how a credential in a file is matched to a row in the dashboard: the dashboard's edit
URL ends with it. That is what showed, on 2026-09-23, that the host was still using the
shared token.

**Check what a token reaches, not what it was meant to reach.** Permissions in the
dashboard and a line in a document are both statements of intent; only a call says what
is true. Each of these should be run with the token in question:

```bash
# 403 expected for the host token; the deploy token gets 400, having the right
# and failing on the body
probe="https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/scripts/permission-probe-9f2a"
curl -s -o /dev/null -w '%{http_code}\n' -X PUT \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H 'content-type: application/javascript' --data '//probe' "$probe"
```

The PUT names a script that does not exist, so a token with the rights fails on the
body instead of replacing a live Worker. `GET .../workers/scripts` is not a usable
check on its own: a token with no Workers rights gets `200` and an empty list.

### Deleting one safely

A deleted token cannot be recovered, and the dashboard list is the only place its
name appears. Before deleting:

1. Write the value to a file the operator controls, so its removal can be proved
   afterwards rather than assumed.
2. Delete it in the dashboard.
3. Check that it now fails, then destroy the file.

This order was not followed on 2026-09-18: the copy was destroyed first, the wrong
token was then deleted, and neither fact was visible until the next command failed.

When the value cannot be copied because it was never held here, replace what uses it
first, prove the replacement works, and only then delete. That is how the shared token
was removed on 2026-09-23: a new host token, checked by call, a real push to D1, and
the old token deleted afterwards.

---

## Endpoints

| | |
|---|---|
| **service URL for consumers** | `https://threat-pulse.nine-security.com/mcp` |
| also answering | `https://soc-iocs-mcp.nine-security.workers.dev/mcp` — the platform address, kept while the pilot settles. Many SOC proxies block `*.workers.dev`, which is why the custom domain exists |
| health, no authentication | `GET /health` → `{"ok":true,"server":"iocs"}` |
| heartbeat probe, authenticated | `GET /heartbeat` reports the verdict; `POST /heartbeat` sends a labelled test mail to `ALERT_TO` |
| everything else | 404; `/mcp` accepts `POST` only |

The custom domain is attached to the Worker as a Cloudflare **Custom Domain**, not as
a route: Cloudflare created the DNS record and the certificate. It is not declared in
`wrangler.toml`, so a deploy neither needs zone permissions nor disturbs it.

### Worker configuration that matters here

| setting | value | why |
|---|---|---|
| `preview_urls` | `false` | every uploaded version otherwise keeps answering at its own URL, including versions from before the input guard |
| `[observability] enabled` | `true` | the heartbeat's own log lines |
| `invocation_logs` | `false` | per-request logs may carry the `Authorization` header |
| `triggers.crons` | `0 4 * * *` (12:00 Asia/Taipei) | the daily check that the corpus arrived, and the token usage report |

### Client tokens

Issued from the workstation with `node token-admin.mjs issue "<label>" …`. They are
database rows; only a SHA-256 is stored. Scopes are `read` and `context`, quotas
default to 60 calls per minute and 5,000 per UTC day, and handover goes over a
channel separate from the endpoint's. See [`token-runbook.md`](token-runbook.md).

---

## What the plan costs

The service runs on **Workers Free**, and stays there for the pilot: the operator
decided on 2026-09-18 that the measured CPU overrun does not justify the charge.

`enrich_observables` measured 34 ms CPU at p50 for a worst-case call and 7 ms for a
typical one, against Free's documented 10 ms per request. No call has been terminated,
which is an observation rather than a promise; the contract tells the consumer to treat
any platform error as every value unknown and retry.

| | Workers Free | Workers Paid |
|---|---|---|
| charge | none | **US$5 per month minimum for the account** |
| requests | 100,000 per day | 10 million per month included, then $0.30 per million |
| CPU | 10 ms per request | 30 million CPU-ms per month included, then $0.02 per million |
| D1 rows read | 5 million per day | 25 billion per month included, then $0.001 per million |
| D1 rows written | 100,000 per day | 50 million per month included, then $1.00 per million |
| D1 storage | 5 GB | 5 GB included, then $0.75 per GB-month |

At the pilot's own quota ceiling — 5,000 calls a day at about 50 ms each — Paid would
cost the **US$5 minimum**: roughly 7.5 million CPU-ms a month against 30 million
included, and 150,000 requests against 10 million. Passing that would take about
20,000 calls a day.

**Staying on Free** means the 10 ms CPU limit remains documented and exceeded, and
that the daily ceilings apply: 100,000 requests, 5 million database rows read and
100,000 written. The request ceiling is far away. Rows read per call has not been
measured yet, and should be before the pilot carries real volume.

---

## Current state

| | |
|---|---|
| host (D1 only) | **works, and is finally what this file says it is.** Replaced 2026-09-23, id `2748a5c9…`. Checked by call: deploy refused 403, the Worker's settings, secrets and versions refused 403, `workers/scripts` returns an empty list, D1 read and write succeed through the same wrangler path the daily push uses |
| deploy (workstation) | **works.** Recreated 2026-09-23, id `6d371de4…`; it deployed the Worker the same day |
| token shared until 2026-09-23 | **deleted 2026-09-23.** It had been the host's token the whole time: the replacement described for 2026-09-17 was never applied, and this file recorded it as done. Its value was never held here, so its removal is evidenced by the dashboard and by the host now using a different id |
| client tokens | one active: `mssp pilot`, issued 2026-09-18, expires 2026-12-31. Every other row is revoked |
