# Data handling for the IoC query service

**Status:** answers prerequisite 7 of the `enrich_observables` review; revised
2026-09-14 for the three items the review listed as blockers for an endpoint pilot,
and 2026-09-17 for what Cloudflare records, who can reach it, and where it runs
**Scope:** the query path — the Cloudflare Worker at `deploy/worker/` and the D1
database behind it. The daily collector and report email are a separate path and
are described at the end.
**Audience:** whoever has to sign off on sending observables to this service.

Claims below are marked **verified** where they were checked against the code that
runs or the account it runs on, **operational** where they are a commitment rather
than something the code enforces, and **not controllable** where this account cannot
enforce them. Limits, timeouts and error rules are in
[`query-service-limits.md`](query-service-limits.md).

The service runs on a Cloudflare **Workers Free** account. Where a statement depends
on the plan, it is stated for that plan.

---

## Whether request values are logged

**Not by this service. Verified.**

The query path contains no logging statement. The only `console` output in the Worker
comes from the daily heartbeat check and its test endpoint, and neither includes a
submitted value: they record the newest report date and, for a test send, the calling
token's label. Nothing writes a submitted value to a log, a table or a file.

**Per-request invocation logs are disabled** (`invocation_logs = false` under
`[observability.logs]` in `wrangler.toml`). Cloudflare describes invocation logs as
recording "the Request, Response, and related metadata" without saying which request
headers that includes, so a Bearer token may have been among them. Rather than depend
on an unverified reading of what was captured, they are off.

**Not established:** whether invocation logs written before that change held the
`Authorization` header. On this plan logs are kept for 3 days. The question no longer
reaches a working credential:

- the one client token was last used on 2026-09-05, so any entry carrying it expired
  by 2026-09-08; it was revoked on 2026-09-17;
- every token issued since for a check was revoked within a minute of being created.

No client token is active now. One is issued per client when that client needs it, so
a leak revokes one caller.

Observables travel in the body of `POST /mcp`, never in a URL or query string.

A lookup whose database statement fails returns the fixed reason `lookup_failed`; the
database's message is neither returned nor logged. Other tools can still return an
unexpected runtime exception as `tool <name> failed: <message>`, written by the
runtime rather than by this service. No case of that message carrying a bound
parameter has been observed, and it is stated as a limit rather than claimed
impossible.

## What Cloudflare records about a request, and for how long

Every place a request could leave a trace, checked on 2026-09-17:

| record | what it holds | kept | how this is known |
|---|---|---|---|
| Workers invocation logs | "the Request, Response, and related metadata" | **not recorded** — disabled | `invocation_logs = false`; the setting was read back from the API after deploying |
| Workers Logs, console output | the heartbeat's lines: the newest report date, and a test send's token label | 3 days on Free, 7 on Paid | the Worker has no other `console` call |
| Real-time logs (`wrangler tail`) | streamed live to whoever starts one. Cloudflare's example event shows the request URL, method, headers and Cloudflare metadata; the body, where observables travel, is not among them | **not stored** — "Real-time logs does not store Workers Logs" | Cloudflare's documentation. It does not say whether the `Authorization` header is redacted, so a live tail should be assumed to show it |
| Worker analytics | per time bucket: data center, status, script version, request count, CPU and duration | up to 90 days back | the dataset's schema, read through the API: it has **no field** for an IP address, URL, header or body |
| D1 query insights | statement text, duration, serving region, error text. Cloudflare: "Bound parameters are not captured" | up to 90 days back (Cloudflare's D1 page says 31; this account's analytics settings allow 90) | the recorded statements themselves — see below |
| `tokens` table in D1 | per client token: `last_used_at`, `call_count` | until the row is deleted | the code |
| `token_usage` table in D1 | per client token and UTC minute or day: calls counted and calls refused by quota | minute rows until the next daily check; day rows 90 days | the code |
| Log export (Logpush) | — | none configured | Worker setting `logpush: false` |

**D1 query insights, checked against what they actually hold.** Over the seven days
before 2026-09-17, the service's lookup statement was recorded in 6 shapes across 189
executions. Every one was `SELECT * FROM indicators WHERE value_lc IN (?,?,…)`, with
placeholders only and no quoted literal. Over 30 days, no statement recorded an error
string. Submitted values reach D1 only as bound parameters, so they are not in these
records.

The one kind of literal these records do hold is a token's SHA-256, in statements run
by hand to issue or revoke a token. That hash cannot be used to authenticate: the
service hashes whatever it is given, and the token itself is 256 random bits. Tokens
issued for checks since 2026-09-17 are passed as bound parameters, so their hash
does not appear either.

D1 holds no request values, so there is nothing of a caller's to retain or delete
there.

## Who can read those records, or change what is recorded

The question that matters is wider than who can *read* the records above. Anyone who
can **deploy the Worker** can deploy a version that records request bodies. So both
sets of people are listed here, and as of 2026-09-17 they are the same.

| holder | what it can do | how this is known |
|---|---|---|
| Cloudflare account members | **one** member, with the Super Administrator role: the operator | members API |
| Deploy token | deploy the Worker; read its secret names, versions and analytics; query D1. It should be assumed able to start a live tail as well | kept **only on the operator's workstation**. Each listed capability was exercised on 2026-09-17, including a real deploy; the live tail was not tried |
| Collecting-host token | read and write D1, and nothing else | on the collecting host. Each of these was refused with 403 or "authorization denied": listing Worker scripts, reading the Worker's settings, secrets or versions, listing account members, seeing zones, reading analytics |
| Earlier shared token | at least everything the deploy token can do | **still held on the collecting host** by another service there, which uses it only for DNS and tunnel management. That service is to get its own token without Workers or D1 permissions; the shared token is then deleted. Until then it still authenticates: checked on 2026-09-17 |
| Other API tokens on the account | not listable by either token above | to be confirmed by the account owner |
| Cloudflare personnel | governed by Cloudflare's terms | no statement is made here |

**Why there are two tokens.** Until 2026-09-17 one token did both jobs, and it was
stored on the collecting host. That host is shared, and two accounts on it have
root-equivalent access: the operator's and another service's. Either could have
read that token, and it could redeploy the Worker. This service now keeps a token
limited to D1 on that host, and its deploy token elsewhere.

**The split is not finished.** The earlier token was also used by that other service,
for DNS and tunnel management, and that service still holds it on the same host. The
two services share a Cloudflare account, and Cloudflare's Workers permissions apply to
the whole account, not to one Worker. So separating them requires that the other
service's own token carry no Workers or D1 permission at all, and that the shared
token be deleted. Until both are done, a token able to redeploy this service remains
on the collecting host.

**What the collecting-host token still allows,** stated because the host is shared:

- **Changing the corpus.** A compromised host already controls what the collector
  writes, so this adds nothing new.
- **Issuing itself a client token**, since tokens are rows in D1. Such a token reads the
  same corpus every client reads. It sees nothing of other callers: their queries are
  not stored anywhere.
- **Revoking or altering another client's token row**: an availability risk, not a
  confidentiality one.
- **Nothing that observes lookups.** A lookup's only writes are its token's usage
  counters, and they carry no submitted value. SQLite triggers fire only on
  `INSERT`, `UPDATE` and `DELETE`, never on a read, so a trigger planted in the
  database could see the counter but never a looked-up value. Query insights and
  analytics are refused to this token.

## Data residency and subprocessors

**Subprocessor on the query path: Cloudflare, Inc.** — Workers for execution, D1 for
storage. There is no other.

**Where a request is processed: not controllable on this account.** A Worker runs in
whichever Cloudflare data center receives the request. Restricting that to a region
is Cloudflare's Regional Services, an Enterprise add-on this account does not have. A
submitted value exists only in memory for the duration of the request; it is not
stored and, as above, not logged.

Observed, not guaranteed: in the 30 days before 2026-09-17, requests to this Worker
were processed in nine data centers. By request count, the largest were Kaohsiung,
Hong Kong and Taipei; the rest were Tokyo, Osaka, Dallas, Seattle, San Jose and
Portland. That figure mixes the daily scheduled check, which runs wherever Cloudflare
places it, with test calls. Which data center a given caller reaches depends on that
caller's network, and nothing here pins it.

**Where the corpus is stored: observed, not enforced.** The D1 database runs in APAC
with read replication disabled, so there is a single copy. Query insights agree: all
381 statements in the 30 days before 2026-09-17 were served by the primary, in APAC. No stronger statement is
available: a D1 location hint is best-effort by Cloudflare's own description, the
jurisdictions D1 offers are the EU and FedRAMP with none for APAC, and a jurisdiction
cannot be added to a database after it is created. The corpus is derived from
published reporting and contains no customer data.

**Where residency has to be guaranteed**, the offline validation bundle already does
it: the corpus travels to the consumer and submitted values never leave their network.

Email delivery of the daily report uses Resend, which is **not** on the query path and
never receives a submitted observable.

## Whether submitted values build or improve the corpus

**No. Verified, and structurally so.**

The Worker writes only usage counters for the calling token, and a daily cleanup of
those counters:

```sql
UPDATE tokens SET last_used_at = ?, call_count = call_count + 1
  WHERE token_sha256 = ?

-- quotas: one row per token per UTC minute or day
INSERT INTO token_usage (token_sha256, bucket, count) VALUES (?, ?, 1)
  ON CONFLICT (token_sha256, bucket) DO UPDATE SET count = count + 1 WHERE count < ?
  RETURNING count
INSERT INTO token_usage (token_sha256, bucket, count, rejected) VALUES (?, ?, 0, 1)
  ON CONFLICT (token_sha256, bucket) DO UPDATE SET rejected = rejected + 1

DELETE FROM token_usage WHERE (bucket LIKE 'm:%' AND bucket < ?) OR (bucket LIKE 'd:%' AND bucket < ?)
```

Every bound parameter in these is a token hash, a time window, a limit or a count. No
submitted value is among them. Every other statement is a `SELECT`: submitted values
become bound parameters in a comparison and are discarded when the response is
returned. There is no code path by which a queried value could reach the corpus or any
other table, because no write takes one.

The corpus is built solely by the daily collector, from published vendor and CERT
reporting. Nothing a caller sends influences it.

## Authentication and tenant isolation

**Authentication.** A bearer token per client. Only its SHA-256 is stored; the
plaintext is displayed once at issue and cannot be recovered. Tokens carry scopes
(`read`, `context`) and are revoked individually, so a leak invalidates one caller
rather than all of them. `last_used_at` and `call_count` make an unused or runaway
token visible.

**Quotas.** Each token has a per-minute and a per-day ceiling on tool calls, 60 and
5,000 unless set otherwise, enforced before anything is looked up. A daily check
mails the operator about any refused call or any token near its daily ceiling. See
`query-service-limits.md` and `token-runbook.md`.

**Tenant isolation — stated plainly, because the honest answer is not "yes".** There
is no tenant partitioning: every valid token reads the same corpus. That is
deliberate. The corpus is published third-party reporting; it contains no
customer-specific data, so there is nothing belonging to one caller for another to
reach.

The isolation question that does matter is whether one caller's *queries* are visible
to another. They are not, because they are not stored — see the sections above. What
one token can learn about another is limited to nothing: token rows are never read
back through the API.

`context` — a verbatim source sentence, capped at 300 characters — is released only to
a token holding that scope. A `read`-only token receives every hit and every citation
link and follows it to the publisher.

## Maximum request and response sizes

| limit | value | when exceeded |
|---|---|---|
| values per `lookup_iocs` call | 100 | values from position 100 on are returned in `skipped` with `request_limit`; `truncated` is true and `status` is `partial` |
| characters per value | 512 | skipped, `invalid_value` |
| dot-separated labels per value | 16 | skipped, `invalid_value` |
| request body | 256 KiB | HTTP 413; nothing is looked up |
| rows per search response | 200, default 40 | `truncated` is true and `status` is `partial` |
| `context` per row | 300 characters | export-time cap |

**Verified by test.** The earlier gap — values past the 100th dropped with nothing to
say which — is closed. Every submitted value now comes back exactly once, in `items`,
`skipped` or `errors`, with its position, and a response that dropped any value is
never `complete`.

## Values the service will not look up

**Skipped before any database statement is built. Verified by test.**

- addresses that are not globally reachable — private, loopback, link-local, shared,
  documentation, reserved, unique-local and the like — reason `non_public_ip`;
- internal hostnames — single-label names and names under `.local`, `.internal`,
  `.corp`, `.lan`, `.home.arpa`, `.localdomain` or `.intranet` — reason
  `internal_hostname`;
- URLs carrying a username or password — reason `sensitive_url`.

A test composes the input guard with the lookup against a fake database and asserts
that none of these reaches a statement. The first two use the same classification and
the same reason codes as the offline validator. Free-text search refuses a query that
is plainly one of these, but not a single word: `ransomware` and `dc01` are searched,
`dc01.corp` is refused.

**Still sent as given:** a URL's query string and fragment are not stripped, and
defanged values such as `evil[.]com` are not restored — the hosted service matches the
value it receives, lowercased. Callers should send real values and strip query strings
and fragments unless exact full-URL matching is needed. The offline validator, by
contrast, does restore defanged values.

---

## The collector and report path, for completeness

Separate from the query path, and it receives nothing from callers.

- The collector reads public RSS/Atom feeds and article pages over HTTPS, restricted
  to configured hosts and public IP addresses, with redirects re-validated and a
  12 MiB decompressed ceiling.
- Full article bodies stay in the audit JSON on the collecting host. They are
  **never** uploaded to D1 — 26 publishers' text, several under redistribution terms,
  and no query needs it.
- Reports are emailed through Resend to `RESEND_TO`. Operational failure alerts go to
  `ALERT_TO`, a separate address, so report recipients receive no operational noise.
  Three conditions alert from the collecting host: the unit failing, the corpus not
  growing, and a source that has failed on every run for consecutive days. A fourth
  runs on Cloudflare and alerts when the day's report has not arrived, because the
  first three need the host alive to send them.
- Credentials live in an `EnvironmentFile` owned by the service account at mode
  `0600` and are never passed on a command line.

---

## Summary of what is not yet true

Listed together so none of it has to be inferred from the prose above.

| item | state |
|---|---|
| Region where a request is processed | **not controllable** on this account; an Enterprise add-on |
| D1 location pinned by configuration | **not possible** — location hints are best-effort, there is no APAC jurisdiction, and one cannot be added after creation; observed APAC, single copy |
| Defanged values and URL query strings on the hosted service | sent and matched as given, not normalised server-side |
| Deletion of the token shared until 2026-09-17 | **not done** — this service no longer uses it, but another service on the collecting host still does, for DNS and tunnel management. That service is to move to a token without Workers or D1 permissions, then the shared token is deleted. Until then, a token able to redeploy this service remains on that host |
| List of every API token on the account | not visible to either token in use; the account owner confirms |
| Whether a live tail shows the `Authorization` header | not documented by Cloudflare; assume it does. The account member and the deploy token can start one, and so can the shared token until it is deleted |
| CPU limit on a maximum-size batch | 10 ms documented on this plan; a maximum-size batch measured 13.9 ms p50 / 23.2 ms p99 and completed in all 13 attempts, so the limit is not an observed cutoff — but it is not guaranteed either. See `query-service-limits.md` |
| Tenant partitioning of the corpus | not present, and deliberately so |

No longer in this table: reporting of `truncated` and `skipped` on over-limit
batches, server-side skipping of private addresses and internal hostnames, and
per-token quotas, all implemented and tested; and whether pre-change invocation logs held the
`Authorization` header, which is still not established but no longer matters,
because every token that could appear in them is revoked.
