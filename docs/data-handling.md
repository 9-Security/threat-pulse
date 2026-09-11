# Data handling for the IoC query service

**Status:** answers prerequisite 7 of the `enrich_observables` review
**Scope:** the query path — the Cloudflare Worker at `deploy/worker/` and the D1
database behind it. The daily collector and report email are a separate path and
are described at the end.
**Audience:** whoever has to sign off on sending observables to this service.

Claims below are marked **verified** where they were checked against the code
that runs, and **operational** where they are a commitment rather than something
the code enforces. One item is marked **to confirm** because it depends on an
account setting rather than this repository.

---

## Whether request values are logged

**Not by this service. Verified.**

The Worker contains no logging statement of any kind — there is no `console.*`
call in `deploy/worker/src/index.ts`. Nothing writes a submitted value to a log,
a table, or a file.

Cloudflare Workers Logs is enabled (`[observability] enabled = true` in
`wrangler.toml`). It captures invocation metadata and uncaught exceptions, not
request bodies. Observables travel in the body of `POST /mcp`, never in a URL or
query string, so they are outside what that captures.

One honest limit: the service's own error text does not interpolate submitted
values — the error strings are fixed (`"value is required"`,
`"values must be a non-empty array"`, `"unknown tool: …"`). An *unexpected*
runtime exception is returned as `tool <name> failed: <the exception's own
message>`, and that message is written by the runtime rather than by this
service. No case of a D1 error carrying a bound parameter has been observed, but
this is stated as a limit rather than claimed impossible.

## Log retention and deletion

**To confirm.** Workers Logs retention is a Cloudflare account and plan setting,
not something this repository configures. It governs invocation metadata and
exception text only; there are no request values in it to retain.

D1 holds no request values at all, so there is nothing to retain or delete
there. See the next section.

If the reviewing party would prefer no invocation logging at all, setting
`enabled = false` under `[observability]` removes it entirely, at the cost of
losing the ability to diagnose a fault after the fact.

## Data residency and subprocessors

**Subprocessor on the query path: Cloudflare, Inc.** — Workers for execution, D1
for storage. There is no other.

**Residency:** the D1 primary is in Cloudflare's APAC region; queries from Taiwan
are served by the Tokyo (NRT) colo. **No `location_hint` is configured**, so the
primary was selected by Cloudflare at database creation and is not pinned by
this repository. Reads may be served from other locations. If residency must be
guaranteed rather than observed, the database has to be recreated with an
explicit location hint — this is a real limitation, not a formality.

Email delivery of the daily report uses Resend, which is **not** on the query
path and never receives a submitted observable.

## Whether submitted values build or improve the corpus

**No. Verified, and structurally so.**

The only write statement in the entire Worker is a usage counter on the calling
token:

```sql
UPDATE tokens SET last_used_at = ?, call_count = call_count + 1
  WHERE token_sha256 = ?
```

Every other statement is a `SELECT`. Submitted values become bound parameters in
a comparison and are discarded when the response is returned. There is no code
path by which a queried value could reach the corpus, because there is no
insert to reach.

The corpus is built solely by the daily collector, from published vendor and
CERT reporting. Nothing a caller sends influences it.

## Authentication and tenant isolation

**Authentication.** A bearer token per client. Only its SHA-256 is stored; the
plaintext is displayed once at issue and cannot be recovered. Tokens carry
scopes (`read`, `context`) and are revoked individually, so a leak invalidates
one caller rather than all of them. `last_used_at` and `call_count` make an
unused or runaway token visible.

**Tenant isolation — stated plainly, because the honest answer is not "yes".**
There is no tenant partitioning: every valid token reads the same corpus. That
is deliberate. The corpus is published third-party reporting; it contains no
customer-specific data, so there is nothing belonging to one caller for another
to reach.

The isolation question that does matter is whether one caller's *queries* are
visible to another. They are not, because they are not stored — see the previous
section. What one token can learn about another is limited to nothing: token
rows are never read back through the API.

`context` — a verbatim source sentence, capped at 300 characters — is released
only to a token holding that scope. A `read`-only token receives every hit and
every citation link and follows it to the publisher.

## Maximum request and response sizes

| limit | value | constant |
|---|---|---|
| values per batch | 100 | `MAX_BATCH` |
| rows per response | 200 | `MAX_LIMIT` |
| rows by default | 40 | `DEFAULT_LIMIT` |
| `context` per row | 300 characters | export-time cap |

**A known gap:** values beyond 100 are currently dropped silently
(`.slice(0, MAX_BATCH)`). The specification promises a `truncated` field and a
`skipped` bucket so a caller can tell; the current implementation does neither.
This is listed as a prerequisite rather than described as working.

## URLs containing credentials, query strings, fragments, or tokens

**Today, a value is matched exactly as given.** The service lowercases it and
normalises defanging (`evil[.]com`, `hxxp://`); it does not strip anything else.
A URL submitted whole is used as a lookup key including its query string.

Because nothing is stored, a credential in a submitted URL is not retained — but
it does travel to Cloudflare in the request body, and that is avoidable at the
caller's end.

**Callers should strip credentials, query strings and fragments** unless exact
full-URL matching is genuinely required. The specification also calls for
private addresses and clearly internal hostnames to be returned in a `skipped`
bucket rather than searched, so an internal hostname never leaves the caller's
own inference — **that behaviour is specified and not yet implemented.**

Until it is, the recommendation stands as caller guidance rather than a
server-side guarantee, and it is described that way here on purpose.

---

## The collector and report path, for completeness

Separate from the query path, and it receives nothing from callers.

- The collector reads public RSS/Atom feeds and article pages over HTTPS,
  restricted to configured hosts and public IP addresses, with redirects
  re-validated and a 12 MiB decompressed ceiling.
- Full article bodies stay in the audit JSON on the collecting host. They are
  **never** uploaded to D1 — 26 publishers' text, several under redistribution
  terms, and no query needs it.
- Reports are emailed through Resend to `RESEND_TO`. Operational failure alerts
  go to `ALERT_TO`, a separate address, so report recipients receive no
  operational noise. Three conditions alert: the unit failing, the corpus not
  growing, and a source that has failed on every run for consecutive days. The
  last is reported at two days and at each doubling, because a source failing is
  not urgent — the report still goes out — but must not be able to stay broken
  silently, which it did for four days.
- Credentials live in an `EnvironmentFile` owned by the service account at mode
  `0600` and are never passed on a command line.

---

## Summary of what is not yet true

Listed together so none of it has to be inferred from the prose above.

| item | state |
|---|---|
| Workers Logs retention period | to confirm from the Cloudflare account |
| D1 residency pinned by configuration | no — observed APAC, not enforced |
| `truncated` / `skipped` reporting on over-limit batches | specified, not implemented |
| Server-side skipping of private IPs and internal hostnames | specified, not implemented |
| Tenant partitioning of the corpus | not present, and deliberately so |
