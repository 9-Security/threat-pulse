# Data handling for the IoC query service

**Status:** answers prerequisite 7 of the `enrich_observables` review; revised
2026-09-14 for the three items the review listed as blockers for an endpoint pilot
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
`Authorization` header. On this plan logs are kept for 3 days, so any such entries
expire within 3 days of the change being deployed. The one client token in use should
be rotated after that.

Observables travel in the body of `POST /mcp`, never in a URL or query string.

A lookup whose database statement fails returns the fixed reason `lookup_failed`; the
database's message is neither returned nor logged. Other tools can still return an
unexpected runtime exception as `tool <name> failed: <message>`, written by the
runtime rather than by this service. No case of that message carrying a bound
parameter has been observed, and it is stated as a limit rather than claimed
impossible.

## Log retention and deletion

**Verified for this account.** Workers Logs keeps what it stores for **3 days** on the
Free plan (7 days on Paid). With invocation logs off, what it stores is the
heartbeat's console lines, which carry no request data. The Worker has no Logpush
export (`logpush: false` in its settings).

D1 holds no request values, so there is nothing to retain or delete there.

## Data residency and subprocessors

**Subprocessor on the query path: Cloudflare, Inc.** — Workers for execution, D1 for
storage. There is no other.

**Where a request is processed: not controllable on this account.** A Worker runs in
whichever Cloudflare data center receives the request. Restricting that to a region
is Cloudflare's Regional Services, an Enterprise add-on this account does not have. A
submitted value exists only in memory for the duration of the request; it is not
stored and, as above, not logged.

**Where the corpus is stored: observed, not enforced.** The D1 database runs in APAC
with read replication disabled, so there is a single copy. No stronger statement is
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

The only write statement in the entire Worker is a usage counter on the calling
token:

```sql
UPDATE tokens SET last_used_at = ?, call_count = call_count + 1
  WHERE token_sha256 = ?
```

Every other statement is a `SELECT`. Submitted values become bound parameters in a
comparison and are discarded when the response is returned. There is no code path by
which a queried value could reach the corpus, because there is no insert to reach.

The corpus is built solely by the daily collector, from published vendor and CERT
reporting. Nothing a caller sends influences it.

## Authentication and tenant isolation

**Authentication.** A bearer token per client. Only its SHA-256 is stored; the
plaintext is displayed once at issue and cannot be recovered. Tokens carry scopes
(`read`, `context`) and are revoked individually, so a leak invalidates one caller
rather than all of them. `last_used_at` and `call_count` make an unused or runaway
token visible.

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
| values per `lookup_iocs` call | 100 | values from position 100 on are returned in `skipped` with `request_limit`, and `truncated` is true |
| characters per value | 512 | skipped, `invalid_value` |
| dot-separated labels per value | 16 | skipped, `invalid_value` |
| request body | 256 KiB | HTTP 413; nothing is looked up |
| rows per search response | 200, default 40 | `truncated` is true |
| `context` per row | 300 characters | export-time cap |

**Verified by test.** The earlier gap — values past the 100th dropped with nothing to
say which — is closed. Every submitted value now comes back exactly once, in `items`,
`skipped` or `errors`, with its position.

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
| Whether pre-change invocation logs held the `Authorization` header | not established; they expire within 3 days of deployment, after which the client token is rotated |
| Defanged values and URL query strings on the hosted service | sent and matched as given, not normalised server-side |
| Per-token rate limiting | not implemented |
| CPU limit on a maximum-size batch | 10 ms on this plan; a full batch is not guaranteed to complete — see `query-service-limits.md` |
| Tenant partitioning of the corpus | not present, and deliberately so |

No longer in this table, as of this revision: reporting of `truncated` and `skipped`
on over-limit batches, and server-side skipping of private addresses and internal
hostnames. Both are implemented and tested.
