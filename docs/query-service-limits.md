# Query service: limits, timeouts, errors and partial responses

**Applies to:** the hosted MCP query service in `deploy/worker/` — `lookup_iocs`,
`lookup_ioc` and `search_confirmed_iocs`.
**Implemented in:** `deploy/worker/src/guard.ts` (what may be looked up),
`deploy/worker/src/lookup.ts` (what a lookup returns), both tested under node with
`npm test`.
**`enrich_observables`** follows the same rules. Its final request and response
schema, and its own statement budget and measurements, are in
[`enrich-observables-contract.md`](enrich-observables-contract.md).

Every number here is either a constant in the code or a limit of the Cloudflare
account the service runs on, which is on the **Workers Free** plan. Where a rule
depends on the plan, it is stated for that plan.

---

## The rule everything else follows from

**Every submitted value comes back exactly once**, in `items`, `skipped` or `errors`,
carrying its `input_index`. Nothing is dropped, and three things are never confused:

| bucket | means | is it a "not found"? |
|---|---|---|
| `items` with `found: false` | every candidate for the value was queried and none matched | **yes** — and only this |
| `skipped` | the value was not looked up, for the stated reason | **no** |
| `errors` | a lookup for the value was attempted and did not complete | **no** |

A value becomes an item only if *every* candidate it expands to was queried. If the
statement for its most specific candidate failed while a less specific one
succeeded, it is an error — answering from the weaker candidate would return the
wrong match as if it were the right one.

## Limits

### Platform limits of this account

| limit | Workers Free |
|---|---|
| CPU time per request | 10 ms documented; measured behaviour below |
| D1 statements per invocation | 50 |
| D1 statement duration | 30 s |
| D1 bound parameters per statement | 100 |
| Workers Logs retention | 3 days |

### Service limits

| limit | value | when exceeded |
|---|---|---|
| values per `lookup_iocs` call | **100** | values at position 100 and later are returned in `skipped` with `request_limit`; `truncated` is true and `status` is `partial` |
| characters per value | **512** | skipped, `invalid_value` |
| dot-separated labels per value | **16** | skipped, `invalid_value` |
| request body | **256 KiB** | HTTP 413, JSON-RPC `-32600`; nothing is looked up |
| candidates per D1 statement | 90 | internal; leaves room for the date bound |
| D1 statements per call | `lookup_iocs` at most **21** of the 50; `enrich_observables` at most **33** | `lookup_iocs`: 2 for authentication, 2 for the quota counters, at most 17 lookups (100 values × 15 parent candidates ÷ 90). `enrich_observables`: see [its contract](enrich-observables-contract.md#limits-and-performance) |
| wall-clock budget per lookup call | **10 s** | values whose statements were not yet sent are returned in `errors` with `time_budget_exceeded` |
| rows per search | default 40, max **200** | `truncated` is true and `status` is `partial` when more rows matched than were returned |
| tool calls per token, per UTC minute | **60** by default, set per token | HTTP 429; nothing is looked up — see [Quotas](#quotas) |
| tool calls per token, per UTC day | **5,000** by default, set per token | HTTP 429 until 00:00 UTC |

The label limit exists because of the statement limit. Each label of a hostname is a
parent candidate, and without a bound one value of a few hundred labels would expand
into enough statements to exhaust the call for every other value in it. It counts the
whole value rather than only the host of a URL, because a value is expanded as
submitted: a short host followed by a dotted path would otherwise pass a host-only
count and expand anyway.

### CPU time: the one limit that cannot become a partial response

CPU is the one limit this service cannot turn into a `partial` response. If the
platform ends a request for using too much CPU, the caller gets a Cloudflare error
instead of a JSON-RPC response: no `status`, no `errors`, and no way to tell which
values were looked up.

Measured 2026-09-14 against the deployed service (version `d0068328`), as timed
groups of requests read back from Cloudflare's request analytics:

| request | CPU p50 | CPU p90–p99 | wall time | response |
|---|---|---|---|---|
| 100 values × 16 labels — the worst case, 17 D1 statements | 13.9 ms | 23.2 ms | 1.0–1.4 s | 35 KB |
| 6 mixed values | 2.4 ms | 4.5 ms | — | — |
| 300 KB body rejected with 413 | 3.6 ms | 5.9 ms | — | — |

All 13 worst-case requests returned a normal response; none was terminated. Only that
worst-case batch goes over 10 ms at all, and a typical batch stays several times
inside it.

An earlier revision of this page said a request over 10 ms "is terminated by the
platform". That was written from the documented limit rather than from a measurement,
and the measurement contradicts it. What remains true is that 10 ms is the documented
limit and exceeding it is not something a caller can rely on: these numbers describe
what was observed on one day, not a guarantee.

**What a caller should do:** treat a platform error or a timeout as *every value in
the call unknown* — never as misses — and retry with a smaller batch.

**Before an endpoint pilot** the account is to be moved to Workers Paid, where CPU
per request defaults to 30 s and D1 allows 1000 statements per invocation. This page
will carry the numbers of whichever plan is in effect when the endpoint is used.

### `enrich_observables`

The contract tool uses more CPU than `lookup_iocs`. Measured on 2026-09-18:

- **worst case** (100 URLs with 16-label hosts): p50 34 ms, p90 56 ms;
- **six typical values**: p50 7 ms, p90 14 ms.

Both are over this plan's documented 10 ms. Every call completed, but **the hosted
pilot requires Workers Paid**. Its limits, statements per call and measurements are in
[`enrich-observables-contract.md`](enrich-observables-contract.md).

## Quotas

Each client token has a per-minute and a per-day ceiling on calls. Unless a token is
given its own, they are **60 per minute and 5,000 per day**. A call carries up to 100
values, so the default day covers up to 500,000 values.

- **What counts:** `tools/call`, and both methods of `/heartbeat`. `initialize`,
  `notifications/initialized` and `tools/list` do not count: MCP clients may send them
  before every call, and none of them reads the corpus.
- **Windows:** fixed UTC windows. A minute is `HH:MM`, and a day runs from 00:00 to
  24:00 UTC, which is 08:00 to 08:00 in Taipei.
- **Exact:** each counter is taken with one conditional database write, so concurrent
  calls cannot push it past its limit.
- **Refused calls** do not spend the daily quota when the minute limit refused them.
  They are recorded, so the daily usage check can report a client being turned away.
- **Suspending:** a limit of 0 suspends a token without revoking it.

A refused call reads nothing and looks nothing up:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 53

{"jsonrpc":"2.0","id":7,"error":{"code":-32029,
 "message":"rate limit exceeded: 60 calls per minute",
 "data":{"reason":"rate_limited","scope":"minute","limit":60,"retry_after_seconds":53}}}
```

`scope` is `minute` or `day`. `retry_after_seconds` counts to the next minute or to
00:00 UTC. If the quota cannot be checked, because the database is unreachable, the
call is refused with HTTP 503, code `-32030`, reason `quota_unavailable` and
`Retry-After: 30`. In both cases **every value in the call is unknown**, never a miss.

**Monitoring.** The daily check at 04:00 UTC reads the previous UTC day's counters.
It mails the operator when a token had any call refused, or used 80% or more of its
daily quota. A quiet day sends nothing.

**Retention.** Minute counters are deleted by the next daily check. Day counters are
kept 90 days. The counters hold a token hash, a time window and two integers.

Issuing, revoking, suspending and changing a token's quotas are in
[`token-runbook.md`](token-runbook.md).

## Timeouts

| layer | bound | what the caller sees |
|---|---|---|
| lookup budget | 10 s, checked before each D1 statement | remaining values in `errors`, `time_budget_exceeded`; `status` partial or failed |
| one D1 statement | 30 s (platform) | that statement's values in `errors`, `lookup_failed` |
| whole request | no platform wall-clock limit while the caller stays connected | — |

The budget is checked *before* a statement is sent, so a call can overrun it by the one
statement in flight. In the worst case that is the 30-second D1 limit, which puts the
longest possible call at about 40 seconds.

**Client timeout: 45 seconds** or more. On a client timeout, every value in the call is
unknown.

## `status`

| `status` | when | MCP `isError` |
|---|---|---|
| `complete` | no value is in `errors`, and nothing was dropped by a limit | false |
| `partial` | some values are in `errors` and some in `items`; **or** `truncated` is true | false — the items are valid |
| `failed` | every value that was looked up is in `errors` | **true** |

`complete` means nothing the caller asked for was left undone. Two things decide it:

- **`errors`** — a lookup that did not finish.
- **`truncated`** — values past the 100th, which would be looked up if resubmitted.
  An over-limit call is therefore never `complete`, even when every lookup in it
  succeeded. The dropped values are in `skipped` with `request_limit` and their
  `input_index`, so the caller knows exactly which ones to send again.

A value skipped for what it *is* — a private address, an internal name — does not make
a response partial: resubmitting it would be refused again, so it is an answer rather
than a gap. A call in which every value is skipped that way is `complete`, with empty
`items` and `errors`.

A search whose matches exceed its row limit returns `truncated: true` and `status:
"partial"`. There is no cursor; narrow the search by `date`, `since`, `action` or
`indicator_type` to reach the remaining rows.

## Skip reasons

| `reason` | the value | offline validator |
|---|---|---|
| `empty_value` | is blank after trimming | same |
| `invalid_value` | contains whitespace or a control character; is over 512 characters; has more than 16 dot-separated labels; is a dotted quad that is not a valid address (such as `256.1.1.1` or `010.1.1.1`); or is a URL that does not parse | reports these as `unsupported_type`, `malformed_ip` or `unparseable_host` |
| `non_public_ip` | is an address that is not globally reachable, or a URL whose host is one | same |
| `internal_hostname` | is a single-label name, or ends in `.local`, `.internal`, `.corp`, `.lan`, `.home.arpa`, `.localdomain` or `.intranet` — alone, with a port, or as a URL's host | same |
| `sensitive_url` | is a URL carrying a username or password | not checked; the first sample excludes URLs |
| `request_limit` | is at position 100 or later | no batch limit |

**Not globally reachable** follows the IANA special-purpose address registries — the
same definition Python's `ipaddress.is_global` uses, which the offline validator runs.
It covers private, loopback, link-local, shared (CGNAT), documentation, benchmarking,
"this network", reserved, unique-local, 6to4 and Teredo space. An IPv4-mapped IPv6
address is judged by its embedded IPv4 address. Multicast is globally reachable under
that definition and is looked up. The service's tests encode the classifications
Python returns for the edge addresses of each range.

The service does not classify observable types, so it has no `unsupported_type`: a
string that is not an address, hostname, URL, hash or CVE identifier is looked up and
simply misses.

It does **not** restore defanged values (`evil[.]com`) or strip a URL's query string
or fragment. It matches the value it receives, lowercased. The offline validator does
restore defanging.

## Error reasons

| `reason` | a lookup for the value |
|---|---|
| `lookup_failed` | had a D1 statement throw for one of its candidates — including the statement limit being reached |
| `time_budget_exceeded` | had a candidate whose statement was never sent because the budget ran out |

The database's own error message is neither returned nor logged.

## Request-level outcomes

| situation | HTTP | body |
|---|---|---|
| missing, unknown, revoked or expired token | 401 | `{"error":"unauthorized"}` |
| `User-Agent` is Python's `urllib` default, or present but empty | 403 from Cloudflare, before the service | plain text `error code: 1010` — send any other `User-Agent`. Checked 2026-09-17: `python-requests`, `python-httpx`, `aiohttp`, `Go-http-client`, `node`, `undici`, `axios`, `Java`, `okhttp`, and no header at all, all reach the service |
| path other than `/mcp` | 404 | plain text |
| method other than `POST` on `/mcp` | 405 | plain text |
| body over 256 KiB | 413 | JSON-RPC error `-32600` |
| tool call over the token's per-minute or per-day quota | 429, `Retry-After` | JSON-RPC error `-32029`, `data.reason` `rate_limited` |
| quota could not be checked | 503, `Retry-After: 30` | JSON-RPC error `-32030`, `data.reason` `quota_unavailable` |
| body that is not JSON | 200 | JSON-RPC error `-32700` |
| unknown JSON-RPC method | 200 | JSON-RPC error `-32601` |
| unknown tool, or missing or invalid arguments | 200 | tool result with `isError: true` and an `error` message |
| platform failure (CPU limit, runtime exception outside a lookup) | 5xx from Cloudflare | not JSON-RPC — treat every value as unknown |

## Response shapes

### `lookup_iocs`

```json
{
  "status": "partial",
  "truncated": true,
  "counts": { "requested": 103, "processed": 97, "skipped": 5, "failed": 1, "found": 2 },
  "items": [
    {
      "input_index": 0,
      "value": "api.evil.example.com",
      "found": true,
      "matched_on": "evil.example.com",
      "exact": false,
      "first_seen": "2026-09-04",
      "last_seen": "2026-09-05",
      "seen_on": ["2026-09-04", "2026-09-05"],
      "hits": ["…one object per report row, with its citation…"]
    }
  ],
  "skipped": [
    { "input_index": 1, "value": "10.0.0.5", "reason": "non_public_ip" },
    { "input_index": 100, "value": "late.example.com", "reason": "request_limit" }
  ],
  "errors": [
    { "input_index": 7, "value": "x.example.org", "reason": "time_budget_exceeded" }
  ],
  "requested": 103,
  "examined": 97,
  "found": 2
}
```

`requested`, `examined` and `found` at the top level are kept for callers written
against the earlier shape and carry the same numbers as `counts`.

### `lookup_ioc`

| outcome | fields |
|---|---|
| looked up | `status: "complete"` and the same fields as a `lookup_iocs` item |
| not looked up | `status: "skipped"`, `value`, `reason` |
| lookup did not complete | `status: "failed"`, `value`, `reason` |

A skipped or failed single lookup carries **no `found` field**, so no caller can read
it as a miss.

### `search_confirmed_iocs`

| outcome | fields |
|---|---|
| searched, all matches returned | `status: "complete"`, `count`, `truncated: false`, `items` |
| searched, more matches than the limit | `status: "partial"`, `count`, `truncated: true`, `items` |
| query refused | `status: "skipped"`, `reason`, `count: 0`, `truncated: false`, `items: []` |

A query is refused only where the text is plainly an address that is not globally
reachable, an internal dotted name, or a URL carrying credentials. A single word is a
search term: `ransomware` and `dc01` are searched; `dc01.corp` and `10.0.0.5` are not.

## Checking a change after it is deployed

Only the current deployment answers. Version preview URLs are disabled
(`preview_urls = false`): until 2026-09-17 they were on, and eight versions from before
the input guard still answered at their own URLs.

A deploy does not reach every location at once. Of 14 checks run within seconds of the
2026-09-14 deploy, one was answered by the previous version and returned the old
response shape; five retries of the same check minutes later were all correct. A live
check that disagrees with the code just deployed should be repeated before it is
recorded as a failure.
