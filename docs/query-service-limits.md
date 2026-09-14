# Query service: limits, timeouts, errors and partial responses

**Applies to:** the hosted MCP query service in `deploy/worker/` — `lookup_iocs`,
`lookup_ioc` and `search_confirmed_iocs`.
**Implemented in:** `deploy/worker/src/guard.ts` (what may be looked up),
`deploy/worker/src/lookup.ts` (what a lookup returns), both tested under node with
`npm test`.
**Not a final schema.** The `enrich_observables` response schema is frozen only after
the offline coverage result has been reviewed. These are the rules it will inherit.

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
| CPU time per request | 10 ms |
| D1 statements per invocation | 50 |
| D1 statement duration | 30 s |
| D1 bound parameters per statement | 100 |
| Workers Logs retention | 3 days |

### Service limits

| limit | value | when exceeded |
|---|---|---|
| values per `lookup_iocs` call | **100** | values at position 100 and later are returned in `skipped` with `request_limit`; `truncated` is true |
| characters per value | **512** | skipped, `invalid_value` |
| dot-separated labels per value | **16** | skipped, `invalid_value` |
| request body | **256 KiB** | HTTP 413, JSON-RPC `-32600`; nothing is looked up |
| candidates per D1 statement | 90 | internal; leaves room for the date bound |
| D1 statements per call | at most **19** of the 50 | 2 for authentication plus at most 17 lookups (100 values × 15 parent candidates ÷ 90) |
| wall-clock budget per lookup call | **10 s** | values whose statements were not yet sent are returned in `errors` with `time_budget_exceeded` |
| rows per search | default 40, max **200** | `truncated` is true when the count reaches the limit |
| requests per token | none | **not implemented** |

The label limit exists because of the statement limit. Each label of a hostname is a
parent candidate, and without a bound one value of a few hundred labels would expand
into enough statements to exhaust the call for every other value in it. It counts the
whole value rather than only the host of a URL, because a value is expanded as
submitted: a short host followed by a dotted path would otherwise pass a host-only
count and expand anyway.

### CPU time: the one limit that cannot become a partial response

On the Free plan a request that uses more than 10 ms of CPU is terminated by the
platform. The caller receives a Cloudflare error rather than a JSON-RPC response, so
there is no `status`, no `errors` and no way to tell which values were looked up.

Measured before this change was deployed, from one host:

- a batch of 100 three-label hostnames completed in 0.39–0.71 s with a 24.8 KB
  response, three runs out of three;
- over the previous week, 24 calls: CPU p50 1.0 ms and p99 7.1 ms, wall time p50
  1.7 ms and p99 1.08 s.

A p99 of 7.1 ms is close enough to 10 ms that a maximum-size batch is **not
guaranteed** to complete. These are single-host measurements, not the pilot's latency
figures, and the worst case is to be measured again against the deployed change.

**What a caller should do:** treat a platform error or a timeout as *every value in
the call unknown* — never as misses — and retry with a smaller batch.

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
| `complete` | no value is in `errors` | false |
| `partial` | some values are in `errors` and some in `items` | false — the items are valid |
| `failed` | every value that was looked up is in `errors` | **true** |

`status` is decided by `errors` only. Skipped values never make a response partial,
and `truncated` is reported independently of `status`.

A call in which every value is skipped is `complete`, with empty `items` and `errors`.

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
| path other than `/mcp` | 404 | plain text |
| method other than `POST` on `/mcp` | 405 | plain text |
| body over 256 KiB | 413 | JSON-RPC error `-32600` |
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
| searched | `status: "complete"`, `count`, `truncated`, `items` |
| query refused | `status: "skipped"`, `reason`, `count: 0`, `truncated: false`, `items: []` |

A query is refused only where the text is plainly an address that is not globally
reachable, an internal dotted name, or a URL carrying credentials. A single word is a
search term: `ransomware` and `dc01` are searched; `dc01.corp` and `10.0.0.5` are not.
