# Response: the three service-side conditions

**Date:** 2026-09-17
**Subject:** over-limit responses, server-side refusal, and what Cloudflare records — all
three answered, with what is still not true

This does not start endpoint integration. You asked us not to begin that before your
coverage review. These are the conditions on our side of an endpoint, prepared so
they are not what holds a pilot back later. Full detail is in two attached
documents:

- `query-service-limits.md` — limits, timeouts, status rules and response shapes;
- `data-handling.md` — logging, retention, access and residency.

Everything marked *verified* below was checked against the deployed service on
2026-09-17, not only against the code.

---

## 1. An over-limit request is never truncated silently

It is reported as **partial**, and every value that was not looked up is named.

| situation | response |
|---|---|
| more than 100 values in `lookup_iocs` | values from position 100 on appear in `skipped` with reason `request_limit` and their `input_index`; `truncated: true`; **`status: "partial"`** |
| request body over 256 KiB | HTTP 413 with JSON-RPC error `-32600`; nothing is looked up |
| more search matches than the row limit (max 200) | `truncated: true`, **`status: "partial"`** |

`status` follows three rules:

- **`complete`** — nothing you asked for was left undone.
- **`partial`** — some values are in `errors`, or `truncated` is true.
- **`failed`** — every value that was looked up is in `errors`; MCP `isError` is true.

A value refused for what it *is*, such as a private address, does not make a response
partial. Resubmitting it would be refused again, so it is an answer, not a gap.

**A correction.** Until today, a batch of more than 100 values in which every lookup
succeeded reported `truncated: true` but `status: "complete"`. The dropped values were
listed, but a caller reading only `status` would have taken the batch as finished.
That is now `partial`. Search had a related flaw: it reported `truncated` whenever the
row count *reached* the limit, which cannot tell "exactly the limit" from "rows were
left out". It now fetches one row past the limit and reports only the second case.

**There is no pagination.** For a lookup, resubmit the values listed in `skipped`. For
a search, narrow it by `date`, `since`, `action` or `indicator_type`.

**Verified live:**

| request | result |
|---|---|
| 101 values | `partial`, `truncated: true`; position 100 in `skipped` as `request_limit`; counts 101 / 100 / 1 / 0 |
| exactly 100 values | `complete` |
| search where matches equal the limit (13) | `complete`, `truncated: false` |
| search with a limit one below the matches | `partial`, `truncated: true` |
| 300 KB body | HTTP 413 |

**One case this cannot cover.** If the platform itself ends a request, for example on
the CPU limit, you receive a Cloudflare error rather than a JSON-RPC response. Treat
that as *every value unknown*, never as misses. On the current free plan only a
maximum-size batch goes over the documented CPU limit. It measured 14–23 ms and
completed all 13 times. An endpoint pilot would run on the paid plan, where the
default limit is 30 seconds.

## 2. The service refuses private and reserved addresses and internal hostnames

Refused values are classified **before any database statement is built**. They come
back in `skipped` with a reason and are never looked up:

| reason | refused values |
|---|---|
| `non_public_ip` | addresses that are not globally reachable, per the IANA special-purpose registries. This is the same definition as Python's `ipaddress.is_global`, which your offline validator uses. An IPv4-mapped IPv6 address is judged by its IPv4 part |
| `internal_hostname` | single-label names; names under `.local`, `.internal`, `.corp`, `.lan`, `.home.arpa`, `.localdomain`, `.intranet`. Each is refused alone, with a port, or as a URL's host |
| `sensitive_url` | URLs carrying a username or password |

Free-text search refuses a query that is plainly one of these.

**Verified.** Unit tests compose the refusal step with the lookup against a fake
database, and assert that none of these values reaches a statement. Live,
`10.0.0.1` returned `non_public_ip` and `dc01.corp` returned `internal_hostname`.

**Two limits you should plan around:**

1. **The service cannot recognise your internal names under public domains.** An
   internal host such as `vpn01.corp.example.com.tw` looks like any other public name
   to us. Only you know those suffixes, so please filter them before sending.
2. **Refusal means the value is not looked up, stored or logged. It does not mean the
   value was never sent.** A refused value still arrives in the request body, over TLS
   and through Cloudflare, and exists in memory for the length of the request. Only
   filtering on your side prevents transmission. The classification in the offline
   validator you already have matches the service's for addresses and internal
   suffixes, so it can serve as that filter.

**Found and fixed while checking this.** Every version of the service ever uploaded had
its own preview URL, and those URLs kept running that version's code. Eight versions
from before the refusal logic still answered there. No client token existed that could
have used them, but once a pilot token is issued, its holder could have reached code
without this protection. Preview URLs are now disabled. All thirteen versions were
probed again after deploying, and none answers with the service's code.

## 3. Logs: what is kept, for how long, who can reach it, and where

**What is recorded, and for how long:**

| record | contents | kept |
|---|---|---|
| per-request invocation logs | request, response, metadata | **disabled** |
| Worker console output | the daily heartbeat's lines only; no request data | 3 days (7 on the paid plan) |
| live tail | streamed while someone watches. Cloudflare's example event shows URL, method and headers, not the body, which is where observables travel | not stored |
| Worker analytics | time, data center, status, version, counts, CPU. No field for IP, URL, header or body | up to 90 days |
| D1 query insights | SQL text with `?` placeholders. Checked: every lookup statement recorded over 7 days held placeholders only | up to 90 days |
| client token usage | last used time and call count per token | until deleted |

**Submitted values are in none of these.**

**Who can reach them, or change what is recorded.** Anyone who can deploy the service
could deploy a version that records request bodies, so this list covers deploy rights
as well as read rights:

- **one** Cloudflare account member, the operator;
- **one** deploy token, kept only on the operator's workstation;
- a **database-only** token on the collecting host. It was checked to be refused access
  to the service's code, settings, secrets, versions and analytics.

Until 2026-09-17 a single token did both of our jobs and was stored on the collecting
host, which is shared with other services; one of them runs under a root-equivalent
account and used that token as well. Because the two services share a Cloudflare
account, and Cloudflare's Workers permissions cover the whole account rather than one
Worker, that token could deploy this service.

**That token is still in place.** A deletion on 2026-09-18 removed a different token
by mistake, and the shared one still authenticated the same morning. Until it is
removed, a credential able to redeploy this service is held on the collecting host.
We will tell you when that is done, and we treat it as a precondition of the pilot.

The database-only host token can still change the corpus and issue itself a client
token. It cannot see anyone's lookups: a lookup writes nothing that contains a value.

Cloudflare's own staff access is governed by Cloudflare's terms. We make no statement
about it.

**Where it runs:**

- **Processing:** in whichever Cloudflare data center a request reaches. Pinning a
  region is an Enterprise add-on we do not have. Over the last 30 days, requests were
  processed in Taiwan, Hong Kong, Japan and the United States.
- **Storage:** one copy of the corpus in Cloudflare's APAC region. This is observed,
  not configured: all 381 database statements in 30 days were served there, but APAC
  cannot be pinned by configuration.
- **If residency must be guaranteed,** the offline bundle already does that: the corpus
  comes to you, and nothing you check leaves your network.

**Still not true, stated plainly:**

- The request region and the storage region are observed, not enforced.
- The token shared until 2026-09-17 is **not yet removed**, so a credential able to
  redeploy the service is still held by another service on the collecting host.
- Neither of our tokens can list every API token on the account; the account owner
  confirms that list.
- Cloudflare does not document whether a live tail shows the `Authorization` header,
  so we assume it does. The account member and the deploy token can start one.
- There is no per-token rate limiting.

---

## For later, not needed before your coverage review

1. **Egress to `*.workers.dev`.** The service is currently at a `workers.dev` address,
   which many SOC proxies block. For a pilot we can serve it under our own domain
   instead. Please tell us which you can reach.
2. **How you would call it.** Through an agent's MCP client, or by direct HTTP from a
   playbook? Direct HTTP works today without an MCP library. It would benefit from
   structured results, which we would add in the final schema.
3. **Filtering your internal suffixes** before sending, as described in section 2.
