# `enrich_observables` — contract v1

**Status:** final for the hosted pilot
**Date:** 2026-09-18
**Service version:** Worker `ae244995`; corpus `2026-09-17.478eee3d0883` when the
examples were taken
**Machine-readable schemas:**
[`enrich_observables.input.json`](../deploy/worker/src/schemas/enrich_observables.input.json),
[`enrich_observables.output.json`](../deploy/worker/src/schemas/enrich_observables.output.json).
`tools/list` also returns both.
**Examples:** [`docs/examples/enrich_observables/`](examples/enrich_observables/). The
complete and partial examples, and every request-level error, are real responses
from the deployed service. The `failed` example is simulated; see below.

Where this document and the schemas disagree, the schemas win, and the
disagreement is a defect in this document.

This contract describes the same answer the offline validator gives. On
2026-09-18, 5,683 values were run through both the corrected validator and this
service against the same corpus. The inputs were every confirmed and excluded value,
plus subdomains, URLs, defanged forms and trailing-slash variants of them. Every value
landed in the same bucket, and every compared field was identical. The comparison is
described under [Parity with the offline validator](#parity-with-the-offline-validator).

---

## Endpoint

| | |
|---|---|
| URL | `https://threat-pulse.nine-security.com/mcp` |
| method | `POST`, `Content-Type: application/json` |
| protocol | JSON-RPC 2.0, MCP `2025-06-18`. Stateless: no session id and no SSE; every response is one JSON body |
| methods | `initialize`, `notifications/initialized`, `tools/list`, `tools/call` |
| authentication | `Authorization: Bearer <token>`, one token per client, handed over on a separate channel |
| User-Agent | must not be Python `urllib`'s default, and must not be present but empty: Cloudflare refuses both (`403`, `error code: 1010`). Omitting the header works. `requests`, `httpx`, `aiohttp`, Go, Node, Java and okhttp all pass |
| client timeout | **45 s** or more |
| quotas | 60 `tools/call` per UTC minute and 5,000 per UTC day per token, unless agreed otherwise. `initialize` and `tools/list` do not count |

A direct HTTP caller needs no MCP library. Send a `tools/call` and read
`result.structuredContent`:

```json
{"jsonrpc": "2.0", "id": 101, "method": "tools/call",
 "params": {"name": "enrich_observables",
            "arguments": {"values": ["CVE-2026-20079", "login.service-nowinc[.]com"]}}}
```

## The tool

| | |
|---|---|
| name | `enrich_observables` |
| annotations | `readOnlyHint: true`, `openWorldHint: false` |
| result | `structuredContent`, conforming to the output schema, and the same JSON as text in `content[0].text` |
| `isError` | `true` when `status` is `failed`, or when the arguments are invalid |

An argument error is not a result. It carries only a message in `content[0].text`,
for example `{"error": "types, when given, must be an array the same length as
values"}`, and has no `structuredContent`.

## Request

| field | type | required | meaning |
|---|---|---|---|
| `values` | array of string | yes | Observables, any mix of types. At most **100** are looked up; positions 100 and later come back in `skipped` as `request_limit`. Defanged input is accepted: `[.]`, `(.)`, `{.}`, `[:]`, `[://]`, `[dot]`, `(dot)` in any letter case, and the schemes `hxxp`, `hxxps`, `fxp`. Duplicates are answered at each position. |
| `types` | array of string | no | A per-value hint, the same length as `values`: `cve`, `domain`, `ip`, `url`, `md5`, `sha1`, `sha256`, or `""` for none. An unknown hint is reported in `warnings` and ignored. A hint that disagrees with the value's shape is reported, and then used. **A hint never overrides a safety skip.** |
| `detail` | `compact` \| `full` | no, default `compact` | `compact` returns the first citation of each hit. `full` returns every citation, plus each citation's source sentence (`context`) if the token holds the `context` scope. |
| `since` | `YYYY-MM-DD` | no | Ignore report days before this date, for confirmations and exclusions alike. |

Send real values where you can. Strip URL query strings, fragments and credentials
before sending. A URL carrying credentials is refused (`sensitive_url`), and the
other parts only make an exact whole-URL match less likely.

## Response

### Top level

| field | meaning |
|---|---|
| `status` | `complete`: nothing you asked for was left undone. `partial`: some values are in `errors`, or `truncated` is true. `failed`: every value that was looked up is in `errors`. |
| `request_id` | A UUID, for correlation and support. |
| `generated_at` | UTC, ISO 8601. |
| `corpus_version` | The corpus this answer came from. **The same version gives the same answer** for the same request, and it equals the `corpus_version` of an offline bundle built from the same report days. `null` when the stored days do not match the days it was computed from; `coverage.version_note` then says so. |
| `truncated` | `true` when values past the 100th were not looked up. |
| `detail`, `since` | As applied. `since` is `null` when absent. |
| `coverage` | What the corpus covers; see below. |
| `counts` | See below. |
| `hits`, `excluded`, `unseen`, `skipped`, `errors` | **Every submitted value appears in exactly one of these, identified by `input_index`.** |

Skipped values never make a response partial: resubmitting them would be refused
again. `truncated` does, because values dropped by the limit can be resubmitted.

### `counts`

`requested`, `processed` (= `hits` + `excluded` + `unseen`), `hits`,
`headline_hits`, `excluded`, `unseen`, `skipped`, `failed`.

A coverage rate is `headline_hits / processed`. Skipped and failed values are not
in the denominator.

### `coverage`

| field | meaning |
|---|---|
| `report_range` | First and last report day held. **Required to interpret `unseen`.** |
| `report_count` | Daily report batches held, not articles. |
| `source_count` | Distinct publishers that named at least one value. |
| `days_with_source_failures` | `[{report_date, sources_failed: [source keys]}]`. A value absent because its publisher could not be read that day is not the same as one nobody reported. |
| `headline_methods` | `["exact", "parent_domain", "same_host"]` |
| `public_suffix_list_version` | Digest of the suffix rules that bound parent and child relations. |
| `scope`, `verdict_note`, `absence_note` | Fixed sentences stating what this service is not, and how `verdict` and `unseen` must be read. |
| `version_note` | Present only when `corpus_version` is withheld. |

### `hits[]`

| field | meaning |
|---|---|
| `input_index`, `value` | Position and value **as submitted**. |
| `normalized_value` | What was matched: an upper-case CVE, a lower-case hash or domain, a compressed IPv6 address, and **for a URL, its host**. |
| `normalization_applied` | Any of `defang`, `defang_scheme`, `trailing_dot`. |
| `type`, `type_supplied`, `warnings` | The type used, the hint given (or `null`), and notes such as `type_mismatch:supplied=ip,detected=domain`. |
| `verdict` | `source_reported`: a publisher named it. `benign_listed`: a publisher named it, but this service holds it back from blocking; see `benign_basis`. |
| `basis` | `publisher_report` or `service_rule`, matching `verdict`. |
| `match` | `exact`, `same_host` (a URL whose host is a corpus value), `parent_domain` (the submitted host is beneath a corpus domain), or `child_domain` (the corpus named something beneath the submitted domain). Never a boolean. |
| `headline` | `true` for `exact`, `same_host` and `parent_domain`. |
| `matched_value` | The corpus value that matched, as stored. It can be a whole URL, or a domain other than the one you sent. |
| `match_boundary` | `null` for `exact`, `host` for `same_host`, `registrable_domain` for parent and child relations. Parent and child relations never cross a public suffix: `other.github.io` does not match `tenant.github.io`. |
| `first_seen`, `last_seen` | Report days. |
| `days_since_last_seen` | Days from `last_seen` to the **last report day held**, not to today, so the number depends only on `corpus_version`. |
| `report_count` | Distinct daily reports that named it. Not a corroboration measure. |
| `source_count`, `publishers` | Distinct publishers, and their names in first-seen order. **This is the corroboration measure.** Read the names: so far, a network indicator with more than one publisher has usually been an aggregator carrying another publisher's original report. |
| `suggested_investigation_action` | `patch`, `block`, `hunt`, `monitor` or `none`. This service's analysis, **not a safe automatic action**. |
| `priority` | This service's intelligence priority for triage order. Not case severity. |
| `benign_basis` | Why the value is held back: `vendor_brand_apex`, `public_resolver_registry` or `domain_boundary_rule`. `null` otherwise. |
| `reason_code` | `benign_basis` when set. Otherwise, for a CVE: `kev_listed` if KEV lists it, else `cvss_<severity>` from NVD (`cvss_critical`, `cvss_high`, `cvss_medium`, `cvss_low`, `cvss_none`), else `cve_reported`. For everything else: `publisher_indicator`. |
| `reason` | This service's analyst note, **in Traditional Chinese**. Prose, not for parsing. |
| `citation_count`, `citations` | How many (publisher, article) citations exist, and the first (`compact`) or all of them (`full`). **A value that cannot be cited is never a hit**; it is returned in `errors` as `missing_citation`. |
| `vulnerability` | For a CVE, the newest record held; otherwise `null`. |

### `citations[]`

| field | meaning |
|---|---|
| `publisher` | The publishing outlet. |
| `article_title`, `article_url` | The article. Follow the URL to read the claim. |
| `published_at` | The publication time as the publisher states it. |
| `report_date` | The report day that first carried this citation. |
| `report_id` | The identifier of that day's report. |
| `context` | Only with `detail: full` and the `context` scope: the verbatim source sentence, at most 300 characters. |

### `vulnerability`

| field | meaning |
|---|---|
| `kev` | `listed`, `date_added`, `due_date`, `known_ransomware` (CISA KEV) |
| `cvss` | `score`, `severity`, `version`, `vector` (NVD) |
| `nvd_status` | The NVD analysis status |
| `epss` | `score`, `percentile`, `date` (FIRST EPSS) |
| `provenance` | The URL each figure was fetched from |
| `retrieved_at` | When this service fetched the record |
| `observed_on` | The report day whose record this is: the newest one that holds this CVE |

A KEV listing or CVSS score never creates a hit by itself. A CVE is a hit only if a
publisher in the corpus named it.

### `excluded[]`

The service saw the value and ruled it out. That is not the same as never having seen
it.

Fields: `input_index`, `value`, `normalized_value`, `normalization_applied`, `type`,
`type_supplied`, `warnings`, and:

- `matched_value`: the excluded corpus value;
- `reason_codes`: `publisher_domain`, `non_public_ip`, `excluded_editorial_section`, and
  any code the pipeline adds later;
- `report_dates`.

### `unseen[]`

`input_index`, `value`, `normalized_value`, `normalization_applied`, `type`,
`type_supplied`, `warnings`.

**`unseen` is not a clean or benign verdict.** It means this corpus, over
`coverage.report_range`, does not name the value.

### `skipped[]`

`input_index`, `value`, `reason`, and `warnings` when there are any. Skipped values
were **not looked up** and are never `unseen`.

| `reason` | the value |
|---|---|
| `empty_value` | is blank |
| `invalid_value` | is not a string; has whitespace or a control character; is over 512 characters; has more than 16 dot-separated labels; is an address that does not parse; or is a URL without a host |
| `non_public_ip` | is an address that is not globally reachable (IANA special-purpose registries, as Python's `ipaddress.is_global`), or a URL or domain whose host is one |
| `internal_hostname` | is a single-label name, or ends in `.local`, `.internal`, `.corp`, `.lan`, `.home.arpa`, `.localdomain` or `.intranet` |
| `sensitive_url` | is a URL carrying a username or password |
| `unsupported_type` | is none of the supported types, for example `evil.com/path` without a scheme |
| `request_limit` | is at position 100 or later |

**Internal names under a public domain cannot be recognised here.** Filter your own
and your customers' internal suffixes before sending. A skipped value was still
transmitted: skipping means it was not looked up, stored or logged.

### `errors[]`

`input_index`, `value`, `reason`:

| `reason` | meaning |
|---|---|
| `lookup_failed` | a database statement this value needed failed |
| `time_budget_exceeded` | a statement this value needed was not sent before the 10 s budget ran out |
| `missing_citation` | the value matched a corpus entry that carries no citation |

A value is an error if **any** statement it needed did not complete. The service
never answers from a partial set of lookups. For example, it does not report a parent
match when the exact lookup was lost. An error is never an absence: treat it as
unknown, and retry.

## How a value is decided

1. **Normalise.** Undefang (repeated until stable). Drop a trailing dot. Detect the
   type, or use the hint.
2. **Skip** if the service's guard or the type rules say so (table above).
3. **Decide**, first match wins:
   1. an **exact** confirmation of the value, or of the whole URL → hit, `exact`
   2. an **exclusion** of the value, or of the whole URL → `excluded`
   3. for a URL, a confirmation of its **host** → hit, `same_host`
   4. for a URL, an exclusion of its host → `excluded`
   5. a **parent** domain confirmed → hit, `parent_domain`; otherwise a **child** domain
      confirmed → hit, `child_domain`
   6. otherwise → `unseen`
4. **Cite.** A match without a citation becomes an error.

Whole URLs are compared trimmed, in lower case, and without trailing slashes on
either side.

A value held back with a `benign_basis` is matched **only exactly**. No `same_host`,
`parent_domain` or `child_domain` relation passes through it. So
`https://github.com/anything` and `gist.github.com` are `unseen`, while `github.com`
itself is a `benign_listed` hit.

Exclusions are recorded per article, which is why an exact confirmation elsewhere
outranks them. An exclusion still outranks a parent or child relation.

Only the seven supported types are answered. The corpus also holds filenames and
malware family names; this tool does not match them.

## `corpus_version`

- It is computed from the report folder the service is fed from, **by the same code
  that builds an offline bundle**. It is written to the service in the same batch as
  each day's data.
- It is reported only while the service holds exactly the days it was computed
  from. Otherwise it is `null`, with `coverage.version_note`.
- It changes when a day is added or corrected, or when the rules that build it change.
- Record it with every result. Two results with the same `corpus_version` and the same
  request are comparable. Results under different versions may differ because the
  corpus differs.

## Mapping to the fields you store

| your field | take it from |
|---|---|
| source | the service itself (`threat-pulse`), with `corpus_version` |
| publisher | `citations[].publisher`; all names in `publishers` |
| publication date | `citations[].published_at` |
| match method | `match`, with `headline` and `matched_value` |
| corpus version | `corpus_version` |
| `intel_refs` | `citations[].article_url` (with `report_id`) and, for a CVE, `vulnerability.provenance` |

## Request-level outcomes

| situation | HTTP | body | example |
|---|---|---|---|
| missing, unknown, revoked or expired token | 401 | `{"error":"unauthorized"}` | `response-401.json` |
| `User-Agent` refused by Cloudflare | 403 | `error code: 1010` (text) | — |
| body over 256 KiB | 413 | JSON-RPC `-32600` | `response-413.json` |
| over the per-minute or per-day quota | 429, `Retry-After` | JSON-RPC `-32029`, `data: {reason: "rate_limited", scope, limit, retry_after_seconds}` | `response-429.json` |
| quota could not be checked | 503, `Retry-After: 30` | JSON-RPC `-32030`, `quota_unavailable` | — |
| invalid arguments | 200 | tool result, `isError: true`, message only | `response-argument-error.json` |
| unknown method | 200 | JSON-RPC `-32601` | — |
| platform failure | 5xx from Cloudflare | not JSON-RPC | — |

For any non-200 response, or a client timeout, **every value in the call is unknown**.

## Limits and performance

| | |
|---|---|
| values looked up per call | 100 |
| characters per value, labels per value | 512, 16 |
| request body | 256 KiB |
| wall-clock budget | 10 s, checked before each database statement |
| database statements per call | at most 33: 2 authentication, 2 quota, 2 corpus, ≤ 19 confirmations, ≤ 4 exclusions, ≤ 2 child domains, ≤ 2 CVE records |

Measured on 2026-09-18 against the deployed service, eight calls each:

| request | wall time | CPU p50 | CPU p90 | response |
|---|---|---|---|---|
| 100 URLs with 16-label hosts (the worst case), `compact` | 2.1–2.5 s | 34 ms | 56 ms | 53 KiB |
| 6 mixed values, `compact` | 0.8–1.1 s | 7 ms | 14 ms | 17 KiB |
| 100 confirmed values, `full` | 1.1–1.4 s | 15 ms | 29 ms (p99) | 406 KiB |

The pilot runs on Workers Paid, where CPU per request defaults to 30 s; the limits then
in effect are confirmed separately. Use `compact` unless you need every citation:
`full` on 100 hits is about 0.4 MiB.

## Availability

The corpus is pushed once a day, at about 22:00 UTC (06:00 Asia/Taipei). The push
replaces the day's rows through Cloudflare's import path, and Cloudflare states that
the database is unavailable to queries while it runs. On 2026-09-18 that window was
under five seconds.

A call landing in it fails the way any database failure does: `status: "failed"`, every
value in `errors` as `lookup_failed`, and `isError: true`. **Retry.** Nothing in such a
response is an absence.

## Examples

All in [`docs/examples/enrich_observables/`](examples/enrich_observables/).

| file | what it shows |
|---|---|
| `tool-definition.json` | the tool as `tools/list` returns it, schemas included |
| `request-complete.json`, `response-complete.json` | eight values: CVE `exact` with KEV/CVSS/EPSS and six publishers; a defanged subdomain matching its parent; a URL matching whole; an excluded URL; `github.com` as `benign_listed`; a GitHub URL `unseen` because the host is held back; a private address skipped; an unseen MD5 |
| `request-partial.json`, `response-partial.json` | 101 values: `status: partial`, `truncated: true`, position 100 `request_limit` |
| `response-failed.simulated.json` | every database statement failing: `status: failed`, `isError: true`, two `lookup_failed` errors and one skip. Produced by the service's own code (`deploy/worker/scripts/example-failed.ts`) with a database that always throws, because causing an outage in production to capture one is not acceptable |
| `response-argument-error.json`, `response-401.json`, `response-413.json`, `response-429.json` | request-level outcomes |

The service's test suite checks the three responses against the output schema on
every run.

An abbreviated hit from `response-complete.json`:

```json
{
  "input_index": 1,
  "value": "login.service-nowinc[.]com",
  "normalized_value": "login.service-nowinc.com",
  "normalization_applied": ["defang"],
  "type": "domain",
  "type_supplied": "domain",
  "verdict": "source_reported",
  "basis": "publisher_report",
  "match": "parent_domain",
  "headline": true,
  "matched_value": "service-nowinc.com",
  "match_boundary": "registrable_domain",
  "first_seen": "2026-09-11",
  "last_seen": "2026-09-12",
  "days_since_last_seen": 5,
  "report_count": 2,
  "source_count": 2,
  "publishers": ["Microsoft Security Blog", "Cyber Security News"],
  "suggested_investigation_action": "block",
  "priority": "medium",
  "benign_basis": null,
  "reason_code": "publisher_indicator",
  "reason": "防火牆／DNS／proxy 封鎖後再 hunt 連線；原文明確記載",
  "citation_count": 2,
  "citations": [{
    "publisher": "Microsoft Security Blog",
    "article_title": "Protecting organizations from AI-assisted executive impersonation and invoice fraud",
    "article_url": "https://www.microsoft.com/en-us/security/blog/2026/09/10/protecting-organizations-ai-assisted-executive-impersonation-invoice-fraud/",
    "published_at": "2026-09-10T17:23:05+00:00",
    "report_date": "2026-09-11",
    "report_id": "8a30f20df5f2e29c1848a774ed1670274176c0115ea2b28aeb5a880286eca5cd"
  }],
  "vulnerability": null
}
```

## Parity with the offline validator

On 2026-09-18 the live database was copied, and this service was run against the copy.
The corrected validator was run against a snapshot of the same days. Both were given
the same 5,683 values:

- every confirmed and excluded value in the corpus;
- for each domain, a subdomain, a URL on it and its defanged form;
- for each URL, with and without a trailing slash, and in upper case;
- CVEs in lower case;
- held-back, private, internal, unsupported and empty values.

**Every value landed in the same bucket.** The following fields were identical for
every hit:

- match relation, matched value, report count, publisher count and list;
- first and last seen;
- the first citation's URL, publisher and publication date, and the citation count;
- action, priority, benign basis, normalized value and normalizations;
- for CVEs: KEV listing and due date, CVSS score and severity, EPSS score and date,
  provenance, and observed-on.

Skip reasons are the one place the two differ, and only in name:

| value | validator | this service |
|---|---|---|
| a single-label name such as `fairlife`, with no type given | `unsupported_type` | `internal_hostname` |
| an address that does not parse | `malformed_ip` | `invalid_value` |
| a URL or domain without a usable host | `unparseable_host` | `invalid_value` |

This service also skips what the validator has no rule for: `sensitive_url`,
`request_limit`, and values over the length and label limits.

The comparison also found one defect in the bundle builder. On 2026-09-10,
`pf.ch` and `verification.google` were extracted both as filenames and as domains,
with different actions. The bundles dated 2026-09-14 and 2026-09-17 give the domains
the filenames' action, `hunt`; the correct action is `block`, which this service
returns. It is fixed, and a bundle built now carries `block`. Coverage rates are not
affected.

## Differences from specification v2

| v2 | v1 contract | why |
|---|---|---|
| `unseen` as bare strings | objects with `input_index` | a machine client must map each answer back to its input, including duplicates |
| `verdict` `benign_listed` implies action `none` | `benign_listed` keeps the recorded action, usually `hunt` | the action is what the pipeline recorded; the verdict says it will not be blocked |
| `basis` values `nvd`, `kev`, `benign_registry` | `publisher_report` or `service_rule`; CVE sources are in `vulnerability.provenance` | a hit's basis is always a publisher; the vulnerability record carries its own provenance |
| `reporting` block for CVEs | `report_count` and `source_count` on every hit | one shape for every type |
| `normalization_applied`: `case_fold`, `url_normalize` | `defang`, `defang_scheme`, `trailing_dot` | case folding is always done and is not reported |
| `days_since_last_seen` relative to now | relative to the last report day held | so a `corpus_version` always gives one answer |
| `reason` in English | `reason` in Traditional Chinese, plus a stable `reason_code` | the pipeline writes its notes in Chinese; `reason_code` is what a program reads |
| no `headline`, `publishers`, `citation_count`, `warnings` | present | the review asked for corroboration and headline relations to be explicit |

## Not in this version

- Tenant partitioning: every token reads the same corpus, which holds no customer data.
- History before 2026-09-04. The corpus grows one day per day and cannot be backfilled.
- Candidate values and filenames: they are held but not answered.
- Per-value timing inside a call.
