# Review feedback: `enrich_observables`

**Review status:** Interested in a controlled validation pilot  
**Review scope:** Data usefulness, response semantics, safety, and measurability  
**Out of scope:** Consumer implementation details

## Overall assessment

`enrich_observables` is worth validating.

Its differentiated value is not a malicious/benign verdict. Its value is answering:

> Was this observable explicitly named in published vendor or CERT reporting, how was it matched, how recent and repeated was that reporting, and what source can be cited?

The regional corpus, especially TWCERT/CC, HKCERT, and NICS coverage, is potentially useful because it is not consistently represented in Western-oriented intelligence sources.

The most useful capabilities are:

- explicit separation of `source_reported`, `benign_listed`, `excluded`, and `unseen`;
- exact versus related-domain/host match semantics;
- citable provenance;
- reasoned exclusions that prevent indicator-shaped false positives;
- compact batch responses that do not turn `unseen` values into large objects.

We would treat this as report provenance and investigation context. It should complement, not replace, reputation, sandbox, passive DNS, endpoint telemetry, or original alert evidence.

## Important semantic change

Please remove the phrase **safe automated action** from the verdict table.

A value being named in a published report can justify investigation, hunting, prioritisation, or a proposed control action. By itself, it is not sufficient to guarantee that blocking or escalation is safe in every environment.

Suggested replacement:

| Current term | Recommended term |
|---|---|
| `safe automated action` | `suggested investigation action` |
| `suggested_action` | `suggested_investigation_action` |

The documentation should state that the suggestion is the service's analysis and that the consumer must apply its own policy before blocking or escalating.

## Field review

### Top-level and coverage fields

| Field | Mark | Feedback |
|---|---|---|
| `coverage.report_range` | USE | Required to interpret `unseen`. |
| `coverage.report_count` | USE | Keep; define whether this counts documents, daily batches, or unique reports. |
| `coverage.sources` | USE | Rename to `source_count` if it is an integer. A field named `sources` is expected to be a list. |
| `coverage.scope` | USE | Important guardrail against over-interpreting the result. |
| `coverage.verdict_note` | USE | Keep concise and machine-stable. |
| `coverage.absence_note` | USE | Essential. `unseen` must never imply clean or benign. |
| `queried` | USE | Add requested, processed, skipped, and truncated counts if they can differ. |
| `hits` | USE | Keep as a separate bucket. |
| `excluded` | USE | Valuable for defensible suppression and false-positive reduction. |
| `unseen` | USE | Bare strings are appropriate for compact mode. |

### Hit fields

| Field | Mark | Feedback |
|---|---|---|
| `value` | USE | Preserve the queried value for correlation with the request. |
| `type` | USE | Required for interpretation and audit. |
| `verdict` | USE | `source_reported` is preferable to `confirmed`. |
| `match` | USE | One of the most important fields; do not collapse to a boolean. |
| `matched_value` | USE | Required whenever the match is not exact. |
| `first_seen` | USE | Useful for historical context. |
| `last_seen` | USE | More useful than first seen for operational recency. |
| `age_days` | IGNORE | Ambiguous because it is based on `first_seen`; replace with `days_since_last_seen`. |
| `report_count` | USE | Do not describe it as independent corroboration unless independence is measured. |
| `suggested_action` | USE WITH CHANGE | Rename and document it as an investigation recommendation, not a safe automatic action. |
| `priority` | USE WITH CHANGE | Define the deterministic derivation and state that it is intelligence priority, not case severity. |
| `reason` | USE | Keep one sentence in compact mode; identify whether the basis is publisher reporting or service analysis. |
| `citation.title` | USE | Required for human review. |
| `citation.url` | USE | Required and should point to the supporting report, not a search page. |
| `citation.source` | USE | Prefer a stable source identifier. |
| `citation.report_date` | USE | Required for recency and reconstruction. |
| `citation.report_id` | USE | Strong audit and reproducibility feature. |
| `kev` | USE | CVE only; keep provenance distinct from article reporting. |
| `kev_due_date` | USE | CVE only. |
| `cvss_score` | USE | CVE only; include the scoring version/source. |
| `cvss_severity` | USE | CVE only; include the scoring version/source. |

### Excluded fields

| Field | Mark | Feedback |
|---|---|---|
| `value` | USE | Needed to correlate the suppression with the request. |
| `type` | USE | Important for filename/domain ambiguity. |
| `reason` | USE | This is the primary value of the excluded bucket. Prefer stable reason codes plus human text. |

### Full-detail fields

| Field | Mark | Feedback |
|---|---|---|
| `context` | USE | Useful on demand for reviewer workflows; do not return it by default. |
| all supporting citations | USE | Keep the schema type consistent between compact and full modes. Prefer a `citations` array in both modes, limited to one item in compact mode. |

## Missing fields

### Response provenance and completeness

| Proposed field | Why it is needed |
|---|---|
| `corpus_version` | Reproduce a result after the daily corpus changes. |
| `generated_at` | Establish when the enrichment result was produced. |
| `request_id` | Operational troubleshooting and audit correlation. |
| `status` | Distinguish `complete`, `partial`, and `failed` responses. |
| `errors` | Report request-level or per-value failures without converting them to `unseen`. |
| `truncated` | State whether request or response limits removed any values or reports. |

### Per-value correlation and normalisation

| Proposed field | Why it is needed |
|---|---|
| `input_index` | Reliably map duplicate or normalised results back to the request. |
| `normalized_value` | Show the value actually used for matching. |
| `normalization_applied` | Record defanging, case folding, URL normalisation, or trailing-dot removal. |
| `reason_code` | Stable machine-readable classification for exclusions and recommendations. |
| `days_since_last_seen` | Operational recency without ambiguity. |
| `source_count` | Distinguish repeated reporting from multiple-source corroboration. |
| `basis` | Separate `publisher_report`, `service_rule`, `benign_registry`, `nvd`, and `kev` conclusions. |

### Skipped values

Add a compact `skipped` bucket for values that were not processed. It should not be merged with `unseen`.

Suggested reasons include:

- `unsupported_type`
- `invalid_value`
- `private_ip`
- `internal_hostname`
- `sensitive_url`
- `request_limit`

Example:

```json
{
  "value": "10.1.2.3",
  "input_index": 7,
  "reason_code": "private_ip",
  "reason": "Private address ranges are not searched in the public-report corpus."
}
```

## Required clarifications

### Citations

The primary promise of this service is citable reporting. A `source_reported` hit should therefore contain at least one citation. Empty citation objects should be reserved for a clearly documented exceptional state or returned as a partial/error condition.

For compact and full modes, use one stable shape:

```json
"citations": [
  {
    "title": "...",
    "url": "https://...",
    "source": "...",
    "report_date": "2026-09-04",
    "report_id": "rpt_8f3c1a"
  }
]
```

Compact mode may return the best citation only. Full mode may return all supporting citations.

### Report counts and source independence

`report_count` is currently described as distinct daily reports. It must not be described as independent reporting unless the reports come from distinct publishers and independence is actually measured.

Please provide both:

- `report_count`: number of distinct reports;
- `source_count`: number of distinct publishers or source organisations.

### Domain relationship matching

Document whether parent/child matching uses the Public Suffix List. Matching must not treat a public suffix or shared-hosting boundary as an ordinary parent domain.

For every non-exact match, return `matched_value`. Consider adding a stable reason when a potentially related domain is suppressed because the boundary is unsafe.

### Known-benign classification

For `benign_listed`, identify the basis of the benign determination. For example:

- public resolver registry;
- publisher-owned infrastructure;
- cloud/vendor allowlist;
- manually reviewed exception.

Return a registry or rule version where possible. A benign classification without provenance can become stale and is difficult to audit.

### CVE semantics

The current CVE example combines three different facts:

1. a CVE was named in published reporting;
2. NVD assigned a score;
3. CISA listed it in KEV.

These should be represented as separate provenance-bearing facts. `source_reported` should mean that a report explicitly named the CVE; NVD and KEV status should not silently create the same verdict.

Recommended shape:

```json
{
  "verdict": "source_reported",
  "reporting": {"report_count": 2, "source_count": 2},
  "vulnerability": {
    "nvd": {"cvss_score": 9.8, "cvss_version": "3.1"},
    "kev": {"listed": true, "due_date": "2026-09-18"}
  }
}
```

## Data handling requirements

Because observables can contain internal or customer-specific information, please document:

- whether request values are logged;
- log retention and deletion periods;
- data residency and subprocessors;
- whether submitted values are used to build or improve the corpus;
- authentication and tenant-isolation guarantees;
- maximum request and response sizes;
- behaviour for URLs containing credentials, query parameters, fragments, email addresses, or tokens.

The service should recommend that callers remove URL credentials, query strings, and fragments unless exact full-URL matching is explicitly required. Private IPs and clearly internal hostnames should be skipped rather than reported as `unseen`.

## Answers to the review questions

### 1. Adjacent intelligence context

We already have vulnerability and endpoint-exposure context. The unique value expected from this tool is published-report provenance, regional source coverage, reasoned exclusion, and citations. It should remain distinct from reputation and behaviour-verdict services.

### 2. Latency and response budget

For a 1-100 value compact request, a useful initial target is:

- p95 response time at or below 3 seconds;
- service success rate at or above 99%;
- explicit partial responses rather than silently missing results;
- compact payload proportional to hits, not to all queried values.

The proposed bare-string `unseen` bucket is appropriate. Please publish measured p50/p95 latency and maximum payload sizes during the pilot.

### 3. Fields that can change an investigation decision

The strongest fields are:

- `verdict`;
- `match` and `matched_value`;
- `last_seen` and proposed `days_since_last_seen`;
- `report_count` and proposed `source_count`;
- `reason`/`basis`;
- verifiable citations.

`priority` and action recommendations are useful only when their derivation is documented and they are not presented as automatically safe.

### 4. Is `excluded` useful?

Yes. Keep it. It can prevent false escalation and provides a defensible reason for not acting on an indicator-shaped value. Add stable `reason_code` values so consumers do not have to parse prose.

### 5. Batch size

A maximum of 100 values is reasonable for a pilot. Please return `input_index`, processed/skipped counts, and `truncated` so callers can safely handle duplicate values and limits. Actual value distributions should be measured during validation rather than assumed.

## Proposed pilot acceptance measures

The pilot should measure:

- percentage of submitted values successfully processed;
- exact `source_reported` hit rate;
- parent-domain, child-domain, and same-host hit rates;
- `benign_listed` and `excluded` rates;
- percentage of citations that are reachable and directly support the matched value;
- percentage of reviewed hits that changed investigation priority, evidence requests, or next actions;
- false escalation or unsafe-block recommendations;
- p50/p95 latency, timeout rate, and compact response size;
- result stability when the same `corpus_version` is queried repeatedly.

Low overall hit rate is acceptable if exact hits are accurate, citable, and materially useful. The following should be hard requirements:

- no failed or skipped lookup may be returned as `unseen`;
- no `unseen` result may be described as clean or benign;
- citations should directly support the reported observable;
- non-exact matches must never be represented as exact;
- no action recommendation should be documented as universally safe to automate.

## Recommendation

Proceed with a limited validation pilot after the following are addressed:

1. response provenance and partial-failure fields;
2. citation completeness;
3. report-count versus source-count semantics;
4. domain-boundary matching rules;
5. known-benign provenance;
6. CVE provenance separation;
7. data-handling and retention documentation;
8. removal of the claim that blocking or escalation is a safe automated consequence of a single report hit.

With those changes, the service could provide useful, auditable external context while keeping publisher reporting clearly separate from an independent judgement of maliciousness.
