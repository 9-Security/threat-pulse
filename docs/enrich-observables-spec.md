# `enrich_observables` — MCP tool specification (v2)

**Status:** revised after review; pending pilot
**Supersedes:** v1
**Changes:** all eight items in the review's Recommendation section, the field
marks, and four disclosures the reviewers could not have known from v1.

---

## Disclosures before the pilot

The reviewers marked fields USE based on v1's descriptions. Four of those
descriptions were stronger than the data supports, or wrong. Correcting them here
rather than letting the pilot discover them. All figures below were produced on
parser revision `1b592d5` unless stated otherwise.

### 1. Corpus history exists but is shallow, and cannot be deepened backwards

The review named `last_seen`, `days_since_last_seen`, `report_count` and
`source_count` among the strongest fields. All four require history.

A durable store does exist. A scheduled CI job runs daily at 22:00 UTC
(06:00 Asia/Taipei), generates the day's report and pushes its confirmed
indicators into D1. **As of 2026-09-07 that store holds four days**, beginning
2026-09-04. The temporal fields are therefore computable, but four days of depth
makes them close to meaningless in practice; `first_seen` for almost every
indicator is simply the day the store began.

The store does **not** hold candidate or rejected rows, article bodies, or
extraction diagnostics — only confirmed indicators and report metadata. The
`excluded` bucket consequently has no history at all, which compounds
Disclosure 2 below.

**History cannot be added retroactively.** Source feeds carry only their most
recent items. Measured two independent ways:

| same 24-hour window | collected near the day | re-collected 3 days later | loss |
|---|---|---|---|
| articles in window | 55 | 25 | 55% |
| unique confirmed indicators | 150 | 93 | 38% |

and, comparing the stored 2026-09-04 report against a re-collection of the same
window on 2026-09-07:

| indicator type | stored | re-collected | loss |
|---|---|---|---|
| cve | 78 | 56 | 28% |
| sha256 | 25 | 11 | 56% |
| ip | 10 | 3 | 70% |
| filename | 29 | 1 | 97% |

Every day the collector does not run is a day permanently absent, and a later run
recovers roughly half of it at best. The practical consequence for the pilot:
depth accrues only forward, at one day per day, so the measurement window should
be scheduled with that in mind rather than assumed to be available on request.

### 2. `excluded` is thinner than v1 implied

v1 presented the excluded bucket as a major differentiator. Measured on a single
day of output, it was 44 rows over 7 unique values, of which 40 rows (91%) were
`publisher_domain` — a publisher's own domain appearing in its own article.

The reason is structural: most false-positive suppression in this pipeline runs
*before* a value becomes an evidence row — TLD validation, file-extension
precedence, version-number rejection, private-address rejection. Those values are
never recorded, so they never become `excluded`. The capability is real; the
*record* of it is not, and only the recorded part can be served.

Making `excluded` as useful as the review expects requires instrumenting those
earlier filters to emit records. That is implementation work, not an existing
asset. The bucket is retained in this specification because the review asked for
it, but its volume should be treated as unproven until measured on current code.

### 3. `source_count` will be 1 for nearly every non-CVE indicator

Measured on the same day: of 150 unique confirmed indicators, 8 were named by
more than one publisher — and all 8 were CVEs. No domain, IP or hash was
corroborated by a second publisher.

This is expected. Publishers republish each other's CVE numbers; they do not
republish each other's C2 infrastructure. `source_count` is therefore a
meaningful signal on the CVE path and close to a constant on the indicator path.

### 4. Corpus yield is small and heavily weighted toward CVEs

Measured across four consecutive daily windows, re-extracted from the stored
article bodies on the current code:

| report date | day | articles | confirmed unique | CVE | domain | ip | sha256 | family | candidate |
|---|---|---|---|---|---|---|---|---|---|
| 2026-09-04 | Fri | 25 | 81 | 56 | 6 | 3 | 11 | 4 | 99 |
| 2026-09-05 | Sat | 38 | 69 | 61 | 3 | 0 | 0 | 0 | 61 |
| 2026-09-06 | Sun | 9 | 9 | 9 | 0 | 0 | 0 | 0 | 24 |
| 2026-09-07 | Mon | 9 | 1 | 1 | 0 | 0 | 0 | 0 | 16 |

Deduplicated across all four days: **119 unique CVEs against 25 unique network
and file indicators** — 9 domains, 3 IPs, 11 SHA-256, 2 MD5.

Two things follow.

**Daily variance is large.** Confirmed unique indicators ranged from 5 to 93
across four days, tracking publisher activity on weekends. No single day is a
usable baseline, and any pilot measurement needs a window spanning both weekdays
and weekends.

**The CVE path carries roughly five times the volume of the indicator path**, and
CVE identifiers are a closed, unambiguous namespace that a consumer's own
vulnerability data already emits. Observable enrichment against 25 indicators
per four days should be expected to hit rarely. The review already accepted a low
hit rate provided exact hits are accurate and citable; these numbers are what
that acceptance will be tested against.

These supersede every earlier figure. They were produced on `66ca089`, after two
corrections that changed what counts as confirmed:

- Malware family apposition ("X ransomware") became a candidate rather than a
  confirmed claim, which is most of the drop in the `confirmed unique` column
  against figures shared earlier in review.
- Registry boundaries are decided by the Public Suffix List.

The boundary change altered nothing on these four days: none of the nine
confirmed domains is itself a public suffix. Six of them, however, sit under
`duckdns.org`, which is one. Under the previous label-length rule a single
article naming the bare registry would have placed it on the block list, so the
exposure was one article away rather than absent.

The next scheduled run is the first produced end to end on this code.

---

## How to review this

Field marks from the previous round are carried forward. New and changed fields
are marked **NEW** or **CHANGED**. The same convention applies: a field the only
real consumer would not read is a field that should not ship.

---

## What this tool is for

An agent triaging an alert has a set of observables — destination IPs, DNS and
proxy hostnames, file hashes, URLs — and has to decide whether to escalate or
close, then justify that decision to a human who may be a client.

`enrich_observables` answers exactly one question:

> **Was this observable explicitly named in published vendor or CERT reporting,
> how was it matched, how recent and repeated was that reporting, and what source
> can be cited?**

It does **not** answer "is this malicious." It has no sandbox, no detonation, no
AV consensus, no passive DNS. It is report provenance and investigation context.
It complements reputation, sandbox, passive DNS, endpoint telemetry and original
alert evidence; it replaces none of them.

The corpus is 26 vendor and CERT publications, including TWCERT/CC, HKCERT and
NICS, which are not consistently represented in Western-oriented sources.

---

## Verdict vocabulary

Four states.

| verdict | meaning | what it justifies |
|---|---|---|
| `source_reported` | A published report explicitly named this value as an indicator. | Investigation, hunting, prioritisation, or a **proposed** control action. |
| `benign_listed` | The value appears in published indicator sections **and** matches a known-benign registry. | Recording the sighting. Never a block. |
| `excluded` | The value was seen and determined not to be an operational indicator. `reason_code` says which rule fired. | Defensible suppression. |
| `unseen` | The value does not appear in the corpus. | Nothing. Not a clean verdict. |

Two states are **not** verdicts and are returned in their own bucket: `skipped`
(not processed) and per-value `errors` (processing failed). Neither is ever
reported as `unseen`.

### No verdict implies a safe automatic action

**CHANGED per review.** v1 described a "safe automated action" per verdict. That
claim is withdrawn.

A value being named in a published report can justify investigation, hunting,
prioritisation, or a proposed control action. By itself it is never sufficient to
guarantee that blocking or escalation is safe in a given environment. The
consumer must apply its own policy before acting.

`suggested_action` is accordingly renamed `suggested_investigation_action`.

### Why not `confirmed`

The internal pipeline uses `confirmed` to mean *"the publisher explicitly claimed
this."* It is not an independent judgement of maliciousness. A model reading a
field called `confirmed` anchors on "confirmed malicious" regardless of
documentation. `source_reported` states the provenance in the name.

### Why `benign_listed` is separate

`8.8.8.8`, `1.1.1.1` and `dns.google` genuinely appear in the indicator tables of
real threat reports. A consumer that blocks them takes out DNS resolution.

---

## Request

```
enrich_observables(
  values: list[str],          # 1..100 raw observables, any mix of types
  types:  list[str] | None,   # optional per-value hint, same length as values
  detail: "compact" | "full" = "compact",
  since:  str | None = None,  # YYYY-MM-DD, ignore reports older than this
)
```

- **No `date` parameter.** The corpus arrives in daily batches; that is an
  implementation detail an enriching agent does not know and should not supply.
- **Type is inferred**, not required. `types` narrows matching; it is never
  mandatory.
- Values are matched case-insensitively. Defanged input (`evil[.]com`, `hxxp://`)
  is accepted and normalised, and the normalisation is reported back.
- Duplicate values are permitted; results carry `input_index` so the caller can
  map them back.

### Caller guidance on sensitive input

Callers should strip credentials, query strings and fragments from URLs unless
exact full-URL matching is required. Private addresses and clearly internal
hostnames are returned in `skipped`, not searched and not reported as `unseen`.

---

## Response

```json
{
  "status": "complete",
  "request_id": "req_01JD8...",
  "generated_at": "2026-09-07T04:12:33Z",
  "corpus_version": "2026-09-07.1",
  "truncated": false,

  "coverage": {
    "report_range": ["2026-03-01", "2026-09-06"],
    "report_count": 189,
    "source_count": 26,
    "scope": "Published vendor and CERT reporting only. No passive DNS, no sandbox, no AV consensus, no reputation scoring.",
    "verdict_note": "verdict states what a publisher reported. suggested_investigation_action and priority are this service's own analysis and are not safe to automate without consumer policy.",
    "absence_note": "unseen means the value is not named in this corpus. It is not a clean or benign verdict and must not be treated as one."
  },

  "counts": {
    "requested": 42,
    "processed": 38,
    "skipped": 4,
    "failed": 0
  },

  "hits": [
    {
      "input_index": 3,
      "value": "downloading-api.it.com",
      "normalized_value": "downloading-api.it.com",
      "normalization_applied": ["case_fold"],
      "type": "domain",
      "verdict": "source_reported",
      "basis": "publisher_report",
      "match": "exact",
      "first_seen": "2026-08-29",
      "last_seen": "2026-09-04",
      "days_since_last_seen": 3,
      "report_count": 3,
      "source_count": 2,
      "suggested_investigation_action": "block",
      "priority": "high",
      "reason_code": "explicit_ioc_section",
      "reason": "Named in the indicator section of 3 reports from 2 publishers as staging infrastructure.",
      "citations": [
        {
          "title": "TerminalFix campaign deploys a reverse tunnel through multistage intrusion",
          "url": "https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign/",
          "source": "microsoft-security",
          "report_date": "2026-09-04",
          "report_id": "rpt_8f3c1a"
        }
      ]
    },
    {
      "input_index": 5,
      "value": "sub.evil.example",
      "normalized_value": "sub.evil.example",
      "normalization_applied": [],
      "type": "domain",
      "verdict": "source_reported",
      "basis": "publisher_report",
      "match": "parent_domain",
      "matched_value": "evil.example",
      "match_boundary": "registrable_domain",
      "last_seen": "2026-07-11",
      "days_since_last_seen": 58,
      "report_count": 1,
      "source_count": 1,
      "suggested_investigation_action": "hunt",
      "priority": "medium",
      "reason_code": "parent_domain_match",
      "reason": "Parent domain named as C2. The queried host itself was not reported.",
      "citations": [{ "…": "…" }]
    },
    {
      "input_index": 8,
      "value": "8.8.8.8",
      "type": "ip",
      "verdict": "benign_listed",
      "basis": "public_resolver_registry",
      "benign_registry_version": "2026-09-01",
      "match": "exact",
      "suggested_investigation_action": "none",
      "reason_code": "public_dns_resolver",
      "reason": "Appears in published indicator sections but is a public recursive resolver. Do not block.",
      "citations": [{ "…": "…" }]
    },
    {
      "input_index": 11,
      "value": "CVE-2026-3184",
      "type": "cve",
      "verdict": "source_reported",
      "basis": "publisher_report",
      "match": "exact",
      "last_seen": "2026-09-06",
      "days_since_last_seen": 1,
      "reporting": { "report_count": 2, "source_count": 2 },
      "vulnerability": {
        "nvd": {
          "cvss_score": 9.8,
          "cvss_severity": "CRITICAL",
          "cvss_version": "3.1",
          "basis": "nvd",
          "retrieved_at": "2026-09-06T22:04:11Z"
        },
        "kev": {
          "listed": true,
          "due_date": "2026-09-18",
          "basis": "kev",
          "retrieved_at": "2026-09-06T22:03:58Z"
        }
      },
      "suggested_investigation_action": "patch",
      "priority": "high",
      "reason_code": "kev_listed",
      "reason": "KEV listed, CISA due 2026-09-18; CVSS 9.8 CRITICAL (NVD 3.1).",
      "citations": [{ "…": "…" }]
    }
  ],

  "excluded": [
    {
      "input_index": 14,
      "value": "out.tmp",
      "type": "filename",
      "reason_code": "filename_not_domain",
      "reason": "Named as a file on the source line and the final label is not a delegated TLD. Recorded as a filename, not a domain."
    },
    {
      "input_index": 21,
      "value": "www.bleepingcomputer.com",
      "type": "domain",
      "reason_code": "publisher_domain",
      "reason": "The publishing outlet's own domain."
    }
  ],

  "skipped": [
    {
      "input_index": 7,
      "value": "10.1.2.3",
      "reason_code": "private_ip",
      "reason": "Private address ranges are not searched in the public-report corpus."
    }
  ],

  "errors": [],

  "unseen": ["203.0.113.9", "d41d8cd98f00b204e9800998ecf8427e"]
}
```

### Bucket rules

- `unseen` returns bare strings. In a real alert stream most observables land
  here; returning a full object for each is the fastest way to exceed an agent's
  token budget.
- **A failed or skipped lookup is never returned as `unseen`.** This is a hard
  requirement from the review and is enforced by giving each its own bucket.
- `excluded` is a reasoned negative, not a weak positive.

---

## Field reference

### Response-level — all NEW

| field | notes |
|---|---|
| `status` | `complete`, `partial`, `failed`. `partial` whenever any value failed. |
| `request_id` | Troubleshooting and audit correlation. |
| `generated_at` | When the enrichment result was produced. |
| `corpus_version` | Identifies the corpus state; the same version must reproduce the same result. |
| `truncated` | True if request or response limits dropped any value or citation. |
| `counts` | `requested` / `processed` / `skipped` / `failed`, which can differ. |
| `errors` | Per-value failures. Never collapsed into `unseen`. |

### `coverage`

| field | notes |
|---|---|
| `report_range` | Required to interpret `unseen`. |
| `report_count` | **Daily report batches**, not documents and not articles. |
| `source_count` | **CHANGED** — renamed from `sources`; it is an integer. |
| `scope` | Guardrail against over-interpretation. |
| `verdict_note` | Separates publisher claims from service analysis; machine-stable text. |
| `absence_note` | `unseen` never implies clean or benign. |

### Hit object

| field | notes |
|---|---|
| `input_index` | **NEW** — maps results to request positions, including duplicates. |
| `value` | The queried value, verbatim. |
| `normalized_value` | **NEW** — the value actually used for matching. |
| `normalization_applied` | **NEW** — `defang`, `case_fold`, `url_normalize`, `trailing_dot`. |
| `type` | `domain` / `ip` / `url` / `md5` / `sha1` / `sha256` / `cve` / `filename` |
| `verdict` | `source_reported` or `benign_listed`. |
| `basis` | **NEW** — `publisher_report`, `service_rule`, `benign_registry`, `nvd`, `kev`. |
| `match` | `exact`, `parent_domain`, `child_domain`, `same_host`. Never a boolean. |
| `matched_value` | Required whenever `match` is not `exact`. |
| `match_boundary` | **NEW** — which boundary the relation was computed against. |
| `first_seen` / `last_seen` | `last_seen` is the operational one. |
| `days_since_last_seen` | **CHANGED** — replaces `age_days`, which the review marked IGNORE for being anchored on `first_seen`. |
| `report_count` | Distinct daily reports. **Not** a corroboration claim. |
| `source_count` | **NEW** — distinct publishers. This is the corroboration measure. |
| `suggested_investigation_action` | **CHANGED** — renamed. `patch` / `block` / `hunt` / `monitor` / `none`. Service analysis, not a safe automatic consequence. |
| `priority` | Intelligence priority, **not case severity**. Derivation below. |
| `reason_code` | **NEW** — stable machine-readable classification. |
| `reason` | One sentence; states whether the basis is publisher reporting or service analysis. |
| `citations` | Array in both modes. Compact returns the best one; full returns all. |
| `reporting` / `vulnerability` | CVE only; see CVE semantics. |

### Excluded and skipped objects

| field | notes |
|---|---|
| `input_index` | Correlates the suppression with the request. |
| `value`, `type` | Type matters most for filename/domain ambiguity. |
| `reason_code` | **NEW** — stable code so consumers never parse prose. |
| `reason` | Human text alongside the code. |

Skipped reason codes: `unsupported_type`, `invalid_value`, `private_ip`,
`internal_hostname`, `sensitive_url`, `request_limit`.

---

## Required clarifications, answered

### Citations

A `source_reported` hit always carries at least one citation. If a citation
cannot be produced, the value is returned in `errors` with `status: "partial"` —
never as a hit with an empty citation object. `citations` is an array in both
compact and full mode; compact returns the single best citation.

Citation URLs point at the supporting report, never at a search page.

### `report_count` versus `source_count`

`report_count` counts distinct daily report batches. It is **not** described as
independent corroboration anywhere in the response. `source_count` counts
distinct publishers and is the only field that carries a corroboration meaning.

See Disclosure 3: on the indicator path this will almost always be 1.

### Domain relationship matching

**The Public Suffix List is now used on both sides.** The previous rule was a
heuristic — a two-label parent whose left label was three characters or shorter
(`it.com`) was demoted, a longer one (`download-app.us`) was not. It caught
`it.com` by accident and missed `github.io`, `gitlab.io` and `duckdns.org`
entirely, all of which have longer left labels and all of which are registry
boundaries. It also would have demoted `squarespace.com`, which reads like a
platform but is an ordinary registrable domain.

Two things changed:

- **Report generation.** A name that is itself a public suffix is never placed on
  the block list, however it appears in an article and whether or not a
  subdomain accompanies it. It is demoted to hunt with a reason naming the
  boundary. Subdomains beneath it stay blockable — the tenant is not the
  registry.
- **Query matching.** Parent candidates stop at the registrable domain. The
  previous implementation walked down to any two-label pair, producing `co.uk`
  and `github.io` as lookup keys; a report naming either would then have matched
  every unrelated tenant beneath it.

Both read the same bundled list, generated into the Worker from the file the
Python package ships, so the boundary a report was written against cannot drift
from the boundary a query is matched against.

Every non-exact match returns `matched_value`, and `match_boundary` names the
rule that produced the relation.

### Known-benign provenance

Three distinct rules exist today, each with its own basis:

| `basis` | source |
|---|---|
| `public_resolver_registry` | Public DNS resolver addresses and hostnames |
| `vendor_brand_apex` | Brand apex domains, matched as apex or subdomain |
| `domain_boundary_rule` | Parent domain too broad relative to a reported subdomain |

Each is now versioned. `benign_registry_version` is a digest over the contents
of all three sets plus the public suffix rule counts, recorded on every report as
`analyst_brief.benign_registry_version`.

It is derived rather than hand-maintained deliberately: a manual version number
goes stale the first time someone adds an entry without bumping it, and a stale
benign classification is precisely the unauditable case the review described. A
content digest changes when, and only when, a decision would change.

### CVE semantics

Three facts are now separate, each carrying its own basis and retrieval time:

1. `verdict: source_reported` — a report explicitly named the CVE
2. `vulnerability.nvd` — NVD scoring, with `cvss_version`
3. `vulnerability.kev` — CISA KEV listing

NVD or KEV presence never creates a `source_reported` verdict on its own.

### `priority` derivation

Deterministic, in order: KEV listing, then the higher of NVD and article CVSS,
then explicit impact wording in the source, then CISA due date. The response
states which input decided it via `reason_code` and `reason`. This is
intelligence priority for triage ordering, not case severity.

---

## Detail levels and token budget

`detail: "compact"` (default) omits `context` and returns one citation per hit.

Target: **under 40 tokens per hit, under 5 per unseen value**; payload
proportional to hits, not to all queried values.

`detail: "full"` adds `context` — a verbatim source sentence capped at 300
characters — and every supporting citation. It requires a token holding the
`context` scope, because that text belongs to the publisher.

Service targets to be measured and published during the pilot: p95 at or below
3 seconds for a 1–100 value compact request, success rate at or above 99%,
explicit partial responses rather than silently missing results, and measured
p50/p95 latency and maximum payload size.

Values are returned **undefanged**. Machine consumers need the real value; a
consumer rendering results for human clicking must defang at that boundary.

---

## Data handling

To be published as a written policy before the pilot. The commitments the design
already implies:

- Requests carry customer-derived observables and are treated as customer data.
- Private addresses and internal hostnames are skipped, not searched, not logged
  as corpus input.
- Submitted values are **not** used to build or improve the corpus.
- Authentication is a per-client bearer token; only its SHA-256 is stored, and
  tokens are revocable individually.

Still to be decided and documented: whether request values are logged at all,
retention and deletion periods, data residency and subprocessors, tenant
isolation guarantees, and maximum request and response sizes.

---

## Prerequisites before the pilot

From the review's Recommendation, plus what the disclosures add.

| # | item | status |
|---|---|---|
| 1 | Response provenance and partial-failure fields | specified above |
| 2 | Citation completeness | specified above |
| 3 | `report_count` vs `source_count` semantics | specified; see Disclosure 3 |
| 4 | Domain-boundary matching via PSL | done, both sides |
| 5 | Known-benign provenance and versioning | done |
| 6 | CVE provenance separation | specified above |
| 7 | Data handling and retention documentation | partially answered above |
| 8 | Remove "safe to automate" claim | done throughout |
| 9 | **Corpus depth** | store running since 2026-09-04; accrues 1 day/day |
| 10 | Restate measurements on current parser revision | done; see Disclosure 4 |

Items 9 and 10 are not in the review because the reviewers could not have known
about them. Item 9 is not an engineering task — the collector already runs daily
and pushes to the store. It is a scheduling constraint: four of the fields the
review rated strongest need depth the corpus can only accumulate forward, so the
pilot window should be set against the depth that will exist by then.

---

## What happens next, and what it waits on

**Items 1, 2 and 6 are deliberately not built yet.** Response provenance fields,
citation completeness and CVE provenance separation are all shape decisions
inside `enrich_observables`, and their right shape depends on answers the pilot
produces rather than on anything decidable here. The review's acceptance
measures name decision-change rate and citation reachability; if the fields that
change a decision turn out to be `verdict` and `suggested_investigation_action`
alone, the response should be materially smaller than what this document
drafts. Building it first and trimming afterwards costs more than waiting, and
the difference is a scheduling conversation, not a technical one.

**Item 7 is the one piece of work blocked on nobody.** A written data-handling
policy — request logging, retention, residency, subprocessors, tenant isolation
— is procurement's first question and is being drafted independently of the
pilot.

**Item 9 sets the earliest useful pilot date.** Depth accrues one day per day and
cannot be backfilled. A measurement window that reports `last_seen`,
`days_since_last_seen`, `report_count` and `source_count` as anything other than
"the day the store began" needs the store to be materially older than the values
being queried.

### The open question this document does not settle

Disclosure 4 puts the CVE path at roughly five times the volume of the indicator
path, on a namespace that is closed, unambiguous, and already emitted by the
consumer's own vulnerability tooling. `enrich_observables` is specified here
because the review asked for it and validated its shape. Whether it, or a
CVE-centred tool beside it, is the one that earns its place is a question the
pilot's decision-change measurements should answer rather than this
specification.

Both read the same corpus. Nothing in the work below the interface has to be
decided before that answer arrives.
