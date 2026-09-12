# Response: alert-stream coverage validation

**Date:** 2026-09-12  
**Subject:** Proceed with a bounded file-based validation before an endpoint pilot

Thank you for running the backtest first and for reporting the zero-hit result
directly. We agree with the distinction in your note: recurrence within a
published-report corpus is not the same measurement as coverage of our alert
stream.

The result does change our prior. The network-observable path should now be
treated as a low-probability hypothesis that must earn a pilot. The CVE path is
more promising, but our platform already maintains local NVD, CVSS, EPSS, CISA
KEV, and MSRC enrichment. Its incremental value would therefore need to come
from publisher context, independent source corroboration, and useful citations,
not from repeating those public scores.

## Decision

We are willing to proceed with the requested **file-based corpus coverage
validation**. This is not yet approval for endpoint integration or production
data flow.

We will prepare a bounded, deduplicated sample from recently closed cases,
subject to our internal data-sharing review. The initial target will be 300 to
1,000 processed values, with separate populations for:

- public domains;
- public IP addresses;
- MD5 and SHA-256 hashes; and
- CVE identifiers.

We will not include customer identifiers, case or ticket identifiers, alert
text, usernames, internal hostnames, private/reserved IP addresses, secrets, or
live unresolved indicators. Full URLs will be excluded from the first sample
because paths and query strings can contain tenant or authentication data. We
may add safely normalized URLs in a later validation if domains alone show
useful coverage.

Case closure does not imply that an indicator is benign. We will retain any
analyst disposition and case linkage locally so that your service receives only
the minimum values needed for lookup.

## Transfer prerequisites

Before we provide the sample, please send:

1. The secure upload or transfer method and the authorized recipient.
2. The applicable retention period and deletion procedure for both the input
   file and generated result.
3. Confirmation that submitted values will not be used for model training,
   added to a shared corpus, or disclosed to another customer or third party.
4. Confirmation of where the data is processed and stored.
5. The revised `docs/enrich-observables-spec.md` and
   `docs/data-handling.md` versions that apply to this validation.

If you can provide a container or command-line validator that runs locally and
contacts only the corpus lookup endpoint, we would prefer that option over
transferring a file.

## Input format

Please confirm that the following CSV is accepted:

```csv
value,type,sample_id
evil.example.com,domain,S000001
203.0.113.10,ip,S000002
d41d8cd98f00b204e9800998ecf8427e,md5,S000003
CVE-2026-1234,cve,S000004
```

`sample_id` will be randomly generated and will not encode tenant, case, host,
or time information. If your current importer requires only the first column,
the proposed layout preserves `value` as that first column.

## Required result fields

Please return one row for every submitted row, including skipped and failed
items, with at least:

- `sample_id` and original value;
- detected or supplied type;
- normalized value;
- status: `hit`, `miss`, `skipped`, or `error`;
- exclusion/error reason;
- match method: `exact`, `parent_domain`, or `same_host`;
- matched corpus value;
- report count and independent source count, using the revised semantics;
- source/report publication date;
- citation URL and publisher for every hit;
- KEV, CVSS, and EPSS fields for CVEs, including provenance and data version;
- request-level source failures and corpus coverage timestamp.

The denominator for each reported hit rate must be the number actually
processed, while submitted, skipped, and errored counts remain visible.
Metrics must be reported separately by observable type; a combined rate would
hide the expected difference between CVEs and network indicators.

## Interpretation and stopping rule

Because the current corpus has limited depth and the file contains no alert
timestamps, this exercise measures **current-corpus coverage**, not what the
service would have known at the time of each alert. Results must not be
described as prospective detection performance or decision impact.

We propose the following decision rule:

- Network coverage at or below 1%, with no clearly actionable supported hit:
  stop the network-observable integration path.
- Network coverage between 1% and 5%: manually review all hits before deciding
  whether a live pilot is justified.
- Network coverage above 5%: review a stratified sample of hits for citation
  support and potential decision impact before a bounded endpoint pilot.
- CVE coverage: assess separately against our existing local enrichment. A hit
  is incrementally useful only if it adds defensible publisher context,
  independent corroboration, or remediation evidence that we do not already
  have.

No hit-rate threshold alone authorizes automation. Any later endpoint pilot
must still measure latency, payload size, partial-source failure behavior,
citation reachability/support, and analyst decision-change rate.

## Next step

Once the five transfer prerequisites are answered and we confirm the revised
specification, we can prepare the bounded sample. Please do not begin endpoint
integration work on our behalf until this coverage result has been reviewed.
