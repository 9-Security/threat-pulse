# Backtest results, and a request before we build

**Date:** 2026-09-12
**Subject:** measured corpus coverage, and the one input we need from you

Your review of `enrich_observables` set eight conditions and said you would
proceed with a limited validation pilot once they were addressed. All eight are
now addressed — the status table is at the end of this note.

Before asking you to spend pilot time, we ran our own backtest. One of the two
numbers is bad, and we would rather you heard it from us first.

---

## What we measured

We took every confirmed indicator from one day's report and looked it up against
the corpus built from the preceding days. The question that answers is: **does
published reporting repeat its own indicators across days?**

| input (2026-09-11) | submitted | hits | hit rate |
|---|---|---|---|
| network observables (domain, IP, hash) | 72 | **0** | **0.00%** |
| CVE ids | 299 | 23 | 7.69% |

Of the 23 CVE hits: 14 are in CISA KEV, 22 carry a CVSS score, and 13 were named
by more than one publisher independently.

A separate longitudinal count over a larger window agrees: network indicators
recur on **5 of 293 days (1.7%)**; CVE ids recur on **284 of 1,630 (17%)**.

## What that does and does not mean

It is a structural property of published-report feeds, not a defect and not
something more corpus depth will fix. Domains and IP addresses named in vendor
reporting are burned by the act of publication — the infrastructure moves. CVE
identifiers persist and are re-reported.

**But it is not the measurement you need.** We measured whether the corpus
predicts *tomorrow's published indicators*. Your question is whether it covers
*your alert stream* — and those are not the same population. Your alerts may
contain commodity or long-lived infrastructure that published reporting names
repeatedly, which our test would not surface.

We think 0% is a strong negative signal for the observable path. We do not think
it is conclusive, and we are not willing to present it as if it were.

## The request

One file would settle it. From recent closed alerts:

```
value
evil.example.com
203.0.113.10
d41d8cd98f00b204e9800998ecf8427e
CVE-2026-1234
```

One value per line, or a CSV whose first column is the value. Mixed types are
fine; we split them. What is useful:

- **observables** — domains, IPs, URLs, MD5/SHA-256 hashes;
- **CVE ids** — from vulnerability findings or alert enrichment;
- roughly **200–2,000 values**, drawn from alerts you have already closed, so
  nothing is live.

No timestamps, no customer identifiers, no alert text, no internal hostnames or
private addresses — our tooling skips those and reports them as skipped rather
than as "not found", but the safest handling is not to send them at all.

We return: per-value hit or miss, how each hit matched (exact, parent domain,
same host), the citation for each hit, the excluded values with the reason each
was excluded, and the hit rate computed over values actually processed rather
than values submitted.

## What we still cannot measure, with or without that file

- **Decision-change rate** — the measure your review called the one that
  matters. It needs an analyst reading the hits against the original alerts. We
  can produce the hit list; we cannot score it.
- **Citation reachability and support** — we verify a citation exists, not that
  the link resolves or that the sentence supports the value.
- **Latency and payload size** — properties of the served endpoint, to be
  measured during the pilot, not of the corpus.

## Corpus state

| | |
|---|---|
| days held | 9 (2026-09-04 → 2026-09-12) |
| confirmed values | 3,023 |
| — CVE | 2,560 |
| — network indicators | 463 |
| sources | 26 configured, all answering as of today |

Depth accrues one day per day and **cannot be backfilled** — the feeds carry
only their most recent items, so a day not collected is gone. The pilot window
should be set against the depth that will exist by then, not today's.

Since the review, CVE records also carry **EPSS** (exploitation probability and
percentile) alongside KEV and CVSS, and the patch list is ranked by it rather
than by severity alone.

## Status of the eight conditions from your review

| # | item | status |
|---|---|---|
| 1 | Response provenance and partial-failure fields | specified |
| 2 | Citation completeness | specified |
| 3 | `report_count` vs `source_count` semantics | specified |
| 4 | Domain-boundary matching via Public Suffix List | implemented, both sides |
| 5 | Known-benign provenance and versioning | implemented |
| 6 | CVE provenance separation | specified |
| 7 | Data handling and retention documentation | written (`docs/data-handling.md`) |
| 8 | "Safe to automate" claim removed | done throughout |

The revised specification is `docs/enrich-observables-spec.md`.

## What we are asking

Not for pilot time yet. Just the file. If your stream returns something close to
0% as well, that decides the observable path before either side spends a pilot
on it — and the CVE path, which is where the measurement points, is worth
talking about on its own terms.
