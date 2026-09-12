# Corpus coverage validator

Matches a list of observables against a snapshot of the threat-pulse corpus and
reports, per observable type, how many were named in published reporting.

**It runs entirely on your machine.** There is no endpoint, no upload, no
telemetry, and no network call of any kind. The corpus travels to you in
`corpus-snapshot.json`; your values never leave. `validate.py` imports only the
Python standard library and touches only the files you name on the command line
— it is one file, and it is meant to be read before it is run.

Requires Python 3.9 or later. No installation.

```bash
python3 validate.py --input observables.csv --output results.csv --summary summary.json
```

## Input

```csv
value,type,sample_id
evil.example.com,domain,S000001
203.0.113.10,ip,S000002
d41d8cd98f00b204e9800998ecf8427e,md5,S000003
CVE-2026-1234,cve,S000004
```

`type` and `sample_id` are optional; a plain one-value-per-line file works too.
When `type` is absent it is detected from the value's shape. When it is present
and disagrees with detection, both are reported in `type_supplied` and
`type_detected`, a `type_mismatch` note is added to `reason`, and the supplied
type is used. A disagreement is a finding, not something to resolve silently.

Do not send internal hostnames, private or reserved addresses, or live
unresolved indicators. The validator skips them and says so, but the safest
handling is not to put them in the file.

## Output

One row per submitted row, in `results.csv`, with `sample_id` preserved so you
can rejoin to your own records. `status` is one of:

| status | meaning |
|---|---|
| `hit` | a publisher named this value, and the row carries the citation |
| `miss` | this corpus, over the days it covers, does not name it |
| `excluded` | the pipeline saw it and ruled it out; `reason` gives the codes |
| `skipped` | not looked up at all; `reason` says why |
| `error` | the row could not be processed |

**`skipped` is never reported as `miss`.** A private address or an internal
hostname cannot appear in a corpus of published reporting, so answering "not
found" for one would be answering a question that was never asked. Skipped rows
are excluded from every denominator.

**`miss` is not a judgement that the value is benign.** It means this corpus,
over the days it covers, does not name it. Nothing more.

### Match methods

Only these three count toward the headline rate:

| method | relation |
|---|---|
| `exact` | the normalized values are identical |
| `parent_domain` | the submitted host is beneath a domain the corpus named |
| `same_host` | a submitted URL's host is a value the corpus named |

Parent matching **stops at the registrable domain**, using the Public Suffix
List embedded in the snapshot — the same list, by content digest, that the
reports were written against. `a.b.evil.com` finds `evil.com`; nothing finds
`co.uk` or `github.io`, because a registry belongs to no one and matching there
would tie unrelated tenants together.

A fourth relation is computed and reported separately:

| method | relation |
|---|---|
| `child_domain` | the corpus named something *beneath* the submitted domain |

It is real but weaker — submitting `example.com` and learning that
`cdn.example.com` was reported is not the same as `example.com` being reported.
It is **deliberately excluded from the headline rate**, because the decision
thresholds in your review were written against the three relations above, and
widening the definition would move the number against a rule set for something
narrower. `summary.json` carries both: `hit_rate` and
`hit_rate_including_child_domain`.

### Columns

`sample_id`, `value`, `type_supplied`, `type_detected`, `type_used`,
`normalized_value`, `status`, `reason`, `match_method`, `matched_value`,
`report_count`, `source_count`, `first_seen`, `last_seen`, `publication_date`,
`citation_url`, `citation_publisher`, `citation_count`, `action`, `priority`,
`benign_basis`, `kev`, `kev_due_date`, `cvss_score`, `cvss_severity`,
`cvss_version`, `epss_score`, `epss_percentile`, `epss_date`, `cve_provenance`,
`cve_observed_on`.

- `report_count` — how many distinct daily reports named the value.
- `source_count` — how many distinct publishers named it. Expect `1` for almost
  every network indicator: publishers republish each other's CVE numbers, not
  each other's C2 infrastructure.
- `publication_date` — when the article was published, not when we collected it.
- `cve_provenance` — the URLs the KEV/CVSS/EPSS record was retrieved from, so a
  score can be traced rather than taken on trust.

## Rates

`summary.json` reports every rate **per observable type**, with the denominator
being values actually processed. Submitted, skipped, excluded and errored counts
stay visible beside it, so no number is reachable only by subtraction.

`network_combined` covers domain, ip, url and hash types together. CVEs are
never folded into it: the two populations behave differently, and a combined
rate would hide exactly the difference this exercise is measuring.

## What this measures, and what it does not

This is **current-corpus coverage**. The corpus holds only the days it has
collected, and the input carries no alert timestamps, so this cannot say what
the service would have known at the time of each alert.

It is **not** detection performance and **not** decision impact. A hit means a
publisher named the value and here is the citation. Whether that would have
changed an investigation is a judgement only an analyst reading the hits against
the original alerts can make.

Citations are checked for existence, not reachability: the validator does not
open them, because it does not open anything.

## Reproducibility

`corpus_version` appears in `summary.json` and identifies the corpus state. The
same version over the same input produces the same result — it is a digest of
the values, counts, citations, excluded set and boundary rules, and deliberately
not of the time the snapshot was built.

`days_with_source_failures` lists any day in the window where a source could not
be read. A value absent because its publisher was unreachable that day is not
the same as a value nobody reported, and this is what says which days had a gap.

## What is in the snapshot

Confirmed indicators and CVE identifiers, with the publisher, article title,
article URL and publication date for each; the KEV/CVSS/EPSS record for each CVE
with its retrieval provenance; the excluded values and their reason codes; the
per-day source-failure record; and the Public Suffix List rules.

Article bodies are **not** included. They are 26 publishers' text, several under
redistribution terms, and no match needs them.
