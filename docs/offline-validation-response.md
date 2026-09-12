# Response: offline validation, no transfer required

**Date:** 2026-09-12
**Subject:** answers to the five transfer prerequisites, and the validator you asked for

You asked whether we could provide a validator that runs locally and contacts
only our lookup endpoint. We can do better than that: **the corpus travels to
you, and nothing travels back.** There is no endpoint to call, no file to
upload, and no sample to prepare for transfer.

That removes the premise of four of your five prerequisites rather than
answering them, which we think is the better outcome for both sides.

---

## 1. Secure upload method and authorized recipient

**Not required.** We are not requesting your sample. The bundle we send contains
the corpus and the validator; you run it against your own file on your own
machine. Nothing is returned to us unless you choose to share the result.

We would like to see the summary — the per-type rates, not the values — but that
is your decision after you have read it, not a condition of the exercise.

## 2. Retention period and deletion procedure

**We hold nothing to retain.** Your input file, the per-row results and the
summary are all written by a process on your machine, to paths you name. They
never exist on our side.

The bundle itself is yours; there is nothing for us to delete.

## 3. No model training, no shared corpus, no third-party disclosure

We confirm all three. The confirmation is stronger than a policy statement in
this case: we do not receive the values, so there is nothing to train on, add,
or disclose. No process of ours ever sees them.

## 4. Where data is processed and stored

**Your data: on your machine only.** `validate.py` imports only the Python
standard library and opens only the files named on its command line. It makes no
network call of any kind. It is a single readable file, deliberately, so your
team can confirm that before running it rather than taking our word for it.

For completeness, since it bears on any later endpoint pilot: our corpus service
runs on Cloudflare Workers with a D1 database whose primary region is **APAC**,
read replication disabled. It writes no query values to storage and logs none —
the only per-request record is a call counter and last-used timestamp against the
API token. Full article bodies never leave the collecting host at all. None of
this is exercised by the offline validation.

## 5. Applicable specification versions

- `docs/enrich-observables-spec.md` — the revision addressing all eight items
  from your review.
- `docs/data-handling.md` — retention and handling.
- `tools/corpus-validator/README.md` — ships inside the bundle and governs this
  exercise specifically.

---

## Input format: confirmed

Your proposed CSV is accepted exactly as written.

```csv
value,type,sample_id
evil.example.com,domain,S000001
203.0.113.10,ip,S000002
d41d8cd98f00b204e9800998ecf8427e,md5,S000003
CVE-2026-1234,cve,S000004
```

`type` and `sample_id` are both optional; a bare one-value-per-line file also
works. `sample_id` is carried through to every output row unmodified so you can
rejoin to your own records. Where a supplied `type` disagrees with the type
detected from the value's shape, both are reported and the supplied one is used
— a disagreement is a finding, not something to resolve silently.

Excluding full URLs from the first sample is sensible and costs nothing; the
validator supports them if a later sample includes normalized ones.

## Result fields

Every field on your list is produced, one row per submitted row, including
skipped and errored items. The full column list is in the bundle's README. Three
points where we made a decision you should know about:

**Match methods.** `exact`, `parent_domain` and `same_host` are as you
enumerated, and parent matching stops at the registrable domain using the Public
Suffix List embedded in the snapshot — the same list, by content digest, the
reports were written against.

We also compute a fourth relation, `child_domain`: the corpus named something
*beneath* the value you submitted. It is real but weaker, and it is **kept out of
the headline rate** because your decision thresholds were written against the
three relations above. Widening the definition would move the number against a
rule set for something narrower. Both figures appear in the summary:
`hit_rate` and `hit_rate_including_child_domain`.

**`source_count` above 1 is not evidence of independent corroboration, and on
the network path it never has been.** Over the nine days, 9 of 305 network
indicators carry more than one publisher. Every one of the nine is the same
shape: an aggregator (`Cyber Security News`) carrying an original researcher's
report (`Securelist by Kaspersky`, five; `Microsoft Security Blog`, four). That
is republication, not two parties independently finding the same infrastructure.

We could have let the field read as corroboration and said nothing. Instead the
results now carry a `publishers` column listing every name, so you can judge
independence yourself rather than trusting a count — and the bundle's README says
this outright.

On the CVE path the counts are larger and more meaningful: 300 of 1,671 CVEs
were named by more than one publisher, with a long tail up to ten. Whether that
is worth anything to you given your existing enrichment is your call, not ours.

**Source failures travel with the corpus.** `days_with_source_failures` in the
summary lists any day in the window where a publisher could not be read. A value
absent because its source was unreachable that day is not a value nobody
reported, and nothing else in the output would distinguish the two.

You should know the number before you see it: **7 of the 9 days carry at least
one failed source.** Most are single-day timeouts, but CISA's advisory feed
returned 403 on four consecutive days (2026-09-04 to 09-07) and its advisories
are absent from those four reports. We found this while preparing your sample
and have since added an alert for a source that fails on consecutive runs; the
gap in those four days cannot be backfilled.

## Rates and interpretation

Denominators are values actually processed. Submitted, skipped, excluded and
errored counts stay visible beside every rate, so no figure is reachable only by
subtraction. Rates are reported **per observable type**; CVEs are never folded
into the network figure.

We have adopted your framing verbatim in the tool's own output: it measures
current-corpus coverage, not what the service would have known at the time of
each alert, and it is neither detection performance nor decision impact. The
summary file says so itself, so the caveat cannot be separated from the number.

Your stopping rule needs no input from us. We would only add that on the CVE
path, given you already run NVD, CVSS, EPSS, KEV and MSRC locally, the fields
worth assessing are `source_count`, `citation_url`, `citation_publisher` and
`publication_date` — publisher context and corroboration. The scores we return
are the same public ones you already hold, and we do not claim incremental value
there.

## Corpus state

| | |
|---|---|
| days | 9 (2026-09-04 → 2026-09-12) |
| unique confirmed values | 1,976 |
| — CVE | 1,671 |
| — network indicators | 305 (domain 182, sha256 61, url 21, ip 19, md5 17, sha1 5) |
| excluded values | 29 |
| CVE intel records | 1,655 |
| sources | 26 configured |
| corpus_version | `2026-09-12.8a4b49478adb` |

An earlier note of ours quoted 3,023 confirmed values. That figure counted
occurrences across days, not distinct values; 1,976 is the number the validator
will agree with. The correction is downward and ours to make before you find it.

Depth accrues one day per day and cannot be backfilled. A snapshot built later
covers more days; `corpus_version` identifies exactly which corpus produced a
given result, and the same version over the same input reproduces it.

The bundle is built and tested as of today; we are holding it rather than
attaching it, so that you receive one cut against the deepest corpus available
once you have confirmed the specification. Say the word and we will rebuild and
send — it is one command, not a lead time. It is roughly 130 KB compressed, so
it travels as an ordinary attachment with a published SHA-256; no download link,
nothing to expire, and no access log to account for.

## Not started, as requested

No endpoint integration work has begun and none will until this coverage result
has been reviewed.
