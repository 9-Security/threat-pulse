# Corpus provenance

Which copy each day of the corpus is built from, and when that copy was collected.

A day in the corpus is meant to be what the collector saw when that day's window
closed. Feeds carry only their newest items, so a later collection returns less —
re-collecting one window three days late returned 45% of its articles. For the
first days of the corpus that was not always true, and two days were rebuilt on
2026-09-14. This records what each day actually is, so it does not have to be
rediscovered.

**Collection lag** below is the time between the window closing (06:00
Asia/Taipei, 22:00 UTC the previous day) and the collection. A report's
`generated_at` is not evidence of it: a re-run sets `generated_at` to the slot
time, which is how two re-collected copies were mistaken for originals.

---

## Every day

| report date | copy in the corpus | collection lag | established from |
|---|---|---|---|
| 2026-09-04 | **rebuilt** from a local collection: 55 articles, parser `bacf32e` | +8.2 h | file time. The earliest surviving copy. The scheduled CI run for this slot failed, and a later CI run (+18 h, 41 articles) holds no article this one lacks. |
| 2026-09-05 | **rebuilt** from CI run `33932870277`: 47 articles, parser `e74bd75` | +2.4 h | GitHub Actions run start. The scheduled CI run for this slot failed. |
| 2026-09-06 | archive copy, re-collected on 2026-09-07 | +30 h | Identical articles and identical bundle-relevant values to CI run `33999016567` (+1.6 h); one stored body differs. Not rebuilt. Until 2026-09-17 the hosted corpus held the CI copy; the 2026-09-17 re-push replaced it with this one, so the two now agree (see below). |
| 2026-09-07 | archive copy, re-run on 2026-09-07 | +5.8 h | Identical articles and values to CI run `34067024610` (+1.5 h). Not rebuilt. |
| 2026-09-08 | host scheduled run | +0.4 h | systemd journal |
| 2026-09-09 | **manual run after the scheduled run timed out** at 06:46 | +5.3 h | systemd journal records the timeout and no later scheduled run. No earlier copy exists, so it cannot be rebuilt. |
| 2026-09-10 → 2026-09-14 | host scheduled runs | +0.0 – 0.1 h | systemd journal |

From 2026-09-08 the collector runs on a host systemd timer, and the journal is
the authority for when each day was collected. Before that it ran on GitHub
Actions, whose artifacts are the authority — and they expire, so the ones for
2026-09-04 through 2026-09-07 are preserved on the collecting host.

## The 2026-09-14 rebuild

The archive and the hosted corpus both held late copies of 2026-09-04 and
2026-09-05:

| day | copy that was replaced | copy now used |
|---|---|---|
| 2026-09-04 | 25 articles, re-collected +78 h — a strict subset of the copy now used | 55 articles, +8.2 h |
| 2026-09-05 | 38 articles, re-collected +30 h — a strict subset | 47 articles, +2.4 h |

The hosted corpus's 2026-09-04 was a third copy, from a run whose window was
2026-09-03 14:00Z → 2026-09-04 14:00Z — mostly the next day's slot. Two of its
articles, published 2026-09-04 at 12:16Z and 13:21Z, belong to 2026-09-05 and are
there now, from 2026-09-05's own collection.

**The days were not re-fetched**, because a re-fetch returns the decayed copy.
`soc-news-parser reanalyze` (introduced in `627310f`) runs the current extraction
and analysis over the article text the early copies stored. That text is exactly
what extraction saw at collection — `build_manifest` stores it verbatim — and a
report produced by current code and re-analysed by current code reproduces its
confirmed values and its `report_id`, which is tested.

Each rebuilt report carries a `reanalysis` block. What it does not reproduce:

- **the fetch.** An article whose text was unavailable at collection is still
  unavailable: 60 of 65 stored articles had text for 2026-09-04, 47 of 57 for
  2026-09-05.
- **the enrichment date.** KEV, CVSS and EPSS reflect 2026-09-14, not the
  collection date.

| source copy | SHA-256 |
|---|---|
| 2026-09-04 local collection | `501d5c1c66e5569cc7bda3a0267833b2cd5c3be46c15afea0cf5a73e33ca6af9` |
| 2026-09-05, CI artifact `9959165102` | `43fb5e761257e1d1338124c2aa7560f375116017f347eb30ef00487839bc886a` |

### Effect

| | 2026-09-04 | 2026-09-05 |
|---|---|---|
| bundle-relevant values (CVE, domain, IP, URL, hashes) | 76 → 107 | 66 → 134 |
| values removed | 0 | 0 |
| hosted-corpus rows | 169 → 144 | 83 → 187 |

Across the corpus on the same eleven days: unique confirmed values 1,990 → 2,082;
CVEs 1,685 → 1,697; network indicators 305 → 385. **No value left the hosted
corpus**, checked value by value against every other stored day, and the row
counts in the hosted corpus were checked against the SQL that was sent.

The replaced copies, the hosted-corpus rows as they were, and the preserved CI
artifacts are kept on the collecting host.

## The 2026-09-17 re-push

Every day was pushed again from the archive with the exporter that carries
publication dates, exclusions, CVE records and the corpus version. Afterwards,
on every day, the hosted corpus's `report_id` equals the archive file's, and its
counts and `corpus_version` equal an offline snapshot of the same folder.

The one day whose content source changed is 2026-09-06. It went from the CI copy
to the archive copy, which has the same articles and the same values. A full
export of the hosted corpus taken just before is kept on the collecting host.

Article `retrieved_at` is not carried. On every day it equals the window close,
not the time an article was fetched, so it is not evidence of collection time
either.

## Checking a day

- Compare the report file's time to its window close, not `generated_at`.
- From 2026-09-08, read the systemd journal for the run that produced the day.
- Before 2026-09-08, compare against the preserved CI artifacts for the window.
- A copy whose counts match the hosted corpus only shows the two came from the
  same collection. It does not show the collection happened on time.
