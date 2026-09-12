# Response: seven findings, seven fixes

**Date:** 2026-09-12
**Subject:** validator round two — all seven addressed, and what stays open

Thank you for reading the code rather than the description. Every one of the
seven is real. We checked each against the source before accepting it and did
not find a misreading among them.

Your conclusion is also right, and we are adopting it: this is suitable for
offline validation after these corrections, and it is **not** a claim that the
eight review conditions are complete or that an endpoint pilot is warranted.

---

## 1. The specification contradicted itself

You are right, and the fault is ours in a way worth naming precisely: we
conflated **specified** with **implemented**. Items 1, 2 and 6 are shape
decisions inside `enrich_observables`, and the endpoint does not exist yet. The
status table said "specified above" in a column headed "status", the prose two
pages later said "deliberately not built yet", and our covering note said "all
eight are now addressed". The note was the worst of the three.

The table now has one column per deliverable:

| # | item | offline validator | endpoint |
|---|---|---|---|
| 1 | Response provenance and partial-failure fields | implemented | **not implemented** |
| 2 | Citation completeness | implemented | **not implemented** |
| 3 | `report_count` vs `source_count` semantics | implemented | specified |
| 4 | Domain-boundary matching via PSL | implemented | implemented |
| 5 | Known-benign provenance and versioning | implemented | implemented |
| 6 | CVE provenance separation | implemented | **not implemented** |
| 7 | Data handling and retention documentation | written | written, open items named |
| 8 | "Safe to automate" claim removed | done | done |

Five implemented, three specified. The endpoint column is what gates an endpoint
pilot; the validator column is what gates the coverage exercise. We are not
asking you to treat the first as satisfied.

## 2. Citation completeness had no enforcement

Correct. A value with no citation returned `status=hit` and an empty citation
column. It happened to be unreachable with the current builder, which is exactly
the problem: the rule held by accident rather than by construction, and the next
change to the builder could have broken it silently.

A match that cannot be cited is now `status=error`, reason `missing_citation`.
The check is in the reader, where it does not depend on how the snapshot was
made. There is a test that builds a corpus with an unlinked article and asserts
the row comes back `error` with an empty `citation_url`.

## 3. Defanged input was documented and not implemented

Correct, and this one was a promise in two separate documents. `evil[.]com` was
classified `unsupported_type` and dropped out of the denominator, so the failure
mode was silent under-counting.

`[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `[:]`, `hxxp://`, `hxxps://` and `fxp://`
are now restored before type detection runs. Every change is named in a new
`normalization_applied` column — `defang`, `defang_scheme`, `trailing_dot` — so
nothing is altered silently. This is the `normalization_applied` field your
original review asked for, arriving on the validator first.

## 4. A wrong type hint could defeat a safety skip

Correct, and this was the most serious of the seven, because it broke one of
your hard requirements rather than a convenience. A private address declared as
`domain` passed every guard, was looked up, and came back `miss` — in the
denominator, answered as not-found, for a value that was never eligible.

Skip checks now run against the supplied type **and** the detected type, and a
skip from either wins. A bare address arriving under a domain label is
recognised as an address. `10.1.2.3` declared `domain` is skipped as
`non_public_ip`, and the `type_mismatch` note rides along so you can see the
label was wrong as well.

Safety checks do not defer to a caller's label. That is now a stated rule in the
code, not an emergent property.

## 5. Per-row errors could not occur

Correct. There was no per-row guard, so a value that raised took the whole run
with it: we documented a row per input and delivered a traceback and no output
at all.

Each row is now evaluated inside its own guard and a failure produces one
`error` row naming the exception. Verified with a truncated IPv6 URL
(`http://[::1`), which raises inside URL parsing: it returns one `error` row and
the other six rows in the file are unaffected.

## 6. The snapshot was trusted, not verified

Correct, and your reasoning about the digest is right too, so we will not
pretend otherwise: **a SHA-256 that travels in the same message as the file
proves nothing about origin.**

What we have fixed is the part that was fixable in the tool. Before anything
else runs, the validator recomputes `corpus_version` from the snapshot's own
contents and refuses to run if it does not match, and separately checks that the
number of values the snapshot claims is the number it carries. A truncated,
partially written or edited snapshot is now rejected rather than quietly
producing results that look ordinary. There is a test that plants a value in a
built snapshot and asserts the run aborts and writes no output file.

That is integrity, not authenticity, and the README now says so in those words.
For origin, two options, your choice:

- we give you the digest over a channel the file did not travel on; or
- we sign the bundle with a key exchanged separately.

Neither is work for you to wait on; say which you prefer and we will do it
before the bundle is cut.

## 7. URL handling was inconsistent with what the documents implied

Correct. The submitted URL was reduced to its host before anything was tried,
which meant full URLs held in the corpus could never be matched, while a
host-level match was labelled `same_host` with no stronger relation available to
contrast it with.

A URL is now tried whole first and reported `exact` when the corpus holds it;
only then is it reduced to its host and tried again as `same_host`. The two are
never conflated. Since you are excluding URLs from the first sample this changes
nothing for the exercise, but the documents and the code now agree.

---

## What stays open, in your favour

Your reading of `docs/data-handling.md` is correct and we are not treating these
as closed by this round:

- over-limit values are silently truncated rather than reported;
- server-side skipping of private and internal values is not implemented;
- Cloudflare log retention and residency are not fully confirmed.

All three are endpoint properties. None is exercised by the offline validation,
and all three remain blockers for an endpoint pilot. We will not ask you to
revisit that until they are answered with the same evidence standard you have
applied here.

## Status

202 tests pass, 7 of them new — each asserting the specific behaviour that was
wrong, rather than the general area. The fixes were verified against the real
corpus as well as fixtures, because a fixture proves the logic and not the
artefact.

The bundle has not been re-cut yet. When you confirm the specification we will
build it against the corpus as of that date, with whichever origin-verification
option you prefer.
