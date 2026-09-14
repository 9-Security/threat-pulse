# Signed corpus bundle: delivery

**Date:** 2026-09-14
**Subject:** the signed bundle you asked for, and a correction we found while preparing it

You chose a detached Ed25519 signature over the complete ZIP, made with minisign,
with the public key exchanged on a separate channel. That is what is attached.
**The public key is not in this message.** Its fingerprint reaches you separately,
and the key should not be taken from anything that travels with the ZIP.

Before signing, we checked the bundle against our hosted corpus and found that two
of its days were incomplete copies. They are corrected in this delivery. The corpus
figures in our earlier notes were computed on the incomplete copies, so they are
superseded by the figures below. **This is the only bundle to run:** if an earlier
message of ours carried an unsigned bundle, please discard it.

---

## Attached

| file | what it is |
|---|---|
| `threat-pulse-corpus-validation-2026-09-14.zip` | the bundle: corpus snapshot, validator, its tests, README |
| `threat-pulse-corpus-validation-2026-09-14.zip.minisig` | the detached signature over the complete ZIP |
| `bundle-signing.md` | verification, key rotation and revocation |
| `corpus-provenance.md` | which copy each day is built from, and when it was collected |

## Verifying

Verify **before** unzipping, so nothing is extracted from a file that has not been
authenticated:

```bash
minisign -Vm threat-pulse-corpus-validation-2026-09-14.zip -P "<public key from the separate channel>"
```

A correct verification prints:

```
Signature and comment signature verified
Trusted comment: threat-pulse corpus validation bundle, corpus_version 2026-09-14.6c6144778947, built 2026-09-14T14:11:29+08:00
```

The trusted comment is covered by its own signature, so the `corpus_version` in it
cannot be edited without verification failing. It is the same value the validator
recomputes from the snapshot before every run.

Then:

```bash
unzip threat-pulse-corpus-validation-2026-09-14.zip
cd threat-pulse-corpus-validation-2026-09-14
python3 test_validate.py                    # 15 tests, standard library only
python3 validate.py --input your-values.csv --output results.csv --summary summary.json
```

| file | sha256 |
|---|---|
| `threat-pulse-corpus-validation-2026-09-14.zip` | `7075e9cc69c35295b28e6d718f123d593313a639a94b44a872af0dfda7222a16` |
| `threat-pulse-corpus-validation-2026-09-14.zip.minisig` | `ff9ba463db75a742111fe6705b79581785a1836f45f3bff2d3d39ef79d895bcf` |

These digests are in the same message as the files, so they only make a damaged
download obvious. The signature is what authenticates the bundle.

## Two different checks

| check | answers |
|---|---|
| `minisign -Vm` | **is this the bundle we sent, unaltered?** |
| `corpus_version`, recomputed by the validator on every run | **does the snapshot match its own contents?** |

As you put it: `corpus_version` is an internal corpus-integrity identifier and
authenticates nothing; the detached signature authenticates the delivered bundle.
Neither says the corpus is accurate or complete.

## The tool is unchanged

The three tool files are byte-for-byte those of the revision that answered your P2
finding. Only the corpus snapshot is new.

| file | sha256 |
|---|---|
| `validate.py` | `9e8eff3244ab3c517828afc137d4afa63e27b1e2997a28e49ab95941c1c523b0` |
| `test_validate.py` | `21e4be9c84ac2a99b17fcf34ef747e9bfbe860870a35c03dbc85b2bdbe2046c8` |
| `README.md` | `b46c7796961b9817cc17782bfe6372a404b45302c059e779687a319e068ca63d` |

---

## The correction

### What was wrong

The copies of 2026-09-04 and 2026-09-05 were not collected when their windows
closed. They were re-collected on 2026-09-07, and because feeds carry only their
newest items, each re-collection was a strict subset of what had been collected
earlier:

| day | copy we had been using | copy used in this bundle |
|---|---|---|
| 2026-09-04 | 25 articles, collected 78 h after the window closed | 55 articles, after 8.2 h |
| 2026-09-05 | 38 articles, after 30 h | 47 articles, after 2.4 h |

The earlier copies had survived, one as a local collection and one as an artifact
of our CI run, and we had not looked for them.

### How the two days were rebuilt

They were **not** fetched again, because a fresh fetch returns the decayed copy.
The current parser was run over the article text the earlier copies stored, which
is exactly the text extraction saw at collection. The same rebuild was applied to
our hosted corpus, so it and this bundle agree.

Each rebuilt day records, inside its report, the SHA-256 of the copy it was rebuilt
from, the original report id and parser revision, and what the rebuild does not
reproduce: articles whose text was unavailable at collection are still unavailable,
and KEV, CVSS and EPSS reflect 2026-09-14 rather than the collection date.

### What it changes

| | figures in our 2026-09-12 notes | this bundle |
|---|---|---|
| days | 9 (2026-09-04 → 09-12) | 11 (2026-09-04 → 09-14) |
| unique confirmed values | 1,976 | 2,082 |
| — CVE | 1,671 | 1,697 |
| — network indicators | 305 | **385** |
| `corpus_version` | `2026-09-12.594077387780` | `2026-09-14.6c6144778947` |

Compared value by value against the snapshot those figures came from:

- **Removed: none.**
- **Added by the correction: 92** — 80 network indicators and 12 CVEs.
- Added by the two newer days, 2026-09-13 and 09-14: 14 CVEs and no network
  indicators.
- 20 values now carry different or additional report dates.

The network figure is the one that bears on your stopping rule. We had described a
corpus of 305 network indicators; over those days it actually holds 385.

### Collection timing, for every day

Having found two late copies, we checked when every day was collected, not only the
two we fixed:

- **2026-09-06 and 2026-09-07** are also late re-collections, but each is identical,
  article for article and on every value the bundle carries, to a CI copy
  collected 1.5 hours after its window closed. They were not rebuilt.
- **2026-09-09** was collected 5.3 hours late. The scheduled run timed out, and the
  day was collected by a manual run afterwards. No earlier copy exists, so it
  cannot be rebuilt, and you should assume some decay relative to an on-time
  collection.
- **2026-09-08 and 2026-09-10 through 2026-09-14** were collected by the scheduled
  run within 25 minutes of the window closing.

`corpus-provenance.md` has the full per-day record.

---

## Signing key

- The fingerprint reaches you on a separate channel. Keep the key: later
  deliveries are verified against the key you already hold.
- A delivery that arrives carrying its own key is not a rotation. Treat it as a
  failed verification and contact us on the channel the key came on.
- The private key is password-protected and held in an operator's own account,
  not in the service account that builds the corpus. Every signature is made by a
  person at the time of delivery.
- Rotation is announced on that channel before a new key is used. minisign has no
  revocation mechanism, so revocation is an announcement on that channel too.
  `bundle-signing.md` sets out both procedures.

## Unchanged

The three endpoint items in `docs/data-handling.md` remain open and remain blockers
for an endpoint pilot: over-limit values are truncated without an error, server-side
skipping of private and internal values is not implemented, and Cloudflare log
retention and residency are not fully confirmed. Items 1, 2 and 6 remain implemented
in the validator and unbuilt in the endpoint. Nothing here asks you to treat the
eight conditions as complete.
