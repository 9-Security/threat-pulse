# Signed bundle: delivery

**Date:** 2026-09-12
**Subject:** detached Ed25519 signature, as requested — bundle and signature attached

Done as specified. The complete ZIP is signed with Ed25519 via minisign, the
detached signature travels beside it, and **the public key is not in this
message** — you will receive the fingerprint separately, as you required.

---

## What is attached

| file | sha256 |
|---|---|
| `threat-pulse-corpus-validation-2026-09-12.zip` | `2b84fb9e5b4ba02223b8a79521b499601f9e20cafbb89373177a0871335bf3db` |
| `threat-pulse-corpus-validation-2026-09-12.zip.minisig` | `9380bfc9d8fbc3daa01b82d82b499a73918fb0b79cf08d3f7bfa5fe21b2a33d7` |

Those digests are here only so a truncated download is obvious. They are in the
same message as the file and therefore establish nothing about origin — which is
your point, and the reason for the signature.

## Verifying

Verify **before** unzipping, so nothing is extracted from a file that failed
authentication:

```bash
minisign -Vm threat-pulse-corpus-validation-2026-09-12.zip -P "<public key from the separate channel>"
```

A correct verification prints:

```
Signature and comment signature verified
Trusted comment: threat-pulse corpus validation bundle, corpus_version 2026-09-12.594077387780, built 2026-09-12T14:12:04+08:00
```

The trusted comment carries its own signature, so the `corpus_version` and build
time in it cannot be edited without the verification failing.

Then, inside the bundle:

```bash
unzip threat-pulse-corpus-validation-2026-09-12.zip
cd threat-pulse-corpus-validation-2026-09-12
python3 test_validate.py                    # 15 tests, standard library only
python3 validate.py --input your-values.csv --output results.csv --summary summary.json
```

## The two checks are different, deliberately

| check | answers |
|---|---|
| `minisign -Vm` | **is this the bundle we sent, unaltered?** |
| `corpus_version`, recomputed by the validator on every run | **does the snapshot match its own contents?** |

Your framing is the one we have adopted: `corpus_version` is an internal
corpus-integrity identifier and authenticates nothing. The detached signature
authenticates the delivered bundle. Neither is a statement that the corpus is
accurate or complete.

## Bundle contents

`corpus_version 2026-09-12.594077387780` — 9 days, 2026-09-04 to 2026-09-12,
1,976 unique confirmed values (CVE 1,671, network 305), 29 excluded.

- `corpus-snapshot.json` — the corpus and the Public Suffix List rules
- `validate.py` — the matcher; standard library only, no network
- `test_validate.py` — its tests, so our claims are checkable without us
- `README.md` — match semantics, statuses, denominators, limits

## Key handling

`docs/bundle-signing.md` accompanies this and covers the verification command,
rotation schedule and procedure, and revocation. Three points worth stating here
because they change what you should do:

**Keep the key.** Later deliveries are verified against the key you already
hold. A delivery that arrives carrying its own key is not a rotation — treat it
as a failed verification and contact us on the channel the original key came on.

**Rotation is announced before it happens**, on that same channel, and during a
changeover we sign with both keys and ship both signature files, so verification
never depends on your having already processed the announcement.

**minisign has no revocation mechanism.** There is no list to publish to. If the
key is compromised we notify you on the out-of-band channel, name the
fingerprint and the time from which nothing we sign carries it, and list the
bundles that were signed with it by name, SHA-256 and `corpus_version`. If you
suspect compromise before we do, tell us and we will treat it as confirmed until
shown otherwise — rotating unnecessarily costs one message.

## Signing key custody

The private key is password-protected and held in an operator's own account, not
in the service account that builds the corpus. A compromise of the collector is
therefore not also the ability to sign a bundle you would trust.

Signing consequently cannot be automated: every authenticated delivery is
authorised by a person at the moment it is made. That is deliberate and we do
not intend to remove it.

## Unchanged

The three endpoint items in `docs/data-handling.md` — silent truncation over the
limit, server-side private/internal skipping unimplemented, Cloudflare log
retention and residency unconfirmed — remain open and remain blockers for an
endpoint pilot. Items 1, 2 and 6 remain implemented in the validator and unbuilt
in the endpoint. Nothing here asks you to treat the eight conditions as complete.
