# Response: P2 fixed, and the bundle

**Date:** 2026-09-12
**Subject:** the digest now covers the boundary rules — bundle attached

P2 is correct, and it was worse than an inconsistency with the README. Thank you
for looking at what the digest actually hashed rather than what it was described
as hashing.

---

## P2 — the digest covered the version string, not the rules

The material being hashed was `values`, `excluded`, `cve_intel` and
`public_suffix_list_version`. That last one is a string. So this passed the
integrity check unchanged:

```python
payload["public_suffix_rules"]["normal"].remove("github.io")
# public_suffix_list_version untouched
```

And after it, `other.github.io` matches `tenant.github.io` through the registry.
Unrelated tenants tied together, every row looking entirely ordinary, and the
run reporting `integrity verified` on its first line.

The Public Suffix List rules are the one part of the bundle that decides where a
parent-domain match stops, and they were the part the digest did not cover. Both
sides now hash the complete rule sets — normal, wildcard and exception. There is
a test that performs exactly the edit above and asserts the run aborts and
writes no output file.

`corpus_version` has changed as a result, from `2026-09-12.8a4b49478adb` to
`2026-09-12.594077387780`, over an identical corpus. The material being hashed
grew; the data did not.

## The two secondary findings

**Arbitrary or misspelled `type`.** Correct. `banana` was carried into
`type_used`, creating its own bucket in the per-type rates and reaching the
lookup under a type that does not exist. Supplied types are now validated
against the seven we accept; anything else is reported as
`unknown_supplied_type:<label>` and discarded in favour of detection. It also
cannot be used to slip a private address past the skip, which is tested.

**Defanging was case-sensitive and single-pass.** Correct on both counts.
`[Dot]` was missed because only all-lower and all-upper forms were replaced, and
`hxxp[:]//` was left half-converted because the scheme pass ran before the
punctuation pass — and the scheme is not recognisable until the punctuation is
restored. Matching is now case-insensitive and the two passes alternate until
the value stops changing.

## "Cannot independently verify the tests"

Also fair, and the answer is to stop asking you to take it on trust.
`test_validate.py` is in the bundle. Fifteen tests, standard library only,
building their own corpus rather than reading the shipped snapshot — so they
check the tool's behaviour independently of whatever data we sent you.

```
$ python3 test_validate.py
Ran 15 tests in 0.919s
OK
```

One of them parses `validate.py` and asserts it imports no network, subprocess
or dynamic-execution module. The claim that this tool does not talk to anything
is now checked mechanically rather than by reading, and you can run that check
yourself in a second.

## The bundle

| file | sha256 |
|---|---|
| `corpus-snapshot.json` | `273a462cff2109cb3e4e7463ba8d16ac7c521fc89ee8c8fa7fb51477b44831bb` |
| `validate.py` | `9e8eff3244ab3c517828afc137d4afa63e27b1e2997a28e49ab95941c1c523b0` |
| `test_validate.py` | `21e4be9c84ac2a99b17fcf34ef747e9bfbe860870a35c03dbc85b2bdbe2046c8` |
| `README.md` | `b46c7796961b9817cc17782bfe6372a404b45302c059e779687a319e068ca63d` |

`corpus_version 2026-09-12.594077387780` — 9 days, 2026-09-04 to 2026-09-12,
1,976 unique confirmed values (CVE 1,671, network 305), 29 excluded.

These digests are in the same message as the file, so by your own argument they
establish nothing about origin. They are here so that a transfer fault is
visible, no more. **The origin question is still open and still yours to
choose:** the digest read to you over a channel this file did not travel on, or
a detached signature with a key exchanged separately. Say which and we will do
it; neither is work you wait on.

## Unchanged, and still open

The three endpoint items from `docs/data-handling.md` — silent truncation over
the limit, server-side private/internal skipping unimplemented, Cloudflare log
retention and residency unconfirmed — are untouched by this round. They remain
blockers for an endpoint pilot and none is exercised by the offline validation.

Items 1, 2 and 6 remain implemented in the validator and unbuilt in the
endpoint. Nothing here asks you to treat the eight conditions as complete.
