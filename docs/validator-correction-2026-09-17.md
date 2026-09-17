# Correction: three defects in the validator you ran

**Date:** 2026-09-17
**Subject:** the validator in the 2026-09-14 bundle misclassifies some values. A
corrected tool follows against the same corpus.

We found these while building the hosted `enrich_observables` to give the same answers
as the offline validator. Checking the validator line by line against the corpus
turned up three places where it does not do what its README says. They affect results
you may already have computed, so we are reporting them now, ahead of the contract.

The corpus itself is not affected. The corrected bundle ships **the same snapshot, byte
for byte**, so `corpus_version` stays `2026-09-14.6c6144778947`. Any difference between
your earlier results and new ones comes from the tool alone.

---

## 1. An exclusion was checked before a confirmation

Exclusions are recorded per article:

- `excluded_editorial_section` means one article mentioned the value outside its
  indicator section;
- `publisher_domain` means the value was that article's own publisher.

Neither says the value is benign. The validator checked exclusions first, so a value
confirmed by some publishers and mentioned in another's commentary came back
`excluded`.

| value | reported as | confirmed by |
|---|---|---|
| CVE-2026-20079 | `excluded` | CISA Cybersecurity Advisories, Cisco Talos, The Hacker News, SecurityWeek, BleepingComputer, Cyber Security News |
| CVE-2026-15630 | `excluded` | CERT/CC Vulnerability Notes, The Hacker News |
| CVE-2025-20701 | `excluded` | CERT/CC Vulnerability Notes |

The order is now:

1. an exact confirmation, of the value or of the whole URL;
2. an exclusion of the value or of the whole URL;
3. a same-host confirmation;
4. an exclusion of the host;
5. a parent or child relation.

## 2. Excluded URLs were never found, and three confirmed URLs could not match exactly

Exclusions of URLs are stored whole, but the validator looked them up by host, so they
came back `miss`. Separately, the input's trailing `/` was stripped while stored keys
kept theirs. Three confirmed URLs are stored with a trailing `/`:

- two `workers.dev` URLs, which could therefore match only as `parent_domain`;
- a link-local address, which is skipped regardless.

Three exclusions were likewise unreachable. Both sides are now compared without the
trailing slash.

The ten excluded URLs in this snapshot:

| URL | reason |
|---|---|
| `https://aomeitech.com` | `excluded_editorial_section` |
| `https://eclypsium.com/blog/bombshell-the-signed-backdoor-hiding-in-plain-sight-on-framework-devices/` | `excluded_editorial_section` |
| `https://github.com/onlyoffice/onlyoffice-owncloud/blob/master/controller/settingsapicontroller.php` | `excluded_editorial_section` |
| `https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules` | `excluded_editorial_section` |
| `https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language` | `excluded_editorial_section` |
| `https://uefi.org/sites/default/files/resources/uefi_shell_spec_2_0.pdf` | `excluded_editorial_section` |
| `https://www.cisa.gov/notification` | `publisher_domain` |
| `https://www.cisa.gov/privacy-policy` | `publisher_domain` |
| `https://www.sans.edu/cyber-security-programs/bachelors-degree/` | `publisher_domain` |
| `https://www.uefi.org/` | `excluded_editorial_section` |

## 3. Relations passed through values the corpus had held back

Some confirmed values carry a `benign_basis`: the pipeline itself refused to treat them
as blockable.

| value | `benign_basis` |
|---|---|
| `github.com` | `vendor_brand_apex` |
| `login.microsoftonline.com` | `vendor_brand_apex` |
| `ssl-google-analytics.l.google.com` | `vendor_brand_apex` |
| `incoming.telemetry.mozilla.org` | `vendor_brand_apex` |
| `https://github.com/bruneaug/dshield-siem/tree/main` | `vendor_brand_apex` |
| `co.uk`, `co.jp` | `domain_boundary_rule` |

The validator still matched relations through them. **Any URL on `github.com` was a
`same_host` hit, and any host under `login.microsoftonline.com` was a `parent_domain`
hit.** Both count toward the headline network rate, and both are among the commonest
values in an alert stream. An exact match on these values is still reported, with its
basis. A relation through them no longer is.

---

## Effect on your numbers

`hit_rate` is headline hits over processed values. Processed values include `hit`,
`miss` and `excluded`, and none of these corrections changes that count.

| correction | status change | rate effect |
|---|---|---|
| 1 | `excluded` → `hit` for the three CVEs | CVE rate can only **rise** |
| 2 | `miss` → `excluded` for the excluded URLs | none: neither is a hit |
| 2 | `hit` (`same_host`) → `excluded` for the `onlyoffice` URL | network rate can only **fall** |
| 3 | `hit` → `miss` for relations through the values above | network rate can only **fall** |

Across all 2,108 keys in the delivered snapshot, submitted as values, 15 results change.
The three CVEs and the excluded URLs account for all but two of them. The remaining two
are `workers.dev` URLs that move from `parent_domain` to `exact`, which is still a hit.
Correction 3 changes no key in the snapshot, because a held-back value still matches
itself exactly; it changes values you submit that are *beneath* or *on* those hosts. We
cannot see your sample, so we cannot tell you the size of the change for it.

**If your corrected network rate crosses one of your thresholds (1% or 5%), the stopping
rule's outcome changes with it.**

## Correcting results you already have

You can apply the corrections to an existing `results.csv` without the new bundle:

1. A row with `status=excluded` whose value is one of the three CVEs above becomes
   `hit`, `match_method=exact`.
2. A row with `status=hit`, `match_method` in `same_host`, `parent_domain` or
   `child_domain`, and `matched_value` in the `benign_basis` table above becomes
   `miss`.
3. A row whose value is one of the ten URLs above becomes `excluded`, whatever its
   status was, unless the whole URL is itself confirmed. None of the ten is.

Then recompute each type's rate as headline hits (`exact`, `parent_domain`,
`same_host`) over processed rows.

## The corrected bundle

| | |
|---|---|
| snapshot | unchanged; `corpus_version` `2026-09-14.6c6144778947` |
| `validate.py`, `README.md`, `test_validate.py` | replaced; the tests now number 21, including one per correction |
| signature | detached minisign, same key, Key ID `3AF66B0411A91321`, no rotation |
| verification | as before: compare the full public key line, or its SHA-256, against the value you confirmed on the separate channel |

The ZIP and signature digests are given in the delivery message. The README now
states the decision order and the held-back rule under **Order of decision**.

The hosted `enrich_observables` applies the same order and the same rules. Its
contract follows separately.
