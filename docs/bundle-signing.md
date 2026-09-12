# Bundle signing: key, verification, rotation, revocation

The corpus validation bundle is authenticated by a **detached Ed25519 signature
over the complete ZIP**, produced with [minisign](https://jedisct1.github.io/minisign/).

`corpus_version` is not part of this. It is an internal corpus-integrity
identifier — it tells the validator that the snapshot matches its own contents,
and it says nothing about who produced the file. The detached signature is what
authenticates the delivered bundle.

---

## Verifying a delivery

```bash
minisign -Vm threat-pulse-corpus-validation-YYYY-MM-DD.zip -P "<public key>"
```

or, with the public key in a file:

```bash
minisign -Vm threat-pulse-corpus-validation-YYYY-MM-DD.zip -p threat-pulse.pub
```

A successful verification prints `Signature and comment signature verified` and
the trusted comment, which names the `corpus_version` and the build time. Both
are signed: minisign's trusted comment is covered by a second signature, so it
cannot be edited without detection.

The signature file is `<zip name>.minisig` and travels alongside the ZIP.

**Verify before unzipping.** The signature covers the archive, so checking it
first means nothing is extracted from a file that failed authentication.

## The public key

The public key and its fingerprint are transmitted **through a channel that does
not carry the ZIP**, as required. A key that arrives in the same message as the
file it authenticates establishes nothing: an attacker who can replace the file
can replace the key beside it.

Once you hold the key, keep it. Later deliveries are verified against the key
you already have, not against one that arrives with them. If a delivery ever
carries a different key, that is not a key rotation — treat it as a failed
verification and contact us through the channel the original key came on.

## Rotation

The signing key is rotated:

- **on schedule**, every 12 months from generation;
- **immediately**, on any suspicion of compromise, on any change of the person
  holding it, or if the host it lives on is rebuilt or reimaged.

A rotation is announced **on the out-of-band channel first**, before any bundle
is signed with the new key. The announcement carries the new fingerprint and the
date the old key stops being used. During the changeover we sign with both keys
and ship both signature files (`.minisig` and `.minisig.previous`), so a
verification never depends on having already processed the announcement.

The old public key is not deleted on your side. Keep it: it is how a bundle you
archived last year still verifies.

## Revocation

minisign has no revocation mechanism — there is no list to publish to and no
authority to publish it. Revocation is therefore an announcement, and it depends
on the out-of-band channel being real rather than ceremonial.

If the private key is compromised, we will:

1. notify you on the out-of-band channel, naming the fingerprint being revoked
   and the date and time from which no bundle we sign will carry it;
2. state which previously delivered bundles were signed with it, by ZIP name,
   SHA-256 and `corpus_version`, so you can decide what to re-verify or discard;
3. generate a new key and transmit the new fingerprint on the same channel;
4. re-sign and re-deliver any bundle you still need.

**What you should do on receiving a revocation notice:** stop trusting the
revoked fingerprint for anything received after the stated time. Bundles you
verified *before* the compromise are not retroactively suspect, but if the
compromise date is uncertain, treat everything signed with that key as
unverified and ask for re-delivery.

If you suspect compromise before we do, tell us on the out-of-band channel and
we will treat it as confirmed until shown otherwise. The cost of rotating
unnecessarily is one message; the cost of not rotating is a bundle you trust
that we did not send.

## Where the key lives

The private key is password-protected and held by a person, in that person's own
account — not by the service account that builds the corpus. A compromise of the
collector is therefore not also the ability to sign a bundle you would trust.

It follows that signing cannot be automated. Every authenticated delivery is
authorised by a human at the moment it is made, and that is deliberate rather
than a limitation we intend to remove.

## What the signature does and does not cover

| | |
|---|---|
| the exact bytes of the delivered ZIP | **covered** |
| the trusted comment: `corpus_version` and build time | **covered** |
| every file inside the archive, as delivered | **covered**, via the archive |
| that the corpus is accurate, complete, or current | **not covered** |
| that the snapshot matches its own contents | separate check — the validator recomputes `corpus_version` and refuses to run on a mismatch |

A valid signature means this bundle is the one we sent, unaltered. It is not a
statement about the quality of what is in it.
