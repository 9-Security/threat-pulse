# Client token runbook

How the operator issues, hands over, limits, suspends and revokes client tokens for
the query service. Every command runs from the operator's workstation in
`deploy/worker/`, using the deploy token in `.env`. Run them in a terminal only you
can read; `issue` prints a secret.

`token-admin.mjs` talks to D1 through its HTTP API with bound parameters. Neither a
token nor its hash appears in any statement's text, which D1 keeps for up to 90 days,
and no command prints a hash.

## Issue

```bash
node token-admin.mjs issue "mssp pilot" --scopes "read" --per-minute 60 --per-day 5000 --expires 2026-12-31
```

- **One label per client.** An active token with the same label is refused, so
  "revoke by label" always means exactly one caller.
- **Scopes:** `read` returns hits and citation links. Add `context` only if the client
  needs the verbatim source sentence, which is publisher text.
- **Quotas:** leave them out to use the defaults of 60 per minute and 5,000 per UTC
  day. `0` suspends.
- **Expiry:** `--expires` sets a date after which the token stops working, at 00:00
  UTC. Pilot tokens should always have one.
- **Output:** the token is printed once and cannot be recovered. It is 64 hex
  characters. Add `--out FILE` to write it to a file readable only by you, instead of
  printing it.

## Hand over

A client token goes over a **separate, secure channel**: never ordinary email, and
never the message that carries the endpoint URL or the contract. For example, an
end-to-end encrypted messenger both sides already use, or a password manager's share.

1. Send the endpoint URL and the token's **label** in the ordinary channel.
2. Send the token itself over the secure channel.
3. Ask the client to confirm receipt by making one call. Then check that `list` shows
   a `last_used_at` for that label.
4. Delete your copy: the `--out` file, or the terminal scrollback.

The token's hash is all the service keeps. A lost token is replaced, not recovered.

## Check

```bash
node token-admin.mjs list            # every token: scopes, expiry, revocation, last use, quotas
node token-admin.mjs usage --days 7  # calls and refusals per token per UTC day
```

The daily check at 04:00 UTC mails the operator when, on the previous UTC day, a token
had any call refused or used 80% or more of its daily quota. A quiet day sends nothing.

Worth a look even without a mail:

- use outside the client's working pattern, for example at night or at weekends;
- use by a token the client says is idle;
- a sudden step change in daily calls.

## Change quotas, or suspend

```bash
node token-admin.mjs limits "mssp pilot" --per-minute 120 --per-day 20000
node token-admin.mjs limits "mssp pilot" --per-minute 0     # suspend: every call refused with 429
node token-admin.mjs limits "mssp pilot" --per-minute default --per-day default
```

The change applies on the token's next call. Suspending is for "pause while we talk".
If the token may have leaked, revoke it.

## Revoke

```bash
node token-admin.mjs revoke "mssp pilot"
```

The token stops working on its next call, with HTTP 401. Then:

1. **Verify.** `list` shows `revoked_at` for the label. If the client can still call
   with it, stop and investigate: something other than this table is authenticating.
2. **Tell the client**, in the ordinary channel, that the token was revoked and why.
3. **If it leaked,** issue a replacement under a new label, for example
   `"mssp pilot 2"`, and hand it over as above.
4. **Record** the date and reason with the pilot's notes.

## Rotate

Issue the replacement under a new label and hand it over. Wait until `list` shows the
new label in use. Then revoke the old one. Both work in the meantime, so the client
never has a gap.

## Emergency: stop every client

```bash
node token-admin.mjs revoke-all --confirm yes
```

This revokes every active client token at once. The service then answers every call
with 401, until new tokens are issued.

If the deploy token itself may be compromised, revoking client tokens is not enough:
that token can redeploy the Worker and bypass all of this. In that case:

1. Delete the deploy token in the Cloudflare dashboard.
2. Create a new one.
3. Only then revoke and reissue client tokens.
