#!/usr/bin/env bash
# One refresh of the feed side of the corpus: abuse.ch's ThreatFox and Feodo
# Tracker lists, into the same D1 database.
#
# Called from run-samples.sh every hour, so it needs no timer of its own, and
# refreshes only when the last refresh is FEED_HOURS old: ThreatFox's 7-day window
# moves slowly, and every refresh spends writes. A refresh that fails loses
# nothing -- each source's rows stay until they expire -- so this alerts only when
# no source has refreshed for STALL_HOURS.
set -euo pipefail

APP_DIR="${APP_DIR:-$HOME/app}"
FEED_HOURS="${FEED_HOURS:-6}"
STALL_HOURS="${STALL_HOURS:-48}"
export PATH="$HOME/.local/bin:$PATH"

cd "$APP_DIR"

if command -v python3 >/dev/null 2>&1; then
  run_py() { python3 "$@"; }
else
  run_py() { uv run python "$@"; }
fi

d1() {
  npx --yes wrangler@3 d1 execute soc-iocs \
    --config deploy/worker/wrangler.toml --remote "$@"
}

alert() {
  echo "$1" >&2
  {
    echo "The feed side of the IoC corpus (abuse.ch ThreatFox and Feodo Tracker) has"
    echo "not refreshed for at least ${STALL_HOURS} hours. Lookups still answer from"
    echo "the rows already stored, until they expire after 30 days."
    echo
    echo "reason: $1"
  } | "$APP_DIR/deploy/alert.sh" "[threat-pulse] feed corpus stalled on $(hostname)" || true
}

for name in CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID; do
  if [ -z "${!name:-}" ]; then
    echo "$name is not set; skipping the feed export"
    exit 0
  fi
done

# The newest successful refresh of any source. A database without the feed
# tables (migration 006 not applied yet) answers with an error: say so and stop,
# rather than pushing statements that would fail.
# coalesce: first_field.py treats NULL as an absent field (exit 1), which on an empty
# feed_state would read as "could not read" and skip every refresh forever.
latest="$(d1 --json --command \
  "SELECT coalesce(max(exported_at), '') AS latest FROM feed_state WHERE ok = 1" 2>/dev/null |
  run_py "$APP_DIR/deploy/first_field.py" latest)" || {
  echo "could not read feed_state (is migration 006 applied?); skipping the feed export" >&2
  exit 0
}

now="$(date -u +%s)"
if [ -n "$latest" ]; then
  last="$(date -u -d "$latest" +%s 2>/dev/null || echo 0)"
  if [ $((now - last)) -lt $((FEED_HOURS * 3600)) ]; then
    exit 0  # refreshed recently; the quiet, common case
  fi
fi

sql="$(mktemp --suffix=.sql)"
summary="$(mktemp)"
trap 'rm -f "$sql" "$summary"' EXIT

stalled() {
  [ -n "$latest" ] &&
    [ "$(date -u -d "$latest" +%s 2>/dev/null || echo 0)" -lt "$(date -u -d "-${STALL_HOURS} hours" +%s)" ]
}

if ! uv run soc-news-parser export-feeds --output "$sql" 2>"$summary"; then
  echo "feed export failed:" >&2
  cat "$summary" >&2
  # The SQL still records each source's error in feed_state (and runs expiry), so
  # the service can say the feed is failing rather than look merely quiet.
  [ -s "$sql" ] && d1 --file "$sql" >/dev/null 2>&1 || true
  stalled && alert "every source failed; the last successful refresh was ${latest}"
  exit 0
fi
cat "$summary"

if ! d1 --file "$sql"; then
  echo "pushing the feed export to D1 failed" >&2
  stalled && alert "the push failed; the last successful refresh was ${latest}"
  exit 0
fi
echo "feed corpus refreshed"
