#!/usr/bin/env bash
# One export of the malware analyser's new samples into the shared corpus.
#
# Runs hourly, and unlike the daily collection it loses nothing when a run is
# missed: the watermark lives in D1, so the next run reads from where the last
# successful one stopped. That is why this script alerts only when the corpus has
# been stuck for a day, not when one hour fails -- the analyser restarting during
# a deploy would otherwise mail every hour.
set -euo pipefail

APP_DIR="${APP_DIR:-$HOME/app}"
ANALYZER_URL="${ANALYZER_URL:-http://127.0.0.1:18080}"
# A first pass reads the whole public corpus; four API calls per sample against a
# 120-per-minute limit means a few thousand samples take hours. A cap keeps any
# single run bounded, and the next run continues from the new watermark.
MAX_SAMPLES="${MAX_SAMPLES:-400}"
# How stale the sample side may get before this is worth a mail.
STALL_HOURS="${STALL_HOURS:-24}"
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
    echo "The sample side of the IoC corpus has not been updated for at least"
    echo "${STALL_HOURS} hours. Lookups still answer -- D1 holds the last export --"
    echo "but nothing the analyser has found since then is in them."
    echo
    echo "reason: $1"
    echo
    echo "--- last 40 journal lines ---"
    journalctl -u threat-pulse-samples.service -n 40 --no-pager --output=cat 2>&1 || true
  } | "$APP_DIR/deploy/alert.sh" "[threat-pulse] sample corpus stalled on $(hostname)" || true
}

for name in CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID; do
  if [ -z "${!name:-}" ]; then
    # A documented configuration, not a fault: without Cloudflare credentials the
    # host collects and mails, and feeds no corpus. Logged, never mailed.
    echo "$name is not set; skipping the sample export"
    exit 0
  fi
done

# Where the last export stopped. An unreadable answer is not "nothing stored":
# treating it as such would re-read the whole corpus every hour.
state="$(d1 --json --command \
  "SELECT high_water, exported_at FROM sample_state WHERE id = 1" 2>/dev/null |
  run_py "$APP_DIR/deploy/first_field.py" high_water exported_at)" || {
  echo "could not read sample_state; leaving the corpus alone this hour" >&2
  exit 0
}
since="${state%% *}"
exported_at="${state##* }"
[ "$since" = "$exported_at" ] && exported_at=""

extra=()
[ -n "$since" ] && extra+=(--since "$since")

sql="$(mktemp --suffix=.sql)"
trap 'rm -f "$sql"' EXIT
summary="$(mktemp)"
trap 'rm -f "$sql" "$summary"' EXIT

if ! uv run soc-news-parser export-samples \
    --analyzer-url "$ANALYZER_URL" \
    --max-samples "$MAX_SAMPLES" \
    --output "$sql" \
    "${extra[@]}" 2>"$summary"; then
  echo "export failed:" >&2
  cat "$summary" >&2
  # Stuck for a day means the analyser or this script is broken, not busy.
  if [ -n "$exported_at" ] && [ "$(date -u -d "$exported_at" +%s 2>/dev/null || echo 0)" \
      -lt "$(date -u -d "-${STALL_HOURS} hours" +%s)" ]; then
    alert "the export has failed and the last one landed at ${exported_at}"
  fi
  exit 0
fi
cat "$summary"

count="$(run_py "$APP_DIR/deploy/first_field.py" --plain samples < "$summary")" || count=""
if [ "${count:-0}" = "0" ]; then
  echo "no new samples since ${since:-the beginning}"
  exit 0
fi

if ! d1 --file "$sql"; then
  echo "pushing the sample export to D1 failed" >&2
  if [ -n "$exported_at" ] && [ "$(date -u -d "$exported_at" +%s 2>/dev/null || echo 0)" \
      -lt "$(date -u -d "-${STALL_HOURS} hours" +%s)" ]; then
    alert "the push has failed and the last one landed at ${exported_at}"
  fi
  exit 0
fi
echo "pushed ${count} sample(s) to D1"
