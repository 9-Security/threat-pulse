#!/usr/bin/env bash
# One daily run: collect, mail, then push the day's indicators to D1.
#
# Mirrors .github/workflows/daily-deliver.yml so a host-run day and a
# CI-run day produce the same thing. Two differences are deliberate:
# `reports/` and the enrichment cache persist here instead of riding a CI
# cache that can miss, and the checkout is a pull, so a merged fix reaches
# tonight's run the same way it reached the workflow.
set -euo pipefail

APP_DIR="${APP_DIR:-$HOME/app}"
REPORTS_DIR="${REPORTS_DIR:-$APP_DIR/reports}"
export PATH="$HOME/.local/bin:$PATH"

cd "$APP_DIR"

if [ "${SKIP_PULL:-0}" != "1" ]; then
  git pull --ff-only --quiet
fi
echo "revision: $(git rev-parse --short HEAD) $(git log -1 --format=%s)"

uv sync --frozen --quiet

extra=()
if [ "${DRY_RUN:-0}" = "1" ]; then
  extra+=(--dry-run)
  # .invalid can never resolve, so a stand-in cannot reach anyone even if the
  # dry-run guard were removed.
  [ -z "${RESEND_FROM:-}" ] && extra+=(--from "SOC dry run <dry-run@dry-run.invalid>")
  [ -z "${RESEND_TO:-}" ] && extra+=(--to "dry-run@dry-run.invalid")
fi

uv run soc-news-parser deliver \
  --hours 24 \
  --at 06:00 \
  --timezone Asia/Taipei \
  --output-dir "$REPORTS_DIR" \
  "${extra[@]}"

# The email is the deliverable; the D1 corpus is what agents query later. A push
# failure must not fail a run that already sent the report, so everything below
# reports and returns 0.
push_to_d1() {
  if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "dry run; not pushing to D1"
    return 0
  fi
  for name in CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID; do
    if [ -z "${!name:-}" ]; then
      # Both are required: without the account id wrangler enumerates
      # /memberships and dies pointing at the wrong credential.
      echo "$name is not set; skipping the D1 push"
      return 0
    fi
  done

  # Take the folder deliver actually wrote rather than recomputing the date: a
  # manual run in the small hours of Taipei time lands on the previous slot.
  local day evidence
  day="$(ls -1 "$REPORTS_DIR" 2>/dev/null | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' | sort | tail -1)"
  evidence="$REPORTS_DIR/${day}/daily-evidence.json"
  if [ -z "$day" ] || [ ! -f "$evidence" ]; then
    echo "no dated report on disk; nothing to push"
    return 0
  fi

  uv run soc-news-parser export-d1 \
    --json-report "$evidence" --date "$day" --output "/tmp/${day}.sql"
  npx --yes wrangler@3 d1 execute soc-iocs \
    --config deploy/worker/wrangler.toml --remote --file "/tmp/${day}.sql"
  rm -f "/tmp/${day}.sql"
  echo "pushed ${day} to D1"
}

if ! push_to_d1; then
  echo "D1 push failed; the report was still delivered" >&2
fi
