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

# Captured so the push can use the path deliver reports rather than guessing at
# the directory listing. Echoed straight back out so the journal still has it.
deliver_output="$(uv run soc-news-parser deliver \
  --hours 24 \
  --at 06:00 \
  --timezone Asia/Taipei \
  --output-dir "$REPORTS_DIR" \
  "${extra[@]}")"
printf '%s\n' "$deliver_output"

# Read one field of the report JSON deliver just wrote.
evidence_field() {
  uv run python -c 'import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])' "$1" "$2"
}

# The D1 corpus is what agents query later, but the mail is the deliverable, so a
# push failure must be reported without failing a run that already sent it. Every
# step below returns explicitly: errexit does not apply inside a function whose
# caller tests its status, so a bare command failing here would otherwise carry
# on to the next line and report success.
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

  local evidence="$1" day
  if [ -z "$evidence" ] || [ ! -f "$evidence" ]; then
    echo "deliver named no evidence file; nothing to push"
    return 0
  fi
  day="$(basename "$(dirname "$evidence")")" || return 1

  # Look at what is stored before replacing it. The exporter deletes and rewrites
  # the whole date, and a re-run of a window that closed hours ago collects a
  # decayed copy: feeds carry only their most recent items, and the same window
  # re-collected three days later returned 55% of its articles. The scheduled run
  # is safe because it collects the window that just closed. The hazard is a
  # manual re-run, which is also the most natural thing to try.
  #
  # Both counts are compared. Articles alone would let through a re-run that
  # still finds the same headlines but can no longer read their bodies, which
  # deletes the day's indicators and re-inserts nothing.
  # FORCE_D1=1 pushes a genuine correction that legitimately has fewer.
  local stored_json collected_articles collected_iocs
  if stored_json="$(npx --yes wrangler@3 d1 execute soc-iocs \
      --config deploy/worker/wrangler.toml --remote --json \
      --command "SELECT article_count, confirmed_ioc_count FROM reports WHERE report_date = '${day}'" \
      2>/dev/null | uv run python "$APP_DIR/deploy/first_field.py" article_count confirmed_ioc_count)"; then
    collected_articles="$(evidence_field "$evidence" article_count)" || return 1
    collected_iocs="$(evidence_field "$evidence" confirmed_ioc_count)" || return 1
    if [ -n "$stored_json" ] && [ "${FORCE_D1:-0}" != "1" ]; then
      local stored_articles stored_iocs
      stored_articles="${stored_json% *}"
      stored_iocs="${stored_json#* }"
      if [ "$collected_articles" -lt "$stored_articles" ] ||
         [ "$collected_iocs" -lt "$stored_iocs" ]; then
        echo "refusing to replace ${day}: D1 holds ${stored_articles} articles / ${stored_iocs} indicators," >&2
        echo "  this run collected ${collected_articles} / ${collected_iocs}." >&2
        echo "  The stored copy was collected closer to its window; FORCE_D1=1 overrides." >&2
        return 0
      fi
    fi
  else
    # No comparison was possible, so say so rather than letting an unreadable
    # answer look like "nothing stored yet".
    echo "could not read the stored counts for ${day}; replacing it unguarded" >&2
  fi

  uv run soc-news-parser export-d1 \
    --json-report "$evidence" --date "$day" --output "/tmp/${day}.sql" || return 1
  npx --yes wrangler@3 d1 execute soc-iocs \
    --config deploy/worker/wrangler.toml --remote --file "/tmp/${day}.sql" || {
      rm -f "/tmp/${day}.sql"
      return 1
    }
  rm -f "/tmp/${day}.sql"
  echo "pushed ${day} to D1"
}

# deliver names the file it wrote. Scanning the output directory instead would
# pick the lexicographically last folder, which on a run that wrote nothing is
# some earlier day this run never collected.
evidence_path="$(printf '%s' "$deliver_output" \
  | uv run python "$APP_DIR/deploy/first_field.py" --plain json_output)" || evidence_path=""

if ! push_to_d1 "$evidence_path"; then
  echo "D1 push failed; the report was still delivered" >&2
fi
