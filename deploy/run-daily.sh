#!/usr/bin/env bash
# One daily run: collect, mail, then push the day's indicators to D1.
#
# Mirrors .github/workflows/daily-deliver.yml so a host-run day and a CI-run day
# produce the same thing. Two differences are deliberate: `reports/` and the
# enrichment cache persist here instead of riding a CI cache that can miss, and
# the checkout is a pull, so a merged fix reaches tonight's run the same way it
# reached the workflow.
set -euo pipefail

APP_DIR="${APP_DIR:-$HOME/app}"
REPORTS_DIR="${REPORTS_DIR:-$APP_DIR/reports}"
export PATH="$HOME/.local/bin:$PATH"

cd "$APP_DIR"

# first_field.py is pure standard library and is what decides whether a day may
# be overwritten, so it must not depend on the project environment: a lockfile
# drift or a corrupted uv cache is one of the conditions it exists to survive.
# System python3 first, the venv only as a fallback for a host without one.
if command -v python3 >/dev/null 2>&1; then
  run_py() { python3 "$@"; }
else
  run_py() { uv run python "$@"; }
fi

# Alert on anything that leaves the corpus unable to grow. Every path below that
# ends without a push reaches this, because the observable outcome is identical
# whatever the cause: reports keep arriving and D1 quietly stops accruing days.
corpus_stalled() {
  echo "corpus did not grow: $1" >&2
  {
    echo "The daily report was delivered, but the day's indicators did not reach D1."
    echo "The corpus stops growing until this is fixed, and a day the collector"
    echo "misses cannot be collected later."
    echo
    echo "reason: $1"
    echo
    echo "--- last 40 journal lines ---"
    journalctl -u threat-pulse-daily.service -n 40 --no-pager --output=cat 2>&1 || true
  } | "$APP_DIR/deploy/alert.sh" "[threat-pulse] corpus stalled on $(hostname)" || true
}

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

# Streamed to the journal as it happens and captured at the same time. A plain
# command substitution would hold it all back until deliver exited, so a run
# that failed would take its own summary down with it -- and that summary is
# most of what the failure alert has to work with.
deliver_log="$(mktemp)"
trap 'rm -f "$deliver_log"' EXIT
uv run soc-news-parser deliver \
  --hours 24 \
  --at 06:00 \
  --timezone Asia/Taipei \
  --output-dir "$REPORTS_DIR" \
  "${extra[@]}" | tee "$deliver_log"

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
      #
      # Logged, not alerted. A host with no Cloudflare credentials is a
      # documented configuration -- the report still goes out, the corpus simply
      # is not fed -- and mailing about a state the operator chose, every
      # morning, is how the alert that matters becomes one more thing to ignore.
      # A credential that was set and has since stopped working fails inside
      # wrangler instead, which does alert.
      echo "$name is not set; skipping the D1 push"
      return 0
    fi
  done

  local evidence="$1" day
  if [ -z "$evidence" ] || [ ! -f "$evidence" ]; then
    corpus_stalled "deliver named no readable evidence file (got '${evidence:-empty}')"
    return 0
  fi
  day="$(basename "$(dirname "$evidence")")" || return 1
  # The date is interpolated into a SQL string and a /tmp path. It comes from
  # deliver rather than a directory scan now, which removed the pattern filter
  # that used to stand between an unexpected layout and both of those.
  if ! [[ "$day" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    corpus_stalled "evidence path does not name a dated folder: '$evidence'"
    return 0
  fi

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
  local stored collected
  if ! stored="$(npx --yes wrangler@3 d1 execute soc-iocs \
      --config deploy/worker/wrangler.toml --remote --json \
      --command "SELECT article_count, confirmed_ioc_count FROM reports WHERE report_date = '${day}'" \
      2>/dev/null | run_py "$APP_DIR/deploy/first_field.py" article_count confirmed_ioc_count)"; then
    # Exit 1 means the answer could not be read -- an expired token, a changed
    # wrangler envelope. That is not "nothing stored yet", and treating it as
    # such would replace a day on the strength of a failed lookup. Refuse, and
    # say so where someone will see it.
    if [ "${FORCE_D1:-0}" != "1" ]; then
      corpus_stalled "could not read the stored counts for ${day}; refusing to replace it unchecked (FORCE_D1=1 overrides)"
      return 0
    fi
    stored=""
  fi

  if [ -n "$stored" ] && [ "${FORCE_D1:-0}" != "1" ]; then
    collected="$(run_py "$APP_DIR/deploy/first_field.py" --plain \
      article_count confirmed_ioc_count < "$evidence")" || return 1
    # `[ x -lt y ]` on a non-integer exits 2, and an `if` reads that as false --
    # so a malformed count would slip past the comparison instead of stopping
    # it, which is the outcome this guard exists to prevent. Check the shape.
    if ! [[ "$stored $collected" =~ ^[0-9]+" "[0-9]+" "[0-9]+" "[0-9]+$ ]]; then
      corpus_stalled "counts for ${day} are not numeric (stored='${stored}' collected='${collected}'); refusing to replace it unchecked"
      return 0
    fi
    if [ "${collected%% *}" -lt "${stored%% *}" ] ||
       [ "${collected##* }" -lt "${stored##* }" ]; then
      echo "refusing to replace ${day}: D1 holds ${stored} (articles indicators)," >&2
      echo "  this run collected ${collected}." >&2
      echo "  The stored copy was collected closer to its window; FORCE_D1=1 overrides." >&2
      return 0
    fi
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
evidence_path="$(run_py "$APP_DIR/deploy/first_field.py" --plain json_output \
  < "$deliver_log")" || evidence_path=""

if ! push_to_d1 "$evidence_path"; then
  corpus_stalled "the D1 push failed"
fi
