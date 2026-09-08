#!/usr/bin/env bash
# Send one internal failure alert. Subject as $1, body on stdin.
#
# Deliberately does not use uv, the project venv, or any project code: this runs
# when something has already gone wrong, and a broken interpreter or a failed
# `uv sync` is one of the things it has to be able to report. curl and the
# system python3 are the only dependencies, and python3 is used solely to escape
# JSON -- if it is missing the alert still goes out, without the log tail.
#
# Goes to ALERT_TO, never to RESEND_TO. The daily report has a second recipient
# who should not receive operational noise.
set -uo pipefail

subject="${1:-threat-pulse alert}"
body="$(cat)"

if [ -z "${ALERT_TO:-}" ]; then
  echo "ALERT_TO is not set; not sending: ${subject}" >&2
  exit 0
fi
if [ -z "${RESEND_API_KEY:-}" ] || [ -z "${RESEND_FROM:-}" ]; then
  echo "RESEND_API_KEY or RESEND_FROM missing; cannot alert: ${subject}" >&2
  exit 0
fi

payload="$(
  SUBJECT="$subject" BODY="$body" FROM="$RESEND_FROM" TO="$ALERT_TO" \
  python3 -c '
import json, os
print(json.dumps({
    "from": os.environ["FROM"],
    "to": [t.strip() for t in os.environ["TO"].split(",") if t.strip()],
    "subject": os.environ["SUBJECT"],
    "text": os.environ["BODY"],
}))' 2>/dev/null
)"

if [ -z "$payload" ]; then
  # python3 unavailable or refused. Send the subject alone rather than nothing:
  # knowing the collector failed matters more than knowing why. Everything
  # interpolated here is escaped, and the recipient list is split the same way
  # the python path splits it -- a fallback that produces a 422 because it put
  # two addresses in one string would fail in exactly the case it exists for.
  json_escape() {
    local text=$1
    text=${text//\\/\\\\}
    text=${text//\"/\\\"}
    printf '%s' "$text"
  }
  recipients=""
  IFS=',' read -ra _addrs <<< "$ALERT_TO"
  for _addr in "${_addrs[@]}"; do
    _addr="$(printf '%s' "$_addr" | tr -d '[:space:]')"
    [ -z "$_addr" ] && continue
    [ -n "$recipients" ] && recipients="${recipients},"
    recipients="${recipients}\"$(json_escape "$_addr")\""
  done
  payload="{\"from\":\"$(json_escape "$RESEND_FROM")\",\"to\":[${recipients}],\"subject\":\"$(json_escape "$subject")\",\"text\":\"(log tail unavailable: python3 missing on the host)\"}"
fi

code="$(curl -sS -o /tmp/alert-response.$$ -w '%{http_code}' -m 30 \
  -X POST https://api.resend.com/emails \
  -H "Authorization: Bearer ${RESEND_API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$payload")" || code="000"

if [ "$code" = "200" ]; then
  echo "alert sent to ${ALERT_TO}: ${subject}"
else
  # Nothing left to escalate to, so make it loud in the journal instead.
  echo "ALERT DELIVERY FAILED (http ${code}): ${subject}" >&2
  head -c 400 "/tmp/alert-response.$$" >&2 2>/dev/null || true
  echo >&2
fi
rm -f "/tmp/alert-response.$$"
