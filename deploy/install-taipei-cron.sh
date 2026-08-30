#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UV_BIN="${UV_BIN:-$(command -v uv || true)}"
if [[ -z "${UV_BIN}" && -x "${HOME}/.local/bin/uv" ]]; then
  UV_BIN="${HOME}/.local/bin/uv"
fi
if [[ -z "${UV_BIN}" ]]; then
  echo "error: uv not found; install uv or set UV_BIN" >&2
  exit 1
fi

LOG_DIR="${ROOT}/reports"
mkdir -p "${LOG_DIR}"

MARKER="soc-news-parser-taipei-0600"
ENTRY="CRON_TZ=Asia/Taipei"
JOB="0 6 * * * cd ${ROOT} && ${UV_BIN} run soc-news-parser deliver --hours 24 --at 06:00 --timezone Asia/Taipei --output-dir ${LOG_DIR} >> ${LOG_DIR}/deliver.log 2>&1"

EXISTING="$(crontab -l 2>/dev/null || true)"
FILTERED="$(printf '%s\n' "${EXISTING}" | grep -v "${MARKER}" | grep -v "soc-news-parser deliver --hours 24 --at 06:00" || true)"

{
  printf '%s\n' "${FILTERED}"
  echo "# ${MARKER}"
  echo "${ENTRY}"
  echo "${JOB}"
} | grep -v '^$' | crontab -

echo "installed daily 06:00 Asia/Taipei deliver from ${ROOT}"
crontab -l
