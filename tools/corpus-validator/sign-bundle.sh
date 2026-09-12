#!/usr/bin/env bash
# Build the handover ZIP and sign it with the delivery key.
#
# The signing key is password-protected and belongs to a person, not to the
# service account: `threatpulse` builds the corpus, and a compromise of that
# account must not also be the ability to sign a bundle that a consumer will
# then trust. So this runs as the operator, prompts for the password, and
# cannot be driven unattended -- which is the point. Every authenticated
# delivery is authorised by a human at the moment it is made.
#
# Run it from an interactive shell. minisign reads the password from the
# terminal and there is deliberately no way to pass it on a command line, where
# it would reach the process table and the shell history.
#
#   ./sign-bundle.sh                 # signs the current bundle
#   ./sign-bundle.sh --rebuild       # rebuilds the corpus snapshot first
set -euo pipefail

APP_DIR="${APP_DIR:-/home/threatpulse/app}"
BUNDLE_DIR="${BUNDLE_DIR:-/home/threatpulse/bundle}"
OUT_DIR="${OUT_DIR:-$HOME/handover}"
SECKEY="${MINISIGN_SECKEY:-$HOME/.minisign/threat-pulse.key}"
PUBKEY="${MINISIGN_PUBKEY:-$HOME/.minisign/threat-pulse.pub}"

if [ ! -f "$SECKEY" ]; then
  echo "no signing key at $SECKEY" >&2
  echo "generate one first:" >&2
  echo "  mkdir -p ~/.minisign && chmod 700 ~/.minisign" >&2
  echo "  minisign -G -s $SECKEY -p $PUBKEY" >&2
  exit 1
fi

if [ "${1:-}" = "--rebuild" ]; then
  echo "rebuilding the snapshot..."
  sudo -u threatpulse -H bash -lc \
    "cd '$APP_DIR' && export PATH=\$HOME/.local/bin:\$PATH && uv sync --frozen --quiet && \
     rm -rf '$BUNDLE_DIR' && mkdir -p '$BUNDLE_DIR' && \
     uv run soc-news-parser snapshot --output '$BUNDLE_DIR' --reports-dir '$APP_DIR/reports'"
fi

stamp="$(date +%Y-%m-%d)"
name="threat-pulse-corpus-validation-${stamp}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

sudo cp -r "$BUNDLE_DIR/." "$work/$name/"
sudo chown -R "$(id -un):$(id -gn)" "$work/$name"
# __pycache__ appears if the shipped tests were run in place. It is not part of
# the delivery and would change the archive digest for no reason.
rm -rf "$work/$name/__pycache__"
chmod 644 "$work/$name"/*

version="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1], encoding='utf-8'))['corpus_version'])" \
  "$work/$name/corpus-snapshot.json")"

mkdir -p "$OUT_DIR"
zip="$OUT_DIR/${name}.zip"
rm -f "$zip" "$zip.minisig"
( cd "$work" && zip -q -r -X "$zip" "$name" )

echo
echo "signing $(basename "$zip") -- enter the signing key password when prompted"
minisign -S -s "$SECKEY" -m "$zip" \
  -t "threat-pulse corpus validation bundle, corpus_version ${version}, built $(date -Iseconds)"

echo
echo "bundle:    $zip"
echo "signature: $zip.minisig"
echo "corpus_version: $version"
echo
echo "sha256 (transfer check only -- the signature is what authenticates):"
sha256sum "$zip" "$zip.minisig" | sed 's/^/  /'
echo
echo "verify exactly as the consumer will:"
echo "  minisign -Vm $(basename "$zip") -P \"$(cat "$PUBKEY" | tail -1)\""
minisign -Vm "$zip" -p "$PUBKEY" >/dev/null && echo "  self-check: signature verifies"
