#!/bin/bash
# Creates the Ed25519 key that signs blocklist.bin and stores the private half
# in exactly two places:
#   - the GitHub secret BLOCKLIST_SIGNING_KEY (so the Action can sign), and
#   - your macOS login Keychain as "Dead Air blocklist signing key" (your backup).
# Then prints the PUBLIC key to pin in the Dead Air app. The private key is
# never printed and never left on disk.
#
# Read it back later:  security find-generic-password -s "Dead Air blocklist signing key" -w
set -euo pipefail

REPO="${REPO:-ninefingerwoodshop-ops/dead-air-blocklist}"
SERVICE="Dead Air blocklist signing key"

OPENSSL=""
for candidate in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl "$(command -v openssl || true)"; do
  if [ -x "$candidate" ] && "$candidate" version | grep -q '^OpenSSL 3'; then OPENSSL="$candidate"; break; fi
done
[ -n "$OPENSSL" ] || { echo "Needs OpenSSL 3: brew install openssl@3" >&2; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "Log in to GitHub first: gh auth login" >&2; exit 1; }

if security find-generic-password -s "$SERVICE" >/dev/null 2>&1; then
  echo "Your Keychain already has \"$SERVICE\"." >&2
  echo "Replacing it would stop every installed app from accepting new lists until an app" >&2
  echo "update with the new public key ships. To rotate on purpose, delete it in Keychain Access first." >&2
  exit 1
fi

umask 077
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
"$OPENSSL" genpkey -algorithm ed25519 -out "$dir/key.pem" 2>/dev/null
body="$(grep -v -- '-----' "$dir/key.pem" | tr -d '\n')"
[ "${#body}" -eq 64 ] || { echo "Unexpected key format" >&2; exit 1; }

printf '%s' "$body" | gh secret set BLOCKLIST_SIGNING_KEY --repo "$REPO"
security add-generic-password -a dead-air-blocklist -s "$SERVICE" -l "$SERVICE" \
  -j "Ed25519 private key (PKCS#8, base64) that signs $REPO lists. Also the GitHub secret BLOCKLIST_SIGNING_KEY." \
  -w "$body"
public="$("$OPENSSL" pkey -in "$dir/key.pem" -pubout -outform DER 2>/dev/null | tail -c 32 | base64)"

echo "Saved the private key to GitHub ($REPO → BLOCKLIST_SIGNING_KEY) and your Keychain (\"$SERVICE\")."
echo "Public key for the app: $public"
