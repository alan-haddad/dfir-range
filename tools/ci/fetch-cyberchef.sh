#!/usr/bin/env bash
# Download a pinned CyberChef release into dist/cyberchef so the site serves an
# offline copy. Integrity: the zip must match the pinned SHA-256 below, and the
# digest GitHub publishes for the release asset when one is present.
# To upgrade: change VERSION, run once, and pin the SHA-256 it prints.
# CyberChef is Apache-2.0 licensed; its LICENSE is kept alongside it.
set -euo pipefail

VERSION="v10.24.0"
PINNED_SHA256="29947b4d7805b74135c8370f3cba19b609d63e8ece6e33b2cb8ee0dfbbf1393c"
DEST="${1:-dist/cyberchef}"
API="repos/gchq/CyberChef/releases/tags/${VERSION}"

asset_json="$(gh api "$API" --jq '[.assets[] | select(.name | endswith(".zip"))][0]')"
url="$(jq -r '.browser_download_url' <<<"$asset_json")"
digest="$(jq -r '.digest // empty' <<<"$asset_json")"
[[ -n "$url" && "$url" != "null" ]] || { echo "No zip asset found for CyberChef $VERSION" >&2; exit 1; }

tmp="$(mktemp -d)"
curl -fsSL "$url" -o "$tmp/cyberchef.zip"
actual="sha256:$(sha256sum "$tmp/cyberchef.zip" | cut -d' ' -f1)"
echo "CyberChef $VERSION: $actual"
if [[ "$actual" != "sha256:$PINNED_SHA256" ]]; then
  echo "SHA-256 does not match the pinned value sha256:$PINNED_SHA256" >&2
  exit 1
fi
if [[ -n "$digest" && "$digest" != "$actual" ]]; then
  echo "Digest mismatch: expected $digest" >&2
  exit 1
fi

rm -rf "$DEST"
mkdir -p "$DEST"
unzip -q "$tmp/cyberchef.zip" -d "$DEST"
html="$(find "$DEST" -maxdepth 1 -name 'CyberChef_*.html' | head -n1)"
[[ -n "$html" ]] || { echo "CyberChef HTML not found in the release zip" >&2; exit 1; }
cp "$html" "$DEST/index.html"
echo "CyberChef $VERSION installed to $DEST"
