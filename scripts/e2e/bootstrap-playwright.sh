#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_HOME="${LINK42_E2E_HOME:-$HOME/.cache/link42/e2e}"
BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"

mkdir -p "$E2E_HOME" "$BROWSERS_PATH"

if [ ! -f "$E2E_HOME/package.json" ]; then
  cat >"$E2E_HOME/package.json" <<'JSON'
{
  "private": true,
  "name": "link42-local-playwright",
  "description": "Persistent local Playwright runtime for Link42 manual E2E tests",
  "dependencies": {
    "playwright": "^1.53.0"
  }
}
JSON
fi

echo "Installing Playwright runtime in $E2E_HOME"
NODE_OPTIONS=--dns-result-order=ipv4first npm install --prefix "$E2E_HOME"

echo "Installing Chromium browser cache in $BROWSERS_PATH"
PLAYWRIGHT_BROWSERS_PATH="$BROWSERS_PATH" \
  NODE_OPTIONS=--dns-result-order=ipv4first \
  "$E2E_HOME/node_modules/.bin/playwright" install chromium

cat <<EOF

Playwright environment is ready.

Repository: $ROOT_DIR
Runtime:    $E2E_HOME
Browsers:   $BROWSERS_PATH

Run a script with:
  scripts/e2e/run-playwright.sh path/to/test.js
EOF
