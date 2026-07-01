#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <playwright-script.js> [args...]" >&2
  exit 2
fi

E2E_HOME="${LINK42_E2E_HOME:-$HOME/.cache/link42/e2e}"
BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
SCRIPT="$1"
shift

if [ ! -d "$E2E_HOME/node_modules/playwright" ]; then
  echo "Playwright runtime not found. Run scripts/e2e/bootstrap-playwright.sh first." >&2
  exit 1
fi

PLAYWRIGHT_BROWSERS_PATH="$BROWSERS_PATH" \
  NODE_PATH="$E2E_HOME/node_modules" \
  node "$SCRIPT" "$@"
