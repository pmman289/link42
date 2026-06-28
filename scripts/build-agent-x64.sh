#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-"$ROOT_DIR/.venv/bin/python"}"
OUT_DIR="$ROOT_DIR/dist/agent"
NAME="link42-agent-linux-x64"

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "This script builds the x64 Linux agent and must run on x86_64." >&2
  exit 1
fi

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Python not found at $PYTHON_BIN. Set PYTHON_BIN or create .venv first." >&2
  exit 1
fi

if ! "$PYTHON_BIN" -m PyInstaller --version >/dev/null 2>&1; then
  echo "PyInstaller is not installed. Install it with:" >&2
  echo "  $PYTHON_BIN -m pip install pyinstaller" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
cd "$ROOT_DIR"

"$PYTHON_BIN" -m PyInstaller \
  --clean \
  --noconfirm \
  --onefile \
  --name "$NAME" \
  --distpath "$OUT_DIR" \
  --workpath "$ROOT_DIR/build/pyinstaller" \
  --specpath "$ROOT_DIR/build/pyinstaller" \
  --paths "$ROOT_DIR/apps/agent" \
  --paths "$ROOT_DIR/packages" \
  "$ROOT_DIR/apps/agent/agent_entry.py"

chmod +x "$OUT_DIR/$NAME"
echo "$OUT_DIR/$NAME"
