#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-"$ROOT_DIR/.venv/bin/python"}"
OUT_DIR="$ROOT_DIR/dist/agent"
NAME="link42-agent-linux-x64"
BUILD_MODE="${LINK42_AGENT_BUILD_MODE:-docker}"
BUILD_IMAGE="${LINK42_AGENT_BUILD_IMAGE:-python:3.11-slim-bullseye}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "This script builds the x64 Linux agent and must run on x86_64." >&2
  exit 1
fi

if [[ "$BUILD_MODE" == "docker" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required for the default compatible build mode." >&2
    echo "Set LINK42_AGENT_BUILD_MODE=local to build with the local Python instead." >&2
    exit 1
  fi

  mkdir -p "$OUT_DIR" "$ROOT_DIR/build/pyinstaller"
  docker run --rm \
    --platform linux/amd64 \
    -v "$ROOT_DIR:/src" \
    -w /src \
    "$BUILD_IMAGE" \
    sh -c "apt-get update && apt-get install -y --no-install-recommends binutils && python -m pip install --no-cache-dir pyinstaller . && python -m PyInstaller --clean --noconfirm --onefile --name '$NAME' --distpath /src/dist/agent --workpath /src/build/pyinstaller --specpath /src/build/pyinstaller --paths /src/apps/agent --paths /src/packages /src/apps/agent/agent_entry.py"
  chmod +x "$OUT_DIR/$NAME"
  echo "$OUT_DIR/$NAME"
  exit 0
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
