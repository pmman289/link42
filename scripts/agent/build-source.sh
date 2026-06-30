#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT_DIR/dist/agent"
NAME="link42-agent-source.tar.gz"

mkdir -p "$OUT_DIR"
tar \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -czf "$OUT_DIR/$NAME" \
  -C "$ROOT_DIR" \
  apps/agent \
  packages/link42_common \
  packages/link42_wireguard

sha256sum "$OUT_DIR/$NAME" > "$OUT_DIR/$NAME.sha256"
echo "$OUT_DIR/$NAME"
