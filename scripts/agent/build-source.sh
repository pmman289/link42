#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
OUT_DIR="$ROOT_DIR/dist/agent"
NAME="link42-agent-source.tar.gz"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3 || command -v python)"
fi

cd "$ROOT_DIR"
mkdir -p "$OUT_DIR"
tar \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -czf "$OUT_DIR/$NAME" \
  -C "$ROOT_DIR" \
  apps/agent \
  packages/link42_common \
  packages/link42_wireguard

link42_write_sha256 "$OUT_DIR/$NAME"

VERSION="$($PYTHON_BIN - <<'PY'
from pathlib import Path
import re

text = Path("packages/link42_common/version.py").read_text(encoding="utf-8")
match = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text)
if not match:
    raise SystemExit("AGENT_VERSION not found")
print(match.group(1))
PY
)"

if [[ -f "$OUT_DIR/manifest.json" ]]; then
  "$PYTHON_BIN" - "$OUT_DIR/manifest.json" "$NAME" "$VERSION" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
asset_name = sys.argv[2]
version = sys.argv[3]
asset_path = manifest_path.parent / asset_name
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
release = manifest.setdefault("releases", {}).setdefault(version, {})
assets = release.setdefault("assets", {})
assets["openwrt-source"] = {
    "path": asset_name,
    "sha256": hashlib.sha256(asset_path.read_bytes()).hexdigest(),
    "size": asset_path.stat().st_size,
    "install_mode": "source",
}
manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
fi

echo "$OUT_DIR/$NAME"
