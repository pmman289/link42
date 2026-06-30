#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC_DIR="$ROOT_DIR/dist/agent"
OUT_DIR="${1:-"$ROOT_DIR/dist/controller-agent-releases"}"
PYTHON_BIN="${PYTHON_BIN:-"$ROOT_DIR/.venv/bin/python"}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3 || command -v python)"
fi

mkdir -p "$OUT_DIR"

if [[ ! -f "$SRC_DIR/link42-agent-source.tar.gz" ]]; then
  "$ROOT_DIR/scripts/agent/build-source.sh" >/dev/null
fi

if [[ -f "$SRC_DIR/manifest.json" ]]; then
  cp "$SRC_DIR/manifest.json" "$OUT_DIR/manifest.json"
  while IFS= read -r file; do
    cp "$file" "$OUT_DIR/$(basename "$file")"
  done < <(find "$SRC_DIR" -maxdepth 1 -type f -name 'link42-agent-*' | sort)
else
  "$PYTHON_BIN" - <<'PY' > "$OUT_DIR/manifest.json"
from pathlib import Path
import re

text = Path("packages/link42_common/version.py").read_text(encoding="utf-8")
match = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text)
version = match.group(1) if match else "0.0.0"
print(f'''{{
  "latest": "{version}",
  "minimum_supported": "0.1.0",
  "releases": {{}}
}}''')
PY
fi

echo "$OUT_DIR"
