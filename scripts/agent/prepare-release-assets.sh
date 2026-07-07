#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
SRC_DIR="$ROOT_DIR/dist/agent"
OUT_DIR="${1:-"$ROOT_DIR/dist/controller-agent-releases"}"
PYTHON_BIN="${PYTHON_BIN:-"$ROOT_DIR/.venv/bin/python"}"
if [[ ! -x "$PYTHON_BIN" ]]; then
  PYTHON_BIN="$(command -v python3 || command -v python)"
fi

mkdir -p "$OUT_DIR"

# 读取当前 Agent 版本号。
agent_version() {
  "$PYTHON_BIN" - <<'PY'
from pathlib import Path
import re

text = Path("packages/link42_common/version.py").read_text(encoding="utf-8")
match = re.search(r'AGENT_VERSION\s*=\s*"([^"]+)"', text)
if not match:
    raise SystemExit("AGENT_VERSION not found")
print(match.group(1))
PY
}

# 读取现有 Agent 发布清单中的 latest 版本。
manifest_latest() {
  "$PYTHON_BIN" - "$SRC_DIR/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(1)
print(json.loads(path.read_text(encoding="utf-8")).get("latest", ""))
PY
}

# 判断 Agent 输入源码是否比目标产物更新。
agent_inputs_newer_than() {
  local target="$1"
  [[ -f "$target" ]] || return 0
  [[ -n "$(
    find \
      "$ROOT_DIR/apps/agent" \
      "$ROOT_DIR/packages/link42_common" \
      "$ROOT_DIR/packages/link42_wireguard" \
      -type f \
      -newer "$target" \
      -print \
      -quit
  )" ]]
}

expected_version="$(agent_version)"
current_manifest_latest=""
if [[ -f "$SRC_DIR/manifest.json" ]]; then
  current_manifest_latest="$(manifest_latest || true)"
fi

needs_binary_rebuild=0
if [[ "${REBUILD_AGENT_RELEASES:-0}" == "1" \
  || "$current_manifest_latest" != "$expected_version" \
  || ! -f "$SRC_DIR/link42-agent-linux-x64" \
  || ! -f "$SRC_DIR/link42-agent-linux-x64.sha256" ]]; then
  needs_binary_rebuild=1
elif agent_inputs_newer_than "$SRC_DIR/link42-agent-linux-x64"; then
  needs_binary_rebuild=1
fi

if [[ "$needs_binary_rebuild" == "1" ]]; then
  "$ROOT_DIR/scripts/agent/build-x64.sh" >/dev/null
fi

needs_source_rebuild=0
if [[ "${REBUILD_AGENT_RELEASES:-0}" == "1" \
  || ! -f "$SRC_DIR/link42-agent-source.tar.gz" \
  || ! -f "$SRC_DIR/link42-agent-source.tar.gz.sha256" ]]; then
  needs_source_rebuild=1
elif agent_inputs_newer_than "$SRC_DIR/link42-agent-source.tar.gz"; then
  needs_source_rebuild=1
fi

if [[ "$needs_source_rebuild" == "1" ]]; then
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
