#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${LINK42_REAL_ENV_FILE:-/tmp/link42-real-e2e.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

RUN_DIR="${LINK42_REAL_RUN_DIR:-/tmp/link42-real-e2e}"
if [[ -f "$RUN_DIR/state.env" ]]; then
  # shellcheck disable=SC1090
  source "$RUN_DIR/state.env"
fi

DB_PATH="${LINK42_REAL_DB:-$RUN_DIR/link42.db}"
BASE_URL="${LINK42_REAL_BASE_URL:-http://127.0.0.1:${LINK42_REAL_PORT:-8016}}"
REMOTE_SSH="${LINK42_REAL_REMOTE_SSH:-vpstest}"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"

echo "== processes =="
if [[ -f "$RUN_DIR/controller.pid" ]]; then
  ps -p "$(cat "$RUN_DIR/controller.pid")" -o pid,cmd || true
fi
if [[ -f "$RUN_DIR/local-agent.pid" ]]; then
  ps -p "$(cat "$RUN_DIR/local-agent.pid")" -o pid,cmd || true
fi
ssh "$REMOTE_SSH" "if [ -f '$RUN_DIR/remote-agent.pid' ]; then ps -p \$(cat '$RUN_DIR/remote-agent.pid') -o pid,cmd || true; fi" || true

echo
echo "== nodes =="
if [[ -n "${LINK42_REAL_WEB_TOKEN:-}" ]]; then
  curl -fsS "$BASE_URL/api/nodes" -H "authorization: Bearer $LINK42_REAL_WEB_TOKEN" |
    "$PYTHON_BIN" -c 'import json,sys
for n in json.load(sys.stdin):
    print(n["id"], n["name"], n["status"], n.get("agent_version"), ",".join(n.get("agent_capabilities") or []))
' || true
else
  echo "web token missing; cannot query /api/nodes"
fi

echo
echo "== recent tasks =="
if [[ -f "$DB_PATH" ]]; then
  "$PYTHON_BIN" - "$DB_PATH" <<'PY'
import json
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
conn.row_factory = sqlite3.Row
for row in conn.execute("select id,node_id,type,status,result from agent_tasks order by id desc limit 30"):
    brief = ""
    if row["result"]:
        try:
            data = json.loads(row["result"])
            brief = data.get("error") or data.get("message") or str(data)
        except Exception:
            brief = row["result"]
    print(row["id"], row["node_id"], row["type"], row["status"], brief[:180])
PY
else
  echo "database not found: $DB_PATH"
fi
