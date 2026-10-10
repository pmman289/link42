#!/usr/bin/env bash
set -euo pipefail
# 运行状态文件包含 Web/Agent token；整个测试目录默认只允许当前用户访问。
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${LINK42_REAL_ENV_FILE:-/tmp/link42-real-e2e.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

RUN_DIR="${LINK42_REAL_RUN_DIR:-/tmp/link42-real-e2e}"
RUN_MARKER="$RUN_DIR/.link42-real-e2e"
DB_PATH="${LINK42_REAL_DB:-$RUN_DIR/link42.db}"
HOST="${LINK42_REAL_HOST:-0.0.0.0}"
PORT="${LINK42_REAL_PORT:-8016}"
BASE_URL="http://127.0.0.1:$PORT"
LOCAL_AGENT_URL="${LINK42_REAL_LOCAL_AGENT_URL:-$BASE_URL}"
REMOTE_AGENT_URL="${LINK42_REAL_REMOTE_AGENT_URL:-}"
LOCAL_NODE_NAME="${LINK42_REAL_LOCAL_NODE_NAME:-real-local}"
REMOTE_NODE_NAME="${LINK42_REAL_REMOTE_NODE_NAME:-real-remote}"
LOCAL_ENDPOINT="${LINK42_REAL_LOCAL_ENDPOINT:-}"
REMOTE_ENDPOINT="${LINK42_REAL_REMOTE_ENDPOINT:-}"
REMOTE_SSH="${LINK42_REAL_REMOTE_SSH:-vpstest}"
POLL_INTERVAL="${LINK42_REAL_POLL_INTERVAL:-2}"
PYTHON_BIN="${PYTHON_BIN:-$ROOT_DIR/.venv/bin/python}"
UVICORN_BIN="${UVICORN_BIN:-$ROOT_DIR/.venv/bin/uvicorn}"

# 输出错误并终止真实端到端测试。
fail() {
  echo "[link42-real-e2e] ERROR: $*" >&2
  exit 1
}

# 检查真实端到端测试依赖命令。
require() {
  command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"
}

# 从 JSON 标准输入中读取指定字段。
json_get() {
  "$PYTHON_BIN" -c 'import json,sys
data=json.load(sys.stdin)
for key in sys.argv[1].split("."):
    data = data[int(key)] if isinstance(data, list) else data[key]
print(data)' "$1"
}

# 把路径和环境值安全嵌入远端 POSIX shell 命令。
shell_quote() {
  local value="$1"
  value=${value//\'/\'\\\'\'}
  printf "'%s'" "$value"
}

# 通过 SSH 标准输入传输，内容仅在启动 Agent 时由 shell 解释一次。
remote_agent_script() {
  local agent_dir="$1" agent_token="$2"
  printf '#!/bin/sh\nset -eu\ncd %s\nexport PYTHONPATH=%s\nexport LINK42_SERVER_URL=%s\nexport LINK42_NODE_ID=%s\nexport LINK42_AGENT_TOKEN=%s\nexport LINK42_POLL_INTERVAL=%s\nexec python3 -m link42_agent.main\n' \
    "$(shell_quote "$agent_dir")" "$(shell_quote 'apps/agent:packages')" \
    "$(shell_quote "$REMOTE_AGENT_URL")" "$(shell_quote "$REMOTE_NODE_ID")" \
    "$(shell_quote "$agent_token")" "$(shell_quote "$POLL_INTERVAL")"
}

# 等待测试主控健康检查通过。
wait_for_api() {
  for _ in $(seq 1 120); do
    if curl -fsS "$BASE_URL/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  tail -120 "$RUN_DIR/controller.log" >&2 || true
  fail "controller did not become healthy"
}

# 等待真实端到端测试节点上线。
wait_for_nodes_online() {
  for _ in $(seq 1 80); do
    local count
    count="$(curl -fsS "$BASE_URL/api/nodes" -H "authorization: Bearer $WEB_TOKEN" |
      "$PYTHON_BIN" -c 'import json,sys; print(sum(1 for n in json.load(sys.stdin) if n["status"] == "online"))')"
    if [[ "$count" -ge 2 ]]; then
      return 0
    fi
    sleep 0.5
  done
  curl -fsS "$BASE_URL/api/nodes" -H "authorization: Bearer $WEB_TOKEN" >&2 || true
  fail "timed out waiting for both agents to become online"
}

# 以已登录 token 调用测试主控 API。
api() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -fsS -X "$method" "$BASE_URL$path" \
      -H "authorization: Bearer $WEB_TOKEN" \
      -H "content-type: application/json" \
      --data-binary "$body"
  else
    curl -fsS -X "$method" "$BASE_URL$path" \
      -H "authorization: Bearer $WEB_TOKEN"
  fi
}

# 写入真实端到端测试运行状态。
write_state() {
  cat > "$RUN_DIR/state.env" <<EOF
LINK42_REAL_RUN_DIR=$(printf '%q' "$RUN_DIR")
LINK42_REAL_DB=$(printf '%q' "$DB_PATH")
LINK42_REAL_PORT=$(printf '%q' "$PORT")
LINK42_REAL_BASE_URL=$(printf '%q' "$BASE_URL")
LINK42_REAL_WEB_TOKEN=$(printf '%q' "$WEB_TOKEN")
LINK42_REAL_LOCAL_NODE_ID=$(printf '%q' "$LOCAL_NODE_ID")
LINK42_REAL_REMOTE_NODE_ID=$(printf '%q' "$REMOTE_NODE_ID")
LINK42_REAL_LOCAL_AGENT_PID=$(printf '%q' "$LOCAL_AGENT_PID")
LINK42_REAL_REMOTE_AGENT_PID=$(printf '%q' "$REMOTE_AGENT_PID")
LINK42_REAL_REMOTE_SSH=$(printf '%q' "$REMOTE_SSH")
EOF
  chmod 0600 "$RUN_DIR/state.env"
}

# 执行脚本主流程。
main() {
  require curl
  require ssh
  require tar
  require realpath
  [[ -x "$PYTHON_BIN" ]] || fail "python not found: $PYTHON_BIN"
  [[ -x "$UVICORN_BIN" ]] || fail "uvicorn not found: $UVICORN_BIN"
  [[ -n "$LOCAL_ENDPOINT" ]] || fail "set LINK42_REAL_LOCAL_ENDPOINT"
  [[ -n "$REMOTE_ENDPOINT" ]] || fail "set LINK42_REAL_REMOTE_ENDPOINT"
  [[ -n "$REMOTE_AGENT_URL" ]] || fail "set LINK42_REAL_REMOTE_AGENT_URL"

  mkdir -p "$RUN_DIR"
  [[ ! -L "$RUN_DIR" ]] || fail "run directory must not be a symbolic link: $RUN_DIR"
  local run_root db_root
  run_root="$(realpath -m "$RUN_DIR")"
  db_root="$(realpath -m "$DB_PATH")"
  [[ "$db_root" == "$run_root"/* ]] || fail "database path must stay inside run directory: $DB_PATH"
  chmod 0700 "$RUN_DIR"
  if [[ -e "$RUN_MARKER" && ( ! -f "$RUN_MARKER" || -L "$RUN_MARKER" ) ]]; then
    fail "run directory marker is not a regular file: $RUN_MARKER"
  fi
  if [[ ! -f "$RUN_MARKER" ]]; then
    if [[ -n "$(find "$RUN_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      fail "refusing to reuse non-empty unmarked run directory: $RUN_DIR"
    fi
    printf 'Link42 real E2E run directory\n' > "$RUN_MARKER"
    chmod 0600 "$RUN_MARKER"
  fi
  rm -f "$DB_PATH" "$DB_PATH"-* "$RUN_DIR"/*.log "$RUN_DIR"/state.env

  LINK42_DATABASE_URL="sqlite:///$DB_PATH" \
    LINK42_CONFIG_DIR="$RUN_DIR/controller-config" \
    LINK42_MASTER_KEY_FILE="$RUN_DIR/controller-config/master.key" \
    LINK42_WEB_DIST_DIR="$ROOT_DIR/apps/web/dist" \
    PYTHONPATH="$ROOT_DIR/apps/api:$ROOT_DIR/packages" \
    "$UVICORN_BIN" link42_api.main:app --host "$HOST" --port "$PORT" --proxy-headers --timeout-keep-alive 65 --no-access-log \
    > "$RUN_DIR/controller.log" 2>&1 &
  CONTROLLER_PID="$!"
  echo "$CONTROLLER_PID" > "$RUN_DIR/controller.pid"
  wait_for_api

  local password
  password="$(sed -n 's/^password=//p' "$RUN_DIR/controller-config/initial-admin-password")"
  [[ -n "$password" ]] || fail "initial password file is empty"
  WEB_TOKEN="$(curl -fsS -X POST "$BASE_URL/api/auth/login" \
    -H "content-type: application/json" \
    -d "{\"username\":\"pmman\",\"password\":\"$password\"}" | json_get token)"

  local local_node remote_node local_token remote_token
  local_node="$(api POST /api/nodes "{\"name\":\"$LOCAL_NODE_NAME\",\"hostname\":\"$LOCAL_NODE_NAME\",\"management_ip\":\"$LOCAL_ENDPOINT\",\"public_ip\":\"$LOCAL_ENDPOINT\",\"endpoint_ips\":[\"$LOCAL_ENDPOINT\"]}")"
  remote_node="$(api POST /api/nodes "{\"name\":\"$REMOTE_NODE_NAME\",\"hostname\":\"$REMOTE_NODE_NAME\",\"management_ip\":\"$REMOTE_ENDPOINT\",\"public_ip\":\"$REMOTE_ENDPOINT\",\"endpoint_ips\":[\"$REMOTE_ENDPOINT\"]}")"
  LOCAL_NODE_ID="$(printf '%s' "$local_node" | json_get node.id)"
  REMOTE_NODE_ID="$(printf '%s' "$remote_node" | json_get node.id)"
  local_token="$(printf '%s' "$local_node" | json_get agent_token)"
  remote_token="$(printf '%s' "$remote_node" | json_get agent_token)"

  PYTHONPATH="$ROOT_DIR/apps/agent:$ROOT_DIR/packages" \
    LINK42_SERVER_URL="$LOCAL_AGENT_URL" \
    LINK42_NODE_ID="$LOCAL_NODE_ID" \
    LINK42_AGENT_TOKEN="$local_token" \
    LINK42_POLL_INTERVAL="$POLL_INTERVAL" \
    "$PYTHON_BIN" -m link42_agent.main > "$RUN_DIR/local-agent.log" 2>&1 &
  LOCAL_AGENT_PID="$!"
  echo "$LOCAL_AGENT_PID" > "$RUN_DIR/local-agent.pid"

  tar -C "$ROOT_DIR" -czf "$RUN_DIR/agent-src.tar.gz" apps/agent packages
  local remote_agent_dir remote_start_script remote_run_dir_q
  remote_agent_dir="$RUN_DIR/remote-agent"
  remote_start_script="$remote_agent_dir/start-agent.sh"
  remote_run_dir_q="$(shell_quote "$remote_agent_dir")"
  ssh "$REMOTE_SSH" "umask 077; rm -rf $remote_run_dir_q && mkdir -p $remote_run_dir_q && chmod 700 $remote_run_dir_q && cat > $(shell_quote "$remote_agent_dir/agent-src.tar.gz")" < "$RUN_DIR/agent-src.tar.gz"
  ssh "$REMOTE_SSH" "cd $remote_run_dir_q && tar -xzf agent-src.tar.gz"
  remote_agent_script "$remote_agent_dir" "$remote_token" | ssh "$REMOTE_SSH" "umask 077; cat > $(shell_quote "$remote_start_script") && chmod 700 $(shell_quote "$remote_start_script")"
  ssh -f -n "$REMOTE_SSH" "cd $remote_run_dir_q && nohup ./start-agent.sh > $(shell_quote "$RUN_DIR/remote-agent.log") 2>&1 < /dev/null & echo \$! > $(shell_quote "$RUN_DIR/remote-agent.pid")"
  REMOTE_AGENT_PID=""
  for _ in $(seq 1 50); do
    REMOTE_AGENT_PID="$(ssh "$REMOTE_SSH" "cat $(shell_quote "$RUN_DIR/remote-agent.pid") 2>/dev/null" || true)"
    if [[ -n "$REMOTE_AGENT_PID" ]]; then
      break
    fi
    sleep 0.2
  done
  [[ -n "$REMOTE_AGENT_PID" ]] || fail "remote agent pid file was not written"

  write_state
  wait_for_nodes_online

  echo "[link42-real-e2e] ready"
  echo "  controller: $BASE_URL"
  echo "  run dir:    $RUN_DIR"
  echo "  nodes:      local=$LOCAL_NODE_ID remote=$REMOTE_NODE_ID"
  echo "  state:      $RUN_DIR/state.env"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
