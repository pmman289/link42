#!/usr/bin/env bash
set -euo pipefail
umask 077

# 在本机搭建真实 Link42 主控 + 两个 Agent + 两条本机 WireGuard 接口的冒烟测试。
# 只操作 l42smoke* 前缀接口和配置文件；会使用真实 /etc/wireguard 和 wg-quick。

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-"$ROOT_DIR/.venv/bin/python"}"
UVICORN_BIN="${UVICORN_BIN:-"$ROOT_DIR/.venv/bin/uvicorn"}"
HOST="${LINK42_SMOKE_HOST:-127.0.0.1}"
PORT="${LINK42_SMOKE_PORT:-18042}"
BASE_URL="http://$HOST:$PORT"
RUN_DIR="${LINK42_SMOKE_RUN_DIR:-/tmp/link42-real-smoke}"
DB_PATH="${LINK42_SMOKE_DB:-$RUN_DIR/link42.db}"
RUN_MARKER="$RUN_DIR/.link42-real-smoke"
WG_DIR="${LINK42_SMOKE_WG_DIR:-/etc/wireguard}"
IFACE_A="${LINK42_SMOKE_IFACE_A:-l42smokea}"
IFACE_B="${LINK42_SMOKE_IFACE_B:-l42smokeb}"
NODE_A_ENDPOINT="${LINK42_SMOKE_NODE_A_ENDPOINT:-127.0.10.1}"
NODE_B_ENDPOINT="${LINK42_SMOKE_NODE_B_ENDPOINT:-127.0.10.2}"
PORT_A="${LINK42_SMOKE_PORT_A:-51881}"
PORT_B="${LINK42_SMOKE_PORT_B:-51882}"
ADDR_A="${LINK42_SMOKE_ADDR_A:-10.42.10.1/32}"
ADDR_B="${LINK42_SMOKE_ADDR_B:-10.42.10.2/32}"
PING_A="${ADDR_A%%/*}"
PING_B="${ADDR_B%%/*}"
PIDS=()

# 这些值会拼入 /etc/wireguard 路径和 systemd 实例名，只接受合法接口名。
validate_iface_name() {
  local iface="$1"
  [[ "$iface" =~ ^l42smoke[A-Za-z0-9_-]{0,7}$ ]] || {
    echo "invalid smoke interface name: $iface" >&2
    exit 1
  }
}

# 检查冒烟测试依赖命令。
require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

# 清理冒烟测试使用的 WireGuard 接口。
cleanup_interface() {
  local iface="$1"
  wg-quick down "$iface" >/dev/null 2>&1 || true
  ip link delete "$iface" >/dev/null 2>&1 || true
  systemctl disable --now "wg-quick@$iface.service" >/dev/null 2>&1 || true
  rm -f "$WG_DIR/$iface.conf"
  rm -f "$WG_DIR/$iface.conf".link42-backup-*
}

# 清理冒烟测试启动的进程和临时资源。
cleanup() {
  set +e
  for pid in "${PIDS[@]}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  sleep 1
  for pid in "${PIDS[@]}"; do
    kill -9 "$pid" >/dev/null 2>&1 || true
  done
  cleanup_interface "$IFACE_A"
  cleanup_interface "$IFACE_B"
  if [[ -f "$RUN_MARKER" && ! -L "$RUN_MARKER" ]]; then
    rm -rf "$RUN_DIR"
  fi
  rm -f "$DB_PATH"
}

# JSON values are encoded as data, including quotes, backslashes and newlines.
login_json() {
  "$PYTHON_BIN" -c 'import json,sys; print(json.dumps({"username":"pmman", "password":sys.argv[1]}))' "$1"
}

node_json() {
  "$PYTHON_BIN" -c 'import json,sys; name,endpoint=sys.argv[1:]; print(json.dumps({"name":name, "hostname":name, "management_ip":endpoint, "public_ip":endpoint, "endpoint_ips":[endpoint]}))' "$1" "$2"
}

# 从 JSON 标准输入中读取指定字段。
json_get() {
  "$PYTHON_BIN" -c 'import json,sys; data=json.load(sys.stdin); path=sys.argv[1].split("."); value=data
for key in path:
    value = value[int(key)] if isinstance(value, list) else value[key]
print(value)' "$1"
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
      -d "$body"
  else
    curl -fsS -X "$method" "$BASE_URL$path" \
      -H "authorization: Bearer $WEB_TOKEN"
  fi
}

# 等待测试主控健康检查通过。
wait_for_api() {
  for _ in $(seq 1 80); do
    if curl -fsS "$BASE_URL/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "API did not become healthy" >&2
  tail -120 "$RUN_DIR/api.log" >&2 || true
  return 1
}

# 等待指定类型任务成功达到目标数量。
wait_for_task_type() {
  local task_type="$1"
  local expected_count="$2"
  for _ in $(seq 1 120); do
    local count
    count="$("$PYTHON_BIN" - "$DB_PATH" "$task_type" <<'PY'
import sqlite3
import sys

db_path, task_type = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
print(conn.execute(
    "select count(*) from agent_tasks where type = ? and status = 'succeeded'",
    (task_type,),
).fetchone()[0])
PY
)"
    if [[ "$count" -ge "$expected_count" ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "timed out waiting for $expected_count succeeded $task_type tasks" >&2
  "$PYTHON_BIN" - "$DB_PATH" <<'PY' >&2
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
for row in conn.execute("select id, node_id, type, status, result from agent_tasks order by id"):
    print(row)
PY
  return 1
}

# 等待指定数量的测试节点上线。
wait_for_node_count_online() {
  for _ in $(seq 1 80); do
    local online
    online="$(api GET /api/nodes | "$PYTHON_BIN" -c 'import json,sys; print(sum(1 for n in json.load(sys.stdin) if n["status"] == "online"))')"
    if [[ "$online" -ge 2 ]]; then
      return 0
    fi
    sleep 0.5
  done
  echo "timed out waiting for two online nodes" >&2
  api GET /api/nodes >&2 || true
  return 1
}

# 创建冒烟测试使用的一对 WireGuard 配置。
create_config_pair() {
  local private_a public_a private_b public_b psk
  private_a="$(wg genkey)"
  public_a="$(printf '%s' "$private_a" | wg pubkey)"
  private_b="$(wg genkey)"
  public_b="$(printf '%s' "$private_b" | wg pubkey)"
  psk="$(wg genpsk)"

  local config_a config_b iface_a_id iface_b_id
  config_a="$(api POST /api/nodes/"$NODE_A_ID"/wireguard/configs "$(
    "$PYTHON_BIN" -c 'import json,sys; print(json.dumps({
      "name": sys.argv[1],
      "tunnel_ips": [sys.argv[2]],
      "listen_port": int(sys.argv[3]),
      "private_key": sys.argv[4],
      "mtu": 1420,
      "table_name": None,
    }))' "$IFACE_A" "$ADDR_A" "$PORT_A" "$private_a"
  )")"
  iface_a_id="$(printf '%s' "$config_a" | json_get id)"
  config_b="$(api POST /api/nodes/"$NODE_B_ID"/wireguard/configs "$(
    "$PYTHON_BIN" -c 'import json,sys; print(json.dumps({
      "name": sys.argv[1],
      "tunnel_ips": [sys.argv[2]],
      "listen_port": int(sys.argv[3]),
      "private_key": sys.argv[4],
      "mtu": 1420,
      "table_name": None,
    }))' "$IFACE_B" "$ADDR_B" "$PORT_B" "$private_b"
  )")"
  iface_b_id="$(printf '%s' "$config_b" | json_get id)"

  api PUT /api/wireguard/configs/"$iface_a_id"/peer "$(
    "$PYTHON_BIN" -c 'import json,sys; print(json.dumps({
      "name": "node-b",
      "public_key": sys.argv[1],
      "preshared_key": sys.argv[2],
      "endpoint_host": sys.argv[3],
      "endpoint_port": int(sys.argv[4]),
      "allowed_ips": [sys.argv[5]],
      "persistent_keepalive": 1,
    }))' "$public_b" "$psk" "$NODE_B_ENDPOINT" "$PORT_B" "$ADDR_B"
  )" >/dev/null
  api PUT /api/wireguard/configs/"$iface_b_id"/peer "$(
    "$PYTHON_BIN" -c 'import json,sys; print(json.dumps({
      "name": "node-a",
      "public_key": sys.argv[1],
      "preshared_key": sys.argv[2],
      "endpoint_host": sys.argv[3],
      "endpoint_port": int(sys.argv[4]),
      "allowed_ips": [sys.argv[5]],
      "persistent_keepalive": 1,
    }))' "$public_a" "$psk" "$NODE_A_ENDPOINT" "$PORT_A" "$ADDR_A"
  )" >/dev/null

  IFACE_A_ID="$iface_a_id"
  IFACE_B_ID="$iface_b_id"
}

# 生成并确认指定接口的部署计划。
confirm_plan() {
  local iface_id="$1"
  local plan plan_id
  plan="$(api POST /api/wireguard/configs/"$iface_id"/plan-apply)"
  plan_id="$(printf '%s' "$plan" | json_get id)"
  api POST /api/change-plans/"$plan_id"/confirm >/dev/null
}

# 请求停止指定测试接口。
stop_iface() {
  api POST /api/wireguard/configs/"$1"/stop >/dev/null || true
}

# 删除指定测试接口记录。
delete_iface() {
  api DELETE /api/wireguard/configs/"$1" >/dev/null || true
}

# 执行脚本主流程。
main() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "real local smoke test must run as root because wg-quick changes host networking" >&2
    exit 1
  fi
  require_command curl
  require_command wg
  require_command wg-quick
  require_command ip
  require_command systemctl
  require_command realpath
  validate_iface_name "$IFACE_A"
  validate_iface_name "$IFACE_B"

  mkdir -p "$RUN_DIR"
  [[ ! -L "$RUN_DIR" ]] || {
    echo "smoke run directory must not be a symbolic link: $RUN_DIR" >&2
    exit 1
  }
  chmod 0700 "$RUN_DIR"
  if [[ -e "$RUN_MARKER" && ( ! -f "$RUN_MARKER" || -L "$RUN_MARKER" ) ]]; then
    echo "unsafe smoke run directory marker: $RUN_MARKER" >&2
    exit 1
  fi
  if [[ ! -f "$RUN_MARKER" ]]; then
    if [[ -n "$(find "$RUN_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
      echo "refusing to reuse non-empty unmarked smoke run directory: $RUN_DIR" >&2
      exit 1
    fi
    printf 'Link42 real smoke run directory\n' > "$RUN_MARKER"
    chmod 0600 "$RUN_MARKER"
  fi
  local run_root db_root
  run_root="$(realpath -m "$RUN_DIR")"
  db_root="$(realpath -m "$DB_PATH")"
  if [[ "$db_root" != "$run_root"/* ]]; then
    echo "smoke database path must stay inside run directory: $DB_PATH" >&2
    exit 1
  fi
  rm -f "$DB_PATH" "$RUN_DIR"/*.log
  trap cleanup EXIT

  cleanup_interface "$IFACE_A"
  cleanup_interface "$IFACE_B"

  LINK42_DATABASE_URL="sqlite:///$DB_PATH" \
    LINK42_CONFIG_DIR="$RUN_DIR/controller-config" \
    LINK42_MASTER_KEY_FILE="$RUN_DIR/controller-config/master.key" \
    LINK42_WEB_DIST_DIR="$ROOT_DIR/apps/web/dist" \
    PYTHONPATH="$ROOT_DIR/apps/api:$ROOT_DIR/packages" \
    "$UVICORN_BIN" link42_api.main:app --host "$HOST" --port "$PORT" --proxy-headers --timeout-keep-alive 65 --no-access-log \
    > "$RUN_DIR/api.log" 2>&1 &
  PIDS+=("$!")
  wait_for_api

  local password
  password="$(sed -n 's/^password=//p' "$RUN_DIR/controller-config/initial-admin-password")"
  [[ -n "$password" ]] || { echo "initial password file is empty" >&2; return 1; }
  WEB_TOKEN="$(curl -fsS -X POST "$BASE_URL/api/auth/login" \
    -H "content-type: application/json" \
    --data-binary "$(login_json "$password")" | json_get token)"

  local node_a node_b token_a token_b
  node_a="$(api POST /api/nodes "$(node_json smoke-node-a "$NODE_A_ENDPOINT")")"
  node_b="$(api POST /api/nodes "$(node_json smoke-node-b "$NODE_B_ENDPOINT")")"
  NODE_A_ID="$(printf '%s' "$node_a" | json_get node.id)"
  NODE_B_ID="$(printf '%s' "$node_b" | json_get node.id)"
  token_a="$(printf '%s' "$node_a" | json_get agent_token)"
  token_b="$(printf '%s' "$node_b" | json_get agent_token)"

  LINK42_SERVER_URL="$BASE_URL" LINK42_NODE_ID="$NODE_A_ID" LINK42_AGENT_TOKEN="$token_a" \
    PYTHONPATH="$ROOT_DIR/apps/agent:$ROOT_DIR/packages" \
    LINK42_WIREGUARD_DIR="$WG_DIR" LINK42_AGENT_DRY_RUN=0 LINK42_POLL_INTERVAL=1 \
    "$PYTHON_BIN" -m link42_agent.main > "$RUN_DIR/agent-a.log" 2>&1 &
  PIDS+=("$!")
  LINK42_SERVER_URL="$BASE_URL" LINK42_NODE_ID="$NODE_B_ID" LINK42_AGENT_TOKEN="$token_b" \
    PYTHONPATH="$ROOT_DIR/apps/agent:$ROOT_DIR/packages" \
    LINK42_WIREGUARD_DIR="$WG_DIR" LINK42_AGENT_DRY_RUN=0 LINK42_POLL_INTERVAL=1 \
    "$PYTHON_BIN" -m link42_agent.main > "$RUN_DIR/agent-b.log" 2>&1 &
  PIDS+=("$!")

  wait_for_node_count_online
  create_config_pair
  confirm_plan "$IFACE_A_ID"
  confirm_plan "$IFACE_B_ID"
  wait_for_task_type wireguard.apply_config 2

  ping -c 1 -W 2 "$PING_A" >/dev/null
  ping -c 1 -W 2 "$PING_B" >/dev/null

  stop_iface "$IFACE_A_ID"
  stop_iface "$IFACE_B_ID"
  wait_for_task_type wireguard.stop_interface 2

  delete_iface "$IFACE_A_ID"
  delete_iface "$IFACE_B_ID"
  wait_for_task_type wireguard.delete_config 2

  echo "real local smoke test passed: nodes=$NODE_A_ID,$NODE_B_ID interfaces=$IFACE_A,$IFACE_B"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
