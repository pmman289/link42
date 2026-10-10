#!/usr/bin/env bash
set -euo pipefail
umask 077
# Interface hint lists are intentionally word-split below; never expand them as
# filesystem globs while deciding which assets to remove.
set -f

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${LINK42_REAL_ENV_FILE:-/tmp/link42-real-e2e.env}"
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

RUN_DIR="${LINK42_REAL_RUN_DIR:-/tmp/link42-real-e2e}"
[[ ! -L "$RUN_DIR" ]] || {
  echo "[link42-real-e2e] refusing symbolic-link run directory: $RUN_DIR" >&2
  exit 1
}
RUN_MARKER="$RUN_DIR/.link42-real-e2e"
if [[ -e "$RUN_MARKER" && ( ! -f "$RUN_MARKER" || -L "$RUN_MARKER" ) ]]; then
  echo "[link42-real-e2e] refusing to clean unsafe run directory marker" >&2
  exit 1
fi
if [[ ! -f "$RUN_MARKER" ]]; then
  echo "[link42-real-e2e] refusing to clean unmarked run directory: $RUN_DIR" >&2
  exit 1
fi
if [[ -f "$RUN_DIR/state.env" ]]; then
  [[ ! -L "$RUN_DIR/state.env" ]] || {
    echo "[link42-real-e2e] refusing to source symbolic-link state file" >&2
    exit 1
  }
  [[ "$(stat -c '%a' "$RUN_DIR/state.env" 2>/dev/null || true)" == "600" ]] || {
    echo "[link42-real-e2e] refusing to source state file with unsafe permissions" >&2
    exit 1
  }
  # shellcheck disable=SC1090
  source "$RUN_DIR/state.env"
fi

REMOTE_SSH="${LINK42_REAL_REMOTE_SSH:-vpstest}"
LOCAL_WG_IFACES="${LINK42_REAL_LOCAL_WG_IFACES:-}"
REMOTE_WG_IFACES="${LINK42_REAL_REMOTE_WG_IFACES:-}"
LOCAL_MIMIC_IFACES="${LINK42_REAL_LOCAL_MIMIC_IFACES:-}"
REMOTE_MIMIC_IFACES="${LINK42_REAL_REMOTE_MIMIC_IFACES:-}"
PURGE_MIMIC="${LINK42_REAL_PURGE_MIMIC:-0}"

# 仅允许 Linux 接口名字符，避免清理提示中的路径穿越、通配符展开或
# 向 systemd 传入额外实例名。真实测试应使用专用接口前缀。
validate_iface_name() {
  local iface="$1"
  [[ "$iface" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$ ]] || {
    echo "[link42-real-e2e] invalid test interface name: $iface" >&2
    return 1
  }
}

validate_iface_list() {
  local iface
  for iface in $1; do
    validate_iface_name "$iface"
  done
}

shell_quote() {
  local value="$1"
  value=${value//\'/\'\\\'\'}
  printf "'%s'" "$value"
}

# 停止并强制清理指定进程。
stop_pid() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  [[ "$pid" =~ ^[0-9]{1,10}$ && "$pid" -gt 1 ]] || {
    echo "[link42-real-e2e] refusing invalid process ID: $pid" >&2
    return 1
  }
  kill "$pid" >/dev/null 2>&1 || true
  sleep 0.3
  kill -9 "$pid" >/dev/null 2>&1 || true
}

# 清理本机 WireGuard 测试接口和配置。
cleanup_local_iface() {
  local iface="$1"
  [[ -n "$iface" ]] || return 0
  wg-quick down "$iface" >/dev/null 2>&1 || true
  systemctl disable --now "wg-quick@$iface.service" >/dev/null 2>&1 || true
  ip link delete "$iface" >/dev/null 2>&1 || true
  rm -f "/etc/wireguard/$iface.conf" "/etc/wireguard/$iface.conf.link42-backup"
  (set +f; rm -f /etc/wireguard/"$iface".conf.link42-backup-*)
}

# 清理本机 mimic 测试配置和服务。
cleanup_local_mimic() {
  local iface="$1"
  [[ -n "$iface" ]] || return 0
  systemctl disable --now "mimic@$iface.service" >/dev/null 2>&1 || true
  systemctl reset-failed "mimic@$iface.service" >/dev/null 2>&1 || true
  rm -f "/etc/mimic/$iface.conf"
  rm -rf "/etc/link42/middleware/mimic/$iface"
}

# 清理本机 udp2raw 中间层测试资产。
cleanup_local_middleware() {
  systemctl disable --now 'link42-udp2raw-server@*.service' >/dev/null 2>&1 || true
  systemctl disable --now 'link42-udp2raw-client@*.service' >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/link42-udp2raw-server@.service
  rm -f /etc/systemd/system/link42-udp2raw-client@.service
  rm -f /usr/local/libexec/link42-udp2raw-systemd
  rm -f /usr/local/bin/udp2raw
  rm -rf /etc/link42/middleware/udp2raw
  systemctl daemon-reload >/dev/null 2>&1 || true
}

# 生成远端测试环境清理脚本。
remote_cleanup_script() {
  cat <<'SH'
set -eu
set -f
RUN_DIR="$1"
WG_IFACES="$2"
MIMIC_IFACES="$3"
PURGE_MIMIC="$4"

if [ -f "$RUN_DIR/remote-agent.pid" ]; then
  pid="$(cat "$RUN_DIR/remote-agent.pid")"
  case "$pid" in
    ''|*[!0-9]*) echo 'invalid remote agent process ID' >&2; exit 1 ;;
  esac
  [ "$pid" -gt 1 ] || { echo 'invalid remote agent process ID' >&2; exit 1; }
  kill "$pid" >/dev/null 2>&1 || true
  sleep 0.3
  kill -9 "$pid" >/dev/null 2>&1 || true
fi

for iface in $WG_IFACES; do
  wg-quick down "$iface" >/dev/null 2>&1 || true
  systemctl disable --now "wg-quick@$iface.service" >/dev/null 2>&1 || true
  ip link delete "$iface" >/dev/null 2>&1 || true
  rm -f "/etc/wireguard/$iface.conf" "/etc/wireguard/$iface.conf.link42-backup"
  (set +f; rm -f /etc/wireguard/"$iface".conf.link42-backup-*)
done

for iface in $MIMIC_IFACES; do
  systemctl disable --now "mimic@$iface.service" >/dev/null 2>&1 || true
  systemctl reset-failed "mimic@$iface.service" >/dev/null 2>&1 || true
  rm -f "/etc/mimic/$iface.conf"
  rm -rf "/etc/link42/middleware/mimic/$iface"
done

systemctl disable --now 'link42-udp2raw-server@*.service' >/dev/null 2>&1 || true
systemctl disable --now 'link42-udp2raw-client@*.service' >/dev/null 2>&1 || true
rm -f /etc/systemd/system/link42-udp2raw-server@.service
rm -f /etc/systemd/system/link42-udp2raw-client@.service
rm -f /usr/local/libexec/link42-udp2raw-systemd
rm -f /usr/local/bin/udp2raw
rm -rf /etc/link42/middleware/udp2raw
systemctl daemon-reload >/dev/null 2>&1 || true

if [ "$PURGE_MIMIC" = "1" ]; then
  apt-get purge -y mimic mimic-dkms >/tmp/link42-real-e2e-mimic-purge.log 2>&1 || true
  apt-get autoremove -y >/tmp/link42-real-e2e-autoremove.log 2>&1 || true
fi

rm -rf "$RUN_DIR/remote-agent"
SH
}

# 执行脚本主流程。
main() {
  validate_iface_list "$LOCAL_WG_IFACES"
  validate_iface_list "$REMOTE_WG_IFACES"
  validate_iface_list "$LOCAL_MIMIC_IFACES"
  validate_iface_list "$REMOTE_MIMIC_IFACES"

  if [[ -f "$RUN_DIR/local-agent.pid" ]]; then
    stop_pid "$(cat "$RUN_DIR/local-agent.pid")"
  fi
  if [[ -f "$RUN_DIR/controller.pid" ]]; then
    stop_pid "$(cat "$RUN_DIR/controller.pid")"
  fi

  for iface in $LOCAL_WG_IFACES; do
    cleanup_local_iface "$iface"
  done
  for iface in $LOCAL_MIMIC_IFACES; do
    cleanup_local_mimic "$iface"
  done
  cleanup_local_middleware

  if [[ "$PURGE_MIMIC" = "1" ]]; then
    apt-get purge -y mimic mimic-dkms >/tmp/link42-real-e2e-mimic-purge.log 2>&1 || true
    apt-get autoremove -y >/tmp/link42-real-e2e-autoremove.log 2>&1 || true
  fi

  remote_cleanup_script | ssh "$REMOTE_SSH" "sh -s -- $(shell_quote "$RUN_DIR") $(shell_quote "$REMOTE_WG_IFACES") $(shell_quote "$REMOTE_MIMIC_IFACES") $(shell_quote "$PURGE_MIMIC")" || true
  rm -rf "$RUN_DIR"
  echo "[link42-real-e2e] cleaned"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
