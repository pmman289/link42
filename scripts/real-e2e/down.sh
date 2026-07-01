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

REMOTE_SSH="${LINK42_REAL_REMOTE_SSH:-remote-test-host}"
LOCAL_WG_IFACES="${LINK42_REAL_LOCAL_WG_IFACES:-}"
REMOTE_WG_IFACES="${LINK42_REAL_REMOTE_WG_IFACES:-}"
LOCAL_MIMIC_IFACES="${LINK42_REAL_LOCAL_MIMIC_IFACES:-}"
REMOTE_MIMIC_IFACES="${LINK42_REAL_REMOTE_MIMIC_IFACES:-}"
PURGE_MIMIC="${LINK42_REAL_PURGE_MIMIC:-0}"

stop_pid() {
  local pid="${1:-}"
  [[ -n "$pid" ]] || return 0
  kill "$pid" >/dev/null 2>&1 || true
  sleep 0.3
  kill -9 "$pid" >/dev/null 2>&1 || true
}

cleanup_local_iface() {
  local iface="$1"
  [[ -n "$iface" ]] || return 0
  wg-quick down "$iface" >/dev/null 2>&1 || true
  systemctl disable --now "wg-quick@$iface.service" >/dev/null 2>&1 || true
  ip link delete "$iface" >/dev/null 2>&1 || true
  rm -f "/etc/wireguard/$iface.conf" "/etc/wireguard/$iface.conf.link42-backup"
  rm -f /etc/wireguard/"$iface".conf.link42-backup-*
}

cleanup_local_mimic() {
  local iface="$1"
  [[ -n "$iface" ]] || return 0
  systemctl disable --now "mimic@$iface.service" >/dev/null 2>&1 || true
  systemctl reset-failed "mimic@$iface.service" >/dev/null 2>&1 || true
  rm -f "/etc/mimic/$iface.conf"
  rm -rf "/etc/link42/middleware/mimic/$iface"
}

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

remote_cleanup_script() {
  cat <<'SH'
set -eu
RUN_DIR="$1"
WG_IFACES="$2"
MIMIC_IFACES="$3"
PURGE_MIMIC="$4"

if [ -f "$RUN_DIR/remote-agent.pid" ]; then
  kill "$(cat "$RUN_DIR/remote-agent.pid")" >/dev/null 2>&1 || true
  sleep 0.3
  kill -9 "$(cat "$RUN_DIR/remote-agent.pid")" >/dev/null 2>&1 || true
fi

for iface in $WG_IFACES; do
  wg-quick down "$iface" >/dev/null 2>&1 || true
  systemctl disable --now "wg-quick@$iface.service" >/dev/null 2>&1 || true
  ip link delete "$iface" >/dev/null 2>&1 || true
  rm -f "/etc/wireguard/$iface.conf" "/etc/wireguard/$iface.conf.link42-backup"
  rm -f /etc/wireguard/"$iface".conf.link42-backup-*
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

main() {
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

  remote_cleanup_script | ssh "$REMOTE_SSH" "sh -s -- '$RUN_DIR' '$REMOTE_WG_IFACES' '$REMOTE_MIMIC_IFACES' '$PURGE_MIMIC'" || true
  rm -rf "$RUN_DIR"
  echo "[link42-real-e2e] cleaned"
}

main "$@"
