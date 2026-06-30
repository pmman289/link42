#!/bin/sh
set -eu

SCRIPT_URL="https://get.pmman.tech/sh/link42-agent.sh"
RES_BASE_URL="${LINK42_RES_BASE_URL:-https://get.pmman.tech/res/link42}"
AGENT_VERSION="${LINK42_AGENT_VERSION:-latest}"
INSTALL_DIR="${LINK42_INSTALL_DIR:-/opt/link42-agent}"
BIN_PATH="${LINK42_AGENT_BIN:-/usr/local/bin/link42-agent}"
ENV_DIR="${LINK42_ENV_DIR:-/etc/link42}"
ENV_FILE="$ENV_DIR/agent.env"
SERVICE_NAME="link42-agent"
POLL_INTERVAL="${LINK42_POLL_INTERVAL:-2}"
WIREGUARD_DIR="${LINK42_WIREGUARD_DIR:-/etc/wireguard}"
DRY_RUN="${LINK42_AGENT_DRY_RUN:-0}"
ACTION="${1:-install}"

log() {
  printf '%s\n' "[link42-agent] $*"
}

fail() {
  printf '%s\n' "[link42-agent] ERROR: $*" >&2
  exit 1
}

need_env() {
  eval "value=\${$1:-}"
  [ -n "$value" ] || fail "missing required environment variable: $1"
}

shell_quote() {
  printf "%s" "$1" | sed "s/'/'\\\\''/g; 1s/^/'/; \$s/\$/'/"
}

run_as_root_hint() {
  cat >&2 <<EOF
Usage:
  curl -fsSL $SCRIPT_URL | sudo env \\
    LINK42_SERVER_URL=http://controller:8000 \\
    LINK42_NODE_ID=1 \\
    LINK42_AGENT_TOKEN=token \\
    sh

  curl -fsSL $SCRIPT_URL | sudo sh -s -- uninstall
EOF
}

if [ "$(id -u)" -ne 0 ]; then
  run_as_root_hint
  fail "please run as root"
fi

detect_service_backend() {
  if command -v systemctl >/dev/null 2>&1; then
    SERVICE_BACKEND="systemd"
  elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then
    SERVICE_BACKEND="openrc"
  elif command -v uci >/dev/null 2>&1 && command -v ifup >/dev/null 2>&1 && [ -f /etc/rc.common ]; then
    SERVICE_BACKEND="openwrt-procd"
  else
    SERVICE_BACKEND="none"
  fi
}

uninstall_systemd_service() {
  if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ] || systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1; then
    systemctl disable --now "$SERVICE_NAME.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$SERVICE_NAME.service" >/dev/null 2>&1 || true
  fi
}

uninstall_openrc_service() {
  if [ -f "/etc/init.d/$SERVICE_NAME" ]; then
    rc-service "$SERVICE_NAME" stop >/dev/null 2>&1 || true
    rc-update del "$SERVICE_NAME" default >/dev/null 2>&1 || true
    rm -f "/etc/init.d/$SERVICE_NAME"
  fi
}

uninstall_openwrt_service() {
  if [ -f "/etc/init.d/$SERVICE_NAME" ]; then
    "/etc/init.d/$SERVICE_NAME" stop >/dev/null 2>&1 || true
    "/etc/init.d/$SERVICE_NAME" disable >/dev/null 2>&1 || true
    rm -f "/etc/init.d/$SERVICE_NAME"
  fi
}

uninstall_agent() {
  detect_service_backend
  if [ "$SERVICE_BACKEND" = "systemd" ]; then
    uninstall_systemd_service
  elif [ "$SERVICE_BACKEND" = "openrc" ]; then
    uninstall_openrc_service
  elif [ "$SERVICE_BACKEND" = "openwrt-procd" ]; then
    uninstall_openwrt_service
  else
    log "service manager not found; removing files only"
  fi

  rm -f "$BIN_PATH"
  rm -f "$ENV_FILE"
  rmdir "$ENV_DIR" >/dev/null 2>&1 || true
  rm -rf "$INSTALL_DIR"
  log "uninstalled $SERVICE_NAME"
  log "wireguard configs were not removed: $WIREGUARD_DIR"
}

case "$ACTION" in
  install)
    ;;
  uninstall|remove)
    uninstall_agent
    exit 0
    ;;
  *)
    run_as_root_hint
    fail "unknown action: $ACTION"
    ;;
esac

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

need_env LINK42_SERVER_URL
need_env LINK42_NODE_ID
need_env LINK42_AGENT_TOKEN

ARCH="$(uname -m)"
AGENT_INSTALL_MODE="binary"
if command -v uci >/dev/null 2>&1 && [ -f /etc/rc.common ]; then
  AGENT_FILE="link42-agent-source.tar.gz"
  AGENT_INSTALL_MODE="source"
else
  case "$ARCH" in
    x86_64|amd64)
      AGENT_FILE="link42-agent-linux-x64"
      ;;
    aarch64|arm64|armv7l|armv6l)
      fail "unsupported ARM Linux without OpenWrt source-mode installer"
      ;;
    *)
      fail "unsupported architecture '$ARCH'; this installer currently supports x86_64 and OpenWrt source mode"
      ;;
  esac
fi

detect_service_backend
if [ "$SERVICE_BACKEND" = "none" ]; then
  fail "no supported service manager found; install systemd, OpenRC, or OpenWrt procd first"
fi

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl wireguard-tools
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ca-certificates curl wireguard-tools
  elif command -v opkg >/dev/null 2>&1; then
    missing_packages=""
    command -v python3 >/dev/null 2>&1 || missing_packages="$missing_packages python3"
    if ! python3 - <<'PY' >/dev/null 2>&1
import ssl
PY
    then
      missing_packages="$missing_packages python3-openssl"
    fi
    if ! python3 - <<'PY' >/dev/null 2>&1
import encodings.idna
PY
    then
      missing_packages="$missing_packages python3-codecs"
    fi
    command -v wg >/dev/null 2>&1 || missing_packages="$missing_packages wireguard-tools"
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
      missing_packages="$missing_packages curl"
    fi
    if [ -z "$missing_packages" ]; then
      log "OpenWrt dependencies already present; skipping opkg install"
    else
      opkg update || log "warning: opkg update failed; continuing because packages may still be installable"
      opkg install ca-bundle $missing_packages
    fi
  else
    log "package manager not found; skipping dependency installation"
  fi
}

download_agent() {
  mkdir -p "$INSTALL_DIR"
  mkdir -p "$(dirname "$BIN_PATH")"
  tmp_file="$(mktemp "${TMPDIR:-/tmp}/link42-agent.XXXXXX")"
  tmp_sha="$(mktemp "${TMPDIR:-/tmp}/link42-agent.sha256.XXXXXX")"
  trap 'rm -f "$tmp_file" "$tmp_sha"' EXIT HUP INT TERM

  if [ "$AGENT_VERSION" = "latest" ]; then
    url="$RES_BASE_URL/$AGENT_FILE"
  else
    url="$RES_BASE_URL/$AGENT_VERSION/$AGENT_FILE"
  fi

  log "downloading $url"
  if command -v curl >/dev/null 2>&1; then
    curl -fL "$url" -o "$tmp_file"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$tmp_file" "$url"
  else
    fail "curl or wget is required to download the agent"
  fi

  sha_url="$url.sha256"
  if command -v sha256sum >/dev/null 2>&1; then
    if command -v curl >/dev/null 2>&1; then
      curl -fsL "$sha_url" -o "$tmp_sha" || true
    elif command -v wget >/dev/null 2>&1; then
      wget -q -O "$tmp_sha" "$sha_url" || true
    fi
    if [ -s "$tmp_sha" ]; then
      expected="$(awk '{print $1}' "$tmp_sha")"
      actual="$(sha256sum "$tmp_file" | awk '{print $1}')"
      [ "$expected" = "$actual" ] || fail "sha256 mismatch for downloaded agent"
    else
      log "sha256 file not found; skipping checksum verification"
    fi
  fi

  if [ "$AGENT_INSTALL_MODE" = "source" ]; then
    rm -rf "$INSTALL_DIR/src"
    mkdir -p "$INSTALL_DIR/src"
    tar -xzf "$tmp_file" -C "$INSTALL_DIR/src"
    cat > "$BIN_PATH" <<EOF
#!/bin/sh
set -eu
if [ -f "$ENV_FILE" ]; then
  set -a
  . "$ENV_FILE"
  set +a
fi
export PYTHONPATH="$INSTALL_DIR/src/apps/agent:$INSTALL_DIR/src/packages"
exec python3 -m link42_agent.main "\$@"
EOF
    chmod 0755 "$BIN_PATH"
  else
    install -m 0755 "$tmp_file" "$BIN_PATH"
  fi
  rm -f "$tmp_file" "$tmp_sha"
  trap - EXIT HUP INT TERM
}

write_env_file() {
  mkdir -p "$ENV_DIR" "$WIREGUARD_DIR"
  chmod 0755 "$ENV_DIR"
  {
    printf 'LINK42_SERVER_URL=%s\n' "$(shell_quote "$LINK42_SERVER_URL")"
    printf 'LINK42_NODE_ID=%s\n' "$(shell_quote "$LINK42_NODE_ID")"
    printf 'LINK42_AGENT_TOKEN=%s\n' "$(shell_quote "$LINK42_AGENT_TOKEN")"
    printf 'LINK42_WIREGUARD_DIR=%s\n' "$(shell_quote "$WIREGUARD_DIR")"
    printf 'LINK42_AGENT_DRY_RUN=%s\n' "$(shell_quote "$DRY_RUN")"
    printf 'LINK42_POLL_INTERVAL=%s\n' "$(shell_quote "$POLL_INTERVAL")"
  } > "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
}

stop_existing_service() {
  if [ "$SERVICE_BACKEND" = "systemd" ]; then
    systemctl stop "$SERVICE_NAME.service" >/dev/null 2>&1 || true
  elif [ "$SERVICE_BACKEND" = "openrc" ]; then
    rc-service "$SERVICE_NAME" stop >/dev/null 2>&1 || true
  elif [ "$SERVICE_BACKEND" = "openwrt-procd" ] && [ -f "/etc/init.d/$SERVICE_NAME" ]; then
    "/etc/init.d/$SERVICE_NAME" stop >/dev/null 2>&1 || true
  fi
}

install_systemd_service() {
  cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Link42 Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_PATH
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME.service"
}

install_openrc_service() {
  cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/sbin/openrc-run
name="Link42 Agent"
description="Link42 Agent"
command="$BIN_PATH"
command_background="yes"
pidfile="/run/$SERVICE_NAME.pid"
output_log="/var/log/$SERVICE_NAME.log"
error_log="/var/log/$SERVICE_NAME.err"

depend() {
  need net
  after firewall
}

start_pre() {
  checkpath -d -m 0755 /run
  if [ -f "$ENV_FILE" ]; then
    set -a
    . "$ENV_FILE"
    set +a
  fi
}
EOF
  chmod 0755 "/etc/init.d/$SERVICE_NAME"
  rc-update add "$SERVICE_NAME" default
  rc-service "$SERVICE_NAME" restart
}

install_openwrt_service() {
  cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1

start_service() {
  procd_open_instance
  procd_set_param command $BIN_PATH
  procd_set_param respawn 10 5 5
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}

stop_service() {
  return 0
}

reload_service() {
  stop
  start
}

status_service() {
  if service_running; then
    echo "running"
    return 0
  fi
  echo "inactive"
  return 3
}
EOF
  chmod 0755 "/etc/init.d/$SERVICE_NAME"
  "/etc/init.d/$SERVICE_NAME" enable
  "/etc/init.d/$SERVICE_NAME" restart
}

log "installing dependencies"
install_packages

if ! command -v wg >/dev/null 2>&1; then
  fail "wg is not installed; install wireguard-tools and rerun this script"
fi

if ! command -v wg-quick >/dev/null 2>&1; then
  if ! command -v uci >/dev/null 2>&1; then
    log "wg-quick not found; this host must use a supported non-wg-quick backend such as OpenWrt UCI"
  fi
fi

stop_existing_service
download_agent
write_env_file

if [ "$SERVICE_BACKEND" = "systemd" ]; then
  install_systemd_service
elif [ "$SERVICE_BACKEND" = "openrc" ]; then
  install_openrc_service
else
  install_openwrt_service
fi

log "installed $SERVICE_NAME using $SERVICE_BACKEND"
log "binary: $BIN_PATH"
log "config: $ENV_FILE"
