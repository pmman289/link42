#!/bin/sh
set -eu

SCRIPT_URL="${LINK42_SERVER_URL:-http://controller:8000}/sh/link42-agent.sh"
AGENT_VERSION="${LINK42_AGENT_VERSION:-latest}"
INSTALL_DIR="${LINK42_INSTALL_DIR:-/opt/link42-agent}"
BIN_PATH="${LINK42_AGENT_BIN:-/usr/local/bin/link42-agent}"
ENV_DIR="${LINK42_ENV_DIR:-/etc/link42}"
ENV_FILE="$ENV_DIR/agent.env"
SERVICE_NAME="${LINK42_AGENT_SERVICE_NAME:-link42-agent}"
MIDDLEWARE_DIR="$ENV_DIR/middleware"
UDP2RAW_CONFIG_DIR="$MIDDLEWARE_DIR/udp2raw"
UDP2RAW_BIN="${LINK42_UDP2RAW_BIN:-/usr/local/bin/udp2raw}"
UDP2RAW_LIBEXEC="/usr/local/libexec/link42-udp2raw-systemd"
MIMIC_CONFIG_DIR="$MIDDLEWARE_DIR/mimic"
MIMIC_SYSTEM_CONFIG_DIR="${LINK42_MIMIC_SYSTEM_CONFIG_DIR:-/etc/mimic}"
KEEP_MIDDLEWARE="${LINK42_KEEP_MIDDLEWARE:-0}"
POLL_INTERVAL="${LINK42_POLL_INTERVAL:-5}"
HTTP_TIMEOUT="${LINK42_HTTP_TIMEOUT:-10}"
HEARTBEAT_TIMEOUT="${LINK42_HEARTBEAT_TIMEOUT:-5}"
POLL_JITTER="${LINK42_POLL_JITTER:-0.2}"
COMMAND_TIMEOUT="${LINK42_COMMAND_TIMEOUT:-5}"
GRE_DIR="${LINK42_GRE_DIR:-/etc/link42/gre}"
LOG_LEVEL="${LINK42_LOG_LEVEL:-INFO}"
WIREGUARD_DIR="${LINK42_WIREGUARD_DIR:-/etc/wireguard}"
DRY_RUN="${LINK42_AGENT_DRY_RUN:-0}"
# Keep an untrusted release response from filling the filesystem before its
# checksum can be verified.  This matches the cap used by the in-agent
# self-upgrade path.
MAX_AGENT_DOWNLOAD_SIZE=$((512 * 1024 * 1024))
ACTION="${1:-install}"

# Keep the caller's explicit values separate from values restored from an
# existing installation.  During uninstall the service environment is the
# source of truth when the original install used custom paths.
INPUT_LINK42_INSTALL_DIR="${LINK42_INSTALL_DIR-}"
INPUT_LINK42_AGENT_BIN="${LINK42_AGENT_BIN-}"
INPUT_LINK42_ENV_DIR="${LINK42_ENV_DIR-}"
INPUT_LINK42_UDP2RAW_BIN="${LINK42_UDP2RAW_BIN-}"
INPUT_LINK42_MIMIC_SYSTEM_CONFIG_DIR="${LINK42_MIMIC_SYSTEM_CONFIG_DIR-}"

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

# POSIX shell 校验，无需先安装 Python；与主控一样仅接受无路径的 HTTP(S) URL。
configure_download_urls() {
  controller_url="${LINK42_SERVER_URL%/}"
  case "$controller_url" in
    http://*) authority="${controller_url#http://}" ;;
    https://*) authority="${controller_url#https://}" ;;
    *) fail "LINK42_SERVER_URL must be an absolute HTTP(S) URL" ;;
  esac
  case "$authority" in
    ''|*[![:graph:]]*|*[\"\'\\/@?#]*) fail "LINK42_SERVER_URL must not contain credentials, a path, query or fragment" ;;
  esac
  port=""
  case "$authority" in
    \[*\]*)
      host="${authority%%]*}]"
      suffix="${authority#*]}"
      case "$host" in *:*) ;; *) fail "invalid IPv6 controller URL" ;; esac
      case "$suffix" in '') ;; :?*) port="${suffix#:}" ;; *) fail "invalid controller port" ;; esac
      ;;
    *:*)
      host="${authority%:*}"
      port="${authority##*:}"
      case "$host" in ''|*:*|*[\[\]]*) fail "invalid controller host" ;; esac
      [ -n "$port" ] || fail "invalid controller port"
      ;;
    *[\[\]]*) fail "invalid controller host" ;;
  esac
  if [ -n "$port" ]; then
    case "$port" in *[!0-9]*) fail "invalid controller port" ;; esac
    [ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null || fail "invalid controller port"
  fi
  LINK42_SERVER_URL="$controller_url"
  SCRIPT_URL="$controller_url/sh/link42-agent.sh"
  # LINK42_RES_BASE_URL is deprecated and deliberately ignored.
  RES_BASE_URL="$controller_url/res/link42"
}

shell_quote() {
  printf "%s" "$1" | sed "s/'/'\\\\''/g; 1s/^/'/; \$s/\$/'/"
}

systemd_quote() {
  printf '"'
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/%/%%/g'
  printf '"'
}

systemd_exec_quote() {
  # ExecStart also expands environment variables; $$ denotes a literal $.
  systemd_quote "$1" | sed 's/\$/$$/g'
}

normalize_install_path() {
  # Normalize lexical components before checking destructive cleanup targets.
  # Inspect the original path first so normalization cannot conceal a symlink.
  reject_symlink_path "$1"
  remaining_path="$1"
  case "$remaining_path" in
    /*) ;;
    *) remaining_path="$(pwd)/$remaining_path" ;;
  esac
  normalized_path=""
  while [ -n "$remaining_path" ]; do
    component="${remaining_path%%/*}"
    case "$remaining_path" in
      */*) remaining_path="${remaining_path#*/}" ;;
      *) remaining_path="" ;;
    esac
    case "$component" in
      ''|.) ;;
      ..) normalized_path="${normalized_path%/*}" ;;
      *) normalized_path="$normalized_path/$component" ;;
    esac
  done
  printf '%s\n' "${normalized_path:-/}"
}

reject_symlink_path() {
  path="$1"
  case "$path" in
    /*) ;;
    *) path="$(pwd)/$path" ;;
  esac
  while [ "$path" != "/" ] && [ -n "$path" ]; do
    [ ! -L "$path" ] || fail "path must not contain a symbolic link: $path"
    path="$(dirname "$path")"
  done
}

reject_dangerous_path() {
  case "$1" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/sys|/tmp|/usr|/usr/local|/var|/var/lib)
      fail "refusing to use a system root as an installation path: $1"
      ;;
  esac
}

validate_service_name() {
  case "$1" in
    ''|*[!A-Za-z0-9_.@-]*) fail "invalid service name: $1" ;;
  esac
}

is_musl_system() {
  if [ -f /etc/alpine-release ]; then
    return 0
  fi
  if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    return 0
  fi
  return 1
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

if [ "$ACTION" = "--help" ] || [ "$ACTION" = "-h" ] || [ "$ACTION" = "help" ]; then
  run_as_root_hint
  exit 0
fi

discover_uninstall_env_file() {
  [ "$ACTION" = "uninstall" ] || [ "$ACTION" = "remove" ] || return
  [ -n "$INPUT_LINK42_ENV_DIR" ] && return

  candidate=""
  unit_file="/etc/systemd/system/$SERVICE_NAME.service"
  if [ -f "$unit_file" ]; then
    candidate="$(sed -n 's/^EnvironmentFile=//p' "$unit_file" | head -n 1)"
    case "$candidate" in
      -*) candidate="${candidate#-}" ;;
    esac
    case "$candidate" in
      \"*\")
        candidate="${candidate#\"}"
        candidate="${candidate%\"}"
        candidate="$(printf '%s' "$candidate" | sed 's/\\\\\\"/\"/g; s/\\\\\\\\/\\\\/g; s/%%/%/g')"
        ;;
    esac
  fi

  # OpenRC and procd templates embed the shell-quoted environment path.
  if [ -z "$candidate" ] && [ -f "/etc/init.d/$SERVICE_NAME" ]; then
    candidate="$(sed -n 's/^AGENT_ENV_FILE=//p' "/etc/init.d/$SERVICE_NAME" | head -n 1)"
    case "$candidate" in
      \'*\')
        candidate="${candidate#\'}"
        candidate="${candidate%\'}"
        candidate="$(printf '%s' "$candidate" | sed "s/'\\\\''/'/g")"
        ;;
    esac
  fi

  if [ -n "$candidate" ] && [ -f "$candidate" ]; then
    ENV_DIR="$(dirname "$candidate")"
  fi
}

if [ "$(id -u)" -ne 0 ]; then
  run_as_root_hint
  fail "please run as root"
fi

validate_service_name "$SERVICE_NAME"
discover_uninstall_env_file

# A successful install records all paths needed by uninstall.  Load that
# metadata before lexical normalization so custom paths are protected and
# removed consistently.  Explicit command-line values still win.
if [ "$ACTION" = "uninstall" ] || [ "$ACTION" = "remove" ]; then
  ENV_FILE="$ENV_DIR/agent.env"
  if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    . "${ENV_FILE}"
    set +a
    [ -n "$INPUT_LINK42_INSTALL_DIR" ] || INSTALL_DIR="${LINK42_INSTALL_DIR:-$INSTALL_DIR}"
    [ -n "$INPUT_LINK42_AGENT_BIN" ] || BIN_PATH="${LINK42_AGENT_BIN:-$BIN_PATH}"
    [ -n "$INPUT_LINK42_ENV_DIR" ] || ENV_DIR="${LINK42_ENV_DIR:-$ENV_DIR}"
    [ -n "$INPUT_LINK42_UDP2RAW_BIN" ] || UDP2RAW_BIN="${LINK42_UDP2RAW_BIN:-$UDP2RAW_BIN}"
    [ -n "$INPUT_LINK42_MIMIC_SYSTEM_CONFIG_DIR" ] || MIMIC_SYSTEM_CONFIG_DIR="${LINK42_MIMIC_SYSTEM_CONFIG_DIR:-$MIMIC_SYSTEM_CONFIG_DIR}"
  fi
fi
INSTALL_DIR="$(normalize_install_path "$INSTALL_DIR")"
BIN_PATH="$(normalize_install_path "$BIN_PATH")"
ENV_DIR="$(normalize_install_path "$ENV_DIR")"
WIREGUARD_DIR="$(normalize_install_path "$WIREGUARD_DIR")"
UDP2RAW_BIN="$(normalize_install_path "$UDP2RAW_BIN")"
MIMIC_SYSTEM_CONFIG_DIR="$(normalize_install_path "$MIMIC_SYSTEM_CONFIG_DIR")"
ENV_FILE="$ENV_DIR/agent.env"
MIDDLEWARE_DIR="$ENV_DIR/middleware"
UDP2RAW_CONFIG_DIR="$MIDDLEWARE_DIR/udp2raw"
MIMIC_CONFIG_DIR="$MIDDLEWARE_DIR/mimic"
reject_dangerous_path "$INSTALL_DIR"
reject_dangerous_path "$BIN_PATH"
reject_dangerous_path "$ENV_DIR"
reject_dangerous_path "$WIREGUARD_DIR"
reject_dangerous_path "$UDP2RAW_BIN"
reject_dangerous_path "$MIMIC_SYSTEM_CONFIG_DIR"
reject_symlink_path "$INSTALL_DIR"
reject_symlink_path "$BIN_PATH"
reject_symlink_path "$ENV_DIR"
reject_symlink_path "$WIREGUARD_DIR"

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

uninstall_udp2raw_systemd() {
  if command -v systemctl >/dev/null 2>&1; then
    for unit in $(systemctl list-units --all 'link42-udp2raw-*.service' --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
      [ -n "$unit" ] || continue
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
      systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
    for unit in $(systemctl list-unit-files 'link42-udp2raw-*.service' --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
      [ -n "$unit" ] || continue
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
      systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
  fi
  rm -f /etc/systemd/system/link42-udp2raw-server@.service
  rm -f /etc/systemd/system/link42-udp2raw-client@.service
  rm -f "$UDP2RAW_LIBEXEC"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

uninstall_udp2raw_openwrt() {
  for script in /etc/init.d/link42-udp2raw-*; do
    [ -e "$script" ] || continue
    "$script" stop >/dev/null 2>&1 || true
    "$script" disable >/dev/null 2>&1 || true
    rm -f "$script"
  done
}

uninstall_mimic_systemd() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return
  fi

  for config in "$MIMIC_CONFIG_DIR"/*; do
    [ -e "$config" ] || continue
    iface="$(basename "$config")"
    [ -n "$iface" ] || continue
    systemctl disable --now "mimic@$iface.service" >/dev/null 2>&1 || true
    systemctl reset-failed "mimic@$iface.service" >/dev/null 2>&1 || true
    rm -f "$MIMIC_SYSTEM_CONFIG_DIR/$iface.conf"
  done

  systemctl daemon-reload >/dev/null 2>&1 || true
}

uninstall_middleware() {
  if [ "$KEEP_MIDDLEWARE" = "1" ]; then
    log "keeping Link42 middleware because LINK42_KEEP_MIDDLEWARE=1"
    return
  fi

  uninstall_udp2raw_systemd
  uninstall_udp2raw_openwrt
  uninstall_mimic_systemd
  rm -rf "$UDP2RAW_CONFIG_DIR"
  rm -rf "$MIMIC_CONFIG_DIR"
  rmdir "$MIDDLEWARE_DIR" >/dev/null 2>&1 || true
  rm -f "$UDP2RAW_BIN"
  log "removed Link42 middleware services and assets"
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

  uninstall_middleware
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

INPUT_LINK42_SERVER_URL="${LINK42_SERVER_URL-}"
INPUT_LINK42_NODE_ID="${LINK42_NODE_ID-}"
INPUT_LINK42_AGENT_TOKEN="${LINK42_AGENT_TOKEN-}"
INPUT_LINK42_WIREGUARD_DIR="${LINK42_WIREGUARD_DIR-}"
INPUT_LINK42_AGENT_DRY_RUN="${LINK42_AGENT_DRY_RUN-}"
INPUT_LINK42_POLL_INTERVAL="${LINK42_POLL_INTERVAL-}"
INPUT_LINK42_HTTP_TIMEOUT="${LINK42_HTTP_TIMEOUT-}"
INPUT_LINK42_HEARTBEAT_TIMEOUT="${LINK42_HEARTBEAT_TIMEOUT-}"
INPUT_LINK42_POLL_JITTER="${LINK42_POLL_JITTER-}"
INPUT_LINK42_COMMAND_TIMEOUT="${LINK42_COMMAND_TIMEOUT-}"
INPUT_LINK42_GRE_DIR="${LINK42_GRE_DIR-}"
INPUT_LINK42_LOG_LEVEL="${LINK42_LOG_LEVEL-}"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

if [ -n "$INPUT_LINK42_SERVER_URL" ]; then
  LINK42_SERVER_URL="$INPUT_LINK42_SERVER_URL"
fi
if [ -n "$INPUT_LINK42_NODE_ID" ]; then
  LINK42_NODE_ID="$INPUT_LINK42_NODE_ID"
fi
if [ -n "$INPUT_LINK42_AGENT_TOKEN" ]; then
  LINK42_AGENT_TOKEN="$INPUT_LINK42_AGENT_TOKEN"
fi
if [ -n "$INPUT_LINK42_WIREGUARD_DIR" ]; then
  LINK42_WIREGUARD_DIR="$INPUT_LINK42_WIREGUARD_DIR"
fi
if [ -n "$INPUT_LINK42_AGENT_DRY_RUN" ]; then
  LINK42_AGENT_DRY_RUN="$INPUT_LINK42_AGENT_DRY_RUN"
fi
if [ -n "$INPUT_LINK42_POLL_INTERVAL" ]; then
  LINK42_POLL_INTERVAL="$INPUT_LINK42_POLL_INTERVAL"
fi
if [ -n "$INPUT_LINK42_HTTP_TIMEOUT" ]; then
  LINK42_HTTP_TIMEOUT="$INPUT_LINK42_HTTP_TIMEOUT"
fi
if [ -n "$INPUT_LINK42_HEARTBEAT_TIMEOUT" ]; then
  LINK42_HEARTBEAT_TIMEOUT="$INPUT_LINK42_HEARTBEAT_TIMEOUT"
fi
if [ -n "$INPUT_LINK42_POLL_JITTER" ]; then
  LINK42_POLL_JITTER="$INPUT_LINK42_POLL_JITTER"
fi
if [ -n "$INPUT_LINK42_COMMAND_TIMEOUT" ]; then
  LINK42_COMMAND_TIMEOUT="$INPUT_LINK42_COMMAND_TIMEOUT"
fi
if [ -n "$INPUT_LINK42_GRE_DIR" ]; then
  LINK42_GRE_DIR="$INPUT_LINK42_GRE_DIR"
fi
if [ -n "$INPUT_LINK42_LOG_LEVEL" ]; then
  LINK42_LOG_LEVEL="$INPUT_LINK42_LOG_LEVEL"
fi

WIREGUARD_DIR="$(normalize_install_path "${LINK42_WIREGUARD_DIR:-/etc/wireguard}")"
GRE_DIR="$(normalize_install_path "${LINK42_GRE_DIR:-/etc/link42/gre}")"
DRY_RUN="${LINK42_AGENT_DRY_RUN:-0}"
POLL_INTERVAL="${LINK42_POLL_INTERVAL:-5}"
HTTP_TIMEOUT="${LINK42_HTTP_TIMEOUT:-10}"
HEARTBEAT_TIMEOUT="${LINK42_HEARTBEAT_TIMEOUT:-5}"
POLL_JITTER="${LINK42_POLL_JITTER:-0.2}"
COMMAND_TIMEOUT="${LINK42_COMMAND_TIMEOUT:-5}"
LOG_LEVEL="${LINK42_LOG_LEVEL:-INFO}"

reject_dangerous_path "$WIREGUARD_DIR"
reject_dangerous_path "$GRE_DIR"
reject_symlink_path "$INSTALL_DIR"
reject_symlink_path "$BIN_PATH"
reject_symlink_path "$ENV_DIR"
reject_symlink_path "$WIREGUARD_DIR"
reject_symlink_path "$GRE_DIR"

need_env LINK42_SERVER_URL
need_env LINK42_NODE_ID
need_env LINK42_AGENT_TOKEN
configure_download_urls

ARCH="$(uname -m)"
AGENT_INSTALL_MODE="binary"
if command -v uci >/dev/null 2>&1 && [ -f /etc/rc.common ]; then
  AGENT_FILE="link42-agent-source.tar.gz"
  AGENT_INSTALL_MODE="source"
elif is_musl_system; then
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
    if [ "$AGENT_INSTALL_MODE" = "source" ]; then
      apk add --no-cache ca-certificates curl python3 wireguard-tools
    else
      apk add --no-cache ca-certificates curl wireguard-tools
    fi
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
    curl -fL --max-filesize "$MAX_AGENT_DOWNLOAD_SIZE" "$url" -o "$tmp_file"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$tmp_file" "$url"
  else
    fail "curl or wget is required to download the agent"
  fi

  downloaded_size="$(wc -c < "$tmp_file")"
  case "$downloaded_size" in
    ''|*[!0-9]*) fail "could not determine downloaded agent size" ;;
  esac
  [ "$downloaded_size" -le "$MAX_AGENT_DOWNLOAD_SIZE" ] || fail "downloaded agent exceeds maximum size"

  sha_url="$url.sha256"
  command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to verify the downloaded agent"
  if command -v curl >/dev/null 2>&1; then
    curl -fsL --max-filesize 4096 "$sha_url" -o "$tmp_sha" || fail "failed to download agent checksum: $sha_url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$tmp_sha" "$sha_url" || fail "failed to download agent checksum: $sha_url"
  fi
  checksum_size="$(wc -c < "$tmp_sha")"
  case "$checksum_size" in
    ''|*[!0-9]*) fail "could not determine agent checksum size" ;;
  esac
  [ "$checksum_size" -le 4096 ] || fail "agent checksum file is too large"
  expected="$(awk 'NR == 1 {print $1}' "$tmp_sha")"
  case "$expected" in
    *[!0-9a-fA-F]*|'') fail "invalid sha256 file for downloaded agent" ;;
  esac
  [ "${#expected}" -eq 64 ] || fail "invalid sha256 file for downloaded agent"
  actual="$(sha256sum "$tmp_file" | awk '{print $1}')"
  [ "$expected" = "$actual" ] || fail "sha256 mismatch for downloaded agent"

  if [ "$AGENT_INSTALL_MODE" = "source" ]; then
    staged_source="$INSTALL_DIR/.src.new"
    rm -rf "$staged_source"
    mkdir -p "$staged_source"
    python3 - "$tmp_file" "$staged_source" <<'PY' || fail "unsafe agent source archive"
from pathlib import PurePosixPath
import os
from pathlib import Path
import shutil
import sys
import tarfile

destination = Path(sys.argv[2]).resolve()
with tarfile.open(sys.argv[1], "r:gz") as archive:
    members = archive.getmembers()
    if len(members) > 10000 or sum(member.size for member in members) > 64 * 1024 * 1024:
        raise SystemExit("agent source archive exceeds safety limits")
    for member in members:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or member.issym()
            or member.islnk()
            or not (member.isdir() or member.isfile())
        ):
            raise SystemExit(f"unsafe archive member: {member.name}")
    for member in members:
        target = destination.joinpath(*PurePosixPath(member.name).parts)
        target.resolve().relative_to(destination)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            target.chmod(0o755)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        source = archive.extractfile(member)
        if source is None:
            raise SystemExit(f"cannot read archive member: {member.name}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o755 if member.mode & 0o111 else 0o644)
        with source, os.fdopen(descriptor, "wb") as output:
            shutil.copyfileobj(source, output)
PY
    staged_version="$(PYTHONPATH="$staged_source/apps/agent:$staged_source/packages" python3 -m link42_agent.main --version)"
    if [ "$AGENT_VERSION" != "latest" ] && [ "$staged_version" != "$AGENT_VERSION" ]; then
      rm -rf "$staged_source"
      fail "downloaded agent version mismatch: expected $AGENT_VERSION, got $staged_version"
    fi
    stop_existing_service
    backup_source="$INSTALL_DIR/.src.bak"
    rm -rf "$backup_source"
    if [ -d "$INSTALL_DIR/src" ]; then
      mv "$INSTALL_DIR/src" "$backup_source"
    fi
    if ! mv "$staged_source" "$INSTALL_DIR/src"; then
      if [ -d "$backup_source" ]; then
        mv "$backup_source" "$INSTALL_DIR/src"
      fi
      fail "failed to activate downloaded agent source"
    fi
    source_env_file="$(shell_quote "$ENV_FILE")"
    source_pythonpath="$(shell_quote "$INSTALL_DIR/src/apps/agent:$INSTALL_DIR/src/packages")"
    cat > "$BIN_PATH" <<EOF
#!/bin/sh
set -eu
if [ -f $source_env_file ]; then
  set -a
  . $source_env_file
  set +a
fi
export PYTHONPATH=$source_pythonpath
exec python3 -m link42_agent.main "\$@"
EOF
    chmod 0755 "$BIN_PATH"
  else
    stop_existing_service
    install -m 0755 "$tmp_file" "$BIN_PATH"
  fi
  rm -f "$tmp_file" "$tmp_sha"
  trap - EXIT HUP INT TERM
}

rollback_source_install() {
  # 服务安装或健康检查失败时恢复覆盖前的 OpenWrt 源码。
  if [ "$AGENT_INSTALL_MODE" != "source" ] || [ ! -d "$INSTALL_DIR/.src.bak" ]; then
    return
  fi
  rm -rf "$INSTALL_DIR/src"
  mv "$INSTALL_DIR/.src.bak" "$INSTALL_DIR/src"
}

write_env_file() {
  mkdir -p "$ENV_DIR" "$WIREGUARD_DIR"
  chmod 0755 "$ENV_DIR"
  {
    printf 'LINK42_SERVER_URL=%s\n' "$(shell_quote "$LINK42_SERVER_URL")"
    printf 'LINK42_NODE_ID=%s\n' "$(shell_quote "$LINK42_NODE_ID")"
    printf 'LINK42_AGENT_TOKEN=%s\n' "$(shell_quote "$LINK42_AGENT_TOKEN")"
    printf 'LINK42_WIREGUARD_DIR=%s\n' "$(shell_quote "$WIREGUARD_DIR")"
    printf 'LINK42_GRE_DIR=%s\n' "$(shell_quote "$GRE_DIR")"
    printf 'LINK42_AGENT_DRY_RUN=%s\n' "$(shell_quote "$DRY_RUN")"
    printf 'LINK42_POLL_INTERVAL=%s\n' "$(shell_quote "$POLL_INTERVAL")"
    printf 'LINK42_HTTP_TIMEOUT=%s\n' "$(shell_quote "$HTTP_TIMEOUT")"
    printf 'LINK42_HEARTBEAT_TIMEOUT=%s\n' "$(shell_quote "$HEARTBEAT_TIMEOUT")"
    printf 'LINK42_POLL_JITTER=%s\n' "$(shell_quote "$POLL_JITTER")"
    printf 'LINK42_COMMAND_TIMEOUT=%s\n' "$(shell_quote "$COMMAND_TIMEOUT")"
    printf 'LINK42_LOG_LEVEL=%s\n' "$(shell_quote "$LOG_LEVEL")"
    printf 'LINK42_INSTALL_DIR=%s\n' "$(shell_quote "$INSTALL_DIR")"
    printf 'LINK42_AGENT_BIN=%s\n' "$(shell_quote "$BIN_PATH")"
    printf 'LINK42_ENV_DIR=%s\n' "$(shell_quote "$ENV_DIR")"
    printf 'LINK42_UDP2RAW_BIN=%s\n' "$(shell_quote "$UDP2RAW_BIN")"
    printf 'LINK42_MIMIC_SYSTEM_CONFIG_DIR=%s\n' "$(shell_quote "$MIMIC_SYSTEM_CONFIG_DIR")"
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
  systemd_env_file="$(systemd_quote "$ENV_FILE")"
  systemd_bin_path="$(systemd_exec_quote "$BIN_PATH")"
  cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Link42 Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$systemd_env_file
ExecStart=$systemd_bin_path
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME.service"
}

install_openrc_service() {
  service_bin_path="$(shell_quote "$BIN_PATH")"
  service_env_file="$(shell_quote "$ENV_FILE")"
  cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/sbin/openrc-run
name="Link42 Agent"
description="Link42 Agent"
command=$service_bin_path
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
  if [ -f $service_env_file ]; then
    set -a
    . $service_env_file
    set +a
  fi
}
EOF
  chmod 0755 "/etc/init.d/$SERVICE_NAME"
  rc-update add "$SERVICE_NAME" default
  rc-service "$SERVICE_NAME" restart
}

install_openwrt_service() {
  service_bin_path="$(shell_quote "$BIN_PATH")"
  service_env_file="$(shell_quote "$ENV_FILE")"
  cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/bin/sh /etc/rc.common

START=95
STOP=10
USE_PROCD=1
AGENT_ENV_FILE=$service_env_file

start_service() {
  [ -f "\$AGENT_ENV_FILE" ] || return 1
  set -a
  . "\$AGENT_ENV_FILE"
  set +a
  procd_open_instance
  procd_set_param env LINK42_SERVER_URL="\$LINK42_SERVER_URL" LINK42_NODE_ID="\$LINK42_NODE_ID" LINK42_AGENT_TOKEN="\$LINK42_AGENT_TOKEN" LINK42_WIREGUARD_DIR="\$LINK42_WIREGUARD_DIR" LINK42_GRE_DIR="\$LINK42_GRE_DIR" LINK42_AGENT_DRY_RUN="\$LINK42_AGENT_DRY_RUN" LINK42_POLL_INTERVAL="\$LINK42_POLL_INTERVAL" LINK42_HTTP_TIMEOUT="\$LINK42_HTTP_TIMEOUT" LINK42_HEARTBEAT_TIMEOUT="\$LINK42_HEARTBEAT_TIMEOUT" LINK42_POLL_JITTER="\$LINK42_POLL_JITTER" LINK42_COMMAND_TIMEOUT="\$LINK42_COMMAND_TIMEOUT" LINK42_LOG_LEVEL="\$LINK42_LOG_LEVEL"
  procd_set_param command $service_bin_path
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
  if "/etc/init.d/$SERVICE_NAME" status >/dev/null 2>&1; then
    service_action=restart
  else
    service_action=start
  fi
  if ! "/etc/init.d/$SERVICE_NAME" "$service_action"; then
    rollback_source_install
    "/etc/init.d/$SERVICE_NAME" restart >/dev/null 2>&1 || true
    fail "failed to restart $SERVICE_NAME after installation"
  fi
  sleep 2
  if ! "/etc/init.d/$SERVICE_NAME" status >/dev/null 2>&1; then
    rollback_source_install
    "/etc/init.d/$SERVICE_NAME" restart >/dev/null 2>&1 || true
    fail "$SERVICE_NAME did not become healthy after installation"
  fi
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

download_agent
write_env_file

if [ "$SERVICE_BACKEND" = "systemd" ]; then
  install_systemd_service
elif [ "$SERVICE_BACKEND" = "openrc" ]; then
  install_openrc_service
else
  install_openwrt_service
fi

installed_version="$("$BIN_PATH" --version)"
if [ "$AGENT_VERSION" != "latest" ] && [ "$installed_version" != "$AGENT_VERSION" ]; then
  rollback_source_install
  if [ "$SERVICE_BACKEND" = "openwrt-procd" ]; then
    "/etc/init.d/$SERVICE_NAME" restart >/dev/null 2>&1 || true
  fi
  fail "installed agent version mismatch: expected $AGENT_VERSION, got $installed_version"
fi
rm -rf "$INSTALL_DIR/.src.bak"

log "installed $SERVICE_NAME using $SERVICE_BACKEND"
log "binary: $BIN_PATH"
log "config: $ENV_FILE"
log "version: $installed_version"
