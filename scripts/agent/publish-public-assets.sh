#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -f "$ROOT_DIR/scripts/release.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/scripts/release.env"
  set +a
fi

REMOTE_HOST="${LINK42_PUBLIC_HOST:-aligz}"
REMOTE_ROOT="${LINK42_PUBLIC_ROOT:-/srv/www/get.pmman.tech}"
PUBLIC_BASE_URL="${LINK42_PUBLIC_BASE_URL:-https://get.pmman.tech}"
SKIP_BUILD="${SKIP_BUILD:-0}"

cd "$ROOT_DIR"

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

if [[ "$SKIP_BUILD" != "1" ]]; then
  log "building x64 agent"
  scripts/agent/build-x64.sh

  log "building OpenWrt source package"
  scripts/agent/build-source.sh
fi

AGENT_VERSION="$(dist/agent/link42-agent-linux-x64 --version | awk '{print $NF}')"
[[ -n "$AGENT_VERSION" ]] || {
  echo "failed to detect agent version" >&2
  exit 1
}

log "agent version: $AGENT_VERSION"
sha256sum -c dist/agent/link42-agent-linux-x64.sha256
sha256sum -c dist/agent/link42-agent-source.tar.gz.sha256

required_files=(
  "deploy/sh/link42-agent.sh"
  "dist/agent/link42-agent-linux-x64"
  "dist/agent/link42-agent-linux-x64.sha256"
  "dist/agent/link42-agent-linux-x64-$AGENT_VERSION"
  "dist/agent/link42-agent-linux-x64-$AGENT_VERSION.sha256"
  "dist/agent/link42-agent-linux-x64-glibc2.31-$AGENT_VERSION"
  "dist/agent/link42-agent-linux-x64-glibc2.31-$AGENT_VERSION.sha256"
  "dist/agent/link42-agent-source.tar.gz"
  "dist/agent/link42-agent-source.tar.gz.sha256"
  "dist/agent/manifest.json"
)

for file in "${required_files[@]}"; do
  [[ -f "$file" ]] || {
    echo "missing required file: $file" >&2
    exit 1
  }
done

log "creating remote directories"
ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_ROOT/sh' '$REMOTE_ROOT/res/link42/$AGENT_VERSION'"

log "uploading installer script"
scp deploy/sh/link42-agent.sh "$REMOTE_HOST:$REMOTE_ROOT/sh/link42-agent.sh"

log "uploading latest assets"
scp \
  dist/agent/link42-agent-linux-x64 \
  dist/agent/link42-agent-linux-x64.sha256 \
  dist/agent/link42-agent-source.tar.gz \
  dist/agent/link42-agent-source.tar.gz.sha256 \
  dist/agent/manifest.json \
  "$REMOTE_HOST:$REMOTE_ROOT/res/link42/"

log "uploading versioned assets"
scp \
  "dist/agent/link42-agent-linux-x64" \
  "dist/agent/link42-agent-linux-x64.sha256" \
  "dist/agent/link42-agent-linux-x64-$AGENT_VERSION" \
  "dist/agent/link42-agent-linux-x64-$AGENT_VERSION.sha256" \
  "dist/agent/link42-agent-linux-x64-glibc2.31-$AGENT_VERSION" \
  "dist/agent/link42-agent-linux-x64-glibc2.31-$AGENT_VERSION.sha256" \
  "dist/agent/link42-agent-source.tar.gz" \
  "dist/agent/link42-agent-source.tar.gz.sha256" \
  "dist/agent/manifest.json" \
  "$REMOTE_HOST:$REMOTE_ROOT/res/link42/$AGENT_VERSION/"

log "fixing remote permissions"
ssh "$REMOTE_HOST" "
set -eu
chmod 0755 '$REMOTE_ROOT/sh/link42-agent.sh'
chmod 0755 '$REMOTE_ROOT/res/link42/link42-agent-linux-x64'
chmod 0755 '$REMOTE_ROOT/res/link42/$AGENT_VERSION'/link42-agent-linux-x64*
chmod 0644 '$REMOTE_ROOT/res/link42/link42-agent-source.tar.gz'
chmod 0644 '$REMOTE_ROOT/res/link42/$AGENT_VERSION/link42-agent-source.tar.gz'
chmod 0644 '$REMOTE_ROOT/res/link42'/*.sha256
chmod 0644 '$REMOTE_ROOT/res/link42/$AGENT_VERSION'/*.sha256
chmod 0644 '$REMOTE_ROOT/res/link42/manifest.json'
chmod 0644 '$REMOTE_ROOT/res/link42/$AGENT_VERSION/manifest.json'
find '$REMOTE_ROOT/res/link42/$AGENT_VERSION' -maxdepth 1 -type f -printf '%f %s bytes\n' | sort
"

log "verifying public URLs"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
(
  cd "$tmpdir"
  curl -fsSL "$PUBLIC_BASE_URL/sh/link42-agent.sh" | head -n 5
  curl -fsSL "$PUBLIC_BASE_URL/sh/link42-agent.sh" | grep -E 'stop_service|reload_service|status_service'
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-linux-x64"
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-linux-x64.sha256"
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-source.tar.gz"
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-source.tar.gz.sha256"
  sha256sum -c link42-agent-linux-x64.sha256
  sha256sum -c link42-agent-source.tar.gz.sha256
  chmod +x link42-agent-linux-x64
  ./link42-agent-linux-x64 --version
  curl -fsSI "$PUBLIC_BASE_URL/res/link42/$AGENT_VERSION/link42-agent-linux-x64" >/dev/null
  curl -fsSI "$PUBLIC_BASE_URL/res/link42/$AGENT_VERSION/link42-agent-source.tar.gz" >/dev/null
  curl -fsS "$PUBLIC_BASE_URL/res/link42/$AGENT_VERSION/manifest.json" >/dev/null
)

log "published agent $AGENT_VERSION to $PUBLIC_BASE_URL/res/link42"
