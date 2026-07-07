#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
link42_load_release_env

REMOTE_HOST="${LINK42_PUBLIC_HOST:-aligz}"
REMOTE_ROOT="${LINK42_PUBLIC_ROOT:-/opt/1panel/www/sites/get.pmman.tech/index}"
PUBLIC_BASE_URL="${LINK42_PUBLIC_BASE_URL:-https://get.pmman.tech}"
SKIP_BUILD="${SKIP_BUILD:-0}"

cd "$ROOT_DIR"

if [[ "$SKIP_BUILD" != "1" ]]; then
  link42_log "building x64 agent"
  scripts/agent/build-x64.sh

  link42_log "building OpenWrt source package"
  scripts/agent/build-source.sh
fi

AGENT_VERSION="$(dist/agent/link42-agent-linux-x64 --version | awk '{print $NF}')"
[[ -n "$AGENT_VERSION" ]] || {
  echo "failed to detect agent version" >&2
  exit 1
}

link42_log "agent version: $AGENT_VERSION"
link42_verify_sha256 dist/agent/link42-agent-linux-x64 dist/agent/link42-agent-linux-x64.sha256
link42_verify_sha256 dist/agent/link42-agent-source.tar.gz dist/agent/link42-agent-source.tar.gz.sha256

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

link42_require_files "${required_files[@]}"

link42_log "creating remote directories"
ssh "$REMOTE_HOST" "mkdir -p '$REMOTE_ROOT/sh' '$REMOTE_ROOT/res/link42/$AGENT_VERSION'"

link42_log "uploading installer script"
scp deploy/sh/link42-agent.sh "$REMOTE_HOST:$REMOTE_ROOT/sh/link42-agent.sh"

link42_log "uploading latest assets"
scp \
  dist/agent/link42-agent-linux-x64 \
  dist/agent/link42-agent-linux-x64.sha256 \
  dist/agent/link42-agent-source.tar.gz \
  dist/agent/link42-agent-source.tar.gz.sha256 \
  dist/agent/manifest.json \
  "$REMOTE_HOST:$REMOTE_ROOT/res/link42/"

link42_log "uploading versioned assets"
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

link42_log "fixing remote permissions"
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

link42_log "verifying public URLs"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
(
  cd "$tmpdir"
  curl -fsSL "$PUBLIC_BASE_URL/sh/link42-agent.sh" -o link42-agent.sh
  sed -n '1,5p' link42-agent.sh
  grep -E 'stop_service|reload_service|status_service' link42-agent.sh
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-linux-x64"
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-linux-x64.sha256"
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-source.tar.gz"
  curl -fsSLO "$PUBLIC_BASE_URL/res/link42/link42-agent-source.tar.gz.sha256"
  link42_verify_sha256 link42-agent-linux-x64 link42-agent-linux-x64.sha256
  link42_verify_sha256 link42-agent-source.tar.gz link42-agent-source.tar.gz.sha256
  chmod +x link42-agent-linux-x64
  ./link42-agent-linux-x64 --version
  curl -fsSI "$PUBLIC_BASE_URL/res/link42/$AGENT_VERSION/link42-agent-linux-x64" >/dev/null
  curl -fsSI "$PUBLIC_BASE_URL/res/link42/$AGENT_VERSION/link42-agent-source.tar.gz" >/dev/null
  curl -fsS "$PUBLIC_BASE_URL/res/link42/$AGENT_VERSION/manifest.json" >/dev/null
)

link42_log "published agent $AGENT_VERSION to $PUBLIC_BASE_URL/res/link42"
