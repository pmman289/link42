#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
link42_load_release_env

IMAGE_TAG="${IMAGE_TAG:-$(date +%Y%m%d-%H%M%S)}"
IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
SKIP_AGENT_PUBLIC="${SKIP_AGENT_PUBLIC:-0}"
SKIP_CONTROLLER="${SKIP_CONTROLLER:-0}"

cd "$ROOT_DIR"

link42_log "release tag: $IMAGE_TAG"

if [[ "$SKIP_AGENT_PUBLIC" != "1" ]]; then
  link42_log "publishing agent public assets"
  scripts/agent/publish-public-assets.sh
fi

if [[ "$SKIP_CONTROLLER" != "1" ]]; then
  link42_log "publishing controller Docker image"
  IMAGE_REPO="$IMAGE_REPO" IMAGE_TAG="$IMAGE_TAG" scripts/controller/publish-dockerhub.sh
fi

link42_log "release complete"
