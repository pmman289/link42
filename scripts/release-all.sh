#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
link42_load_release_env

IMAGE_TAG="${IMAGE_TAG:-$(date +%Y%m%d-%H%M%S)}"
IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"

cd "$ROOT_DIR"

link42_log "release tag: $IMAGE_TAG"

link42_log "publishing controller Docker image with embedded Agent assets"
IMAGE_REPO="$IMAGE_REPO" IMAGE_TAG="$IMAGE_TAG" scripts/controller/publish-dockerhub.sh

link42_log "release complete"
