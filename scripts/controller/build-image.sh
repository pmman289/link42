#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
link42_load_release_env

# 构建 Link42 主控镜像，镜像内包含 FastAPI 后端和已构建的 Web 面板。
IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${IMAGE_NAME:-$IMAGE_REPO:$IMAGE_TAG}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.controller}"

cd "$ROOT_DIR"

if [[ "${SKIP_PREPARE_AGENT_RELEASES:-0}" != "1" ]]; then
  scripts/agent/prepare-release-assets.sh >/dev/null
fi
docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" .

printf '%s\n' "Built $IMAGE_NAME"
