#!/usr/bin/env sh
set -eu

# 构建 Link42 主控镜像，镜像内包含 FastAPI 后端和已构建的 Web 面板。
IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE_NAME="${IMAGE_NAME:-$IMAGE_REPO:$IMAGE_TAG}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.controller}"

scripts/agent/prepare-release-assets.sh >/dev/null
docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" .

printf '%s\n' "Built $IMAGE_NAME"
