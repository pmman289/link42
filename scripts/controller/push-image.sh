#!/usr/bin/env sh
set -eu

# 构建并推送 Link42 主控镜像到 DockerHub。
# 用法：
#   scripts/controller/push-image.sh v0.1.0
#   IMAGE_TAG=v0.1.0 scripts/controller/push-image.sh

IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
IMAGE_TAG="${1:-${IMAGE_TAG:-latest}}"
IMAGE_NAME="${IMAGE_REPO}:${IMAGE_TAG}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.controller}"

scripts/agent/prepare-release-assets.sh >/dev/null
docker build -f "$DOCKERFILE" -t "$IMAGE_NAME" .
docker push "$IMAGE_NAME"

printf '%s\n' "Pushed $IMAGE_NAME"
