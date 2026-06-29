#!/usr/bin/env sh
set -eu

# 导出 Link42 主控镜像，便于复制到其它机器后用 docker load 导入。
IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
IMAGE_TAG="${1:-${IMAGE_TAG:-latest}}"
IMAGE_NAME="${IMAGE_NAME:-$IMAGE_REPO:$IMAGE_TAG}"
OUTPUT="${OUTPUT:-dist/controller/link42-controller-$IMAGE_TAG.tar}"

mkdir -p "$(dirname "$OUTPUT")"
docker save -o "$OUTPUT" "$IMAGE_NAME"

printf '%s\n' "Exported $IMAGE_NAME to $OUTPUT"
