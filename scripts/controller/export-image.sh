#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
link42_load_release_env

# 导出 Link42 主控镜像，便于复制到其它机器后用 docker load 导入。
IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
IMAGE_TAG="${1:-${IMAGE_TAG:-latest}}"
IMAGE_NAME="${IMAGE_NAME:-$IMAGE_REPO:$IMAGE_TAG}"
OUTPUT="${OUTPUT:-dist/controller/link42-controller-$IMAGE_TAG.tar}"

cd "$ROOT_DIR"
mkdir -p "$(dirname "$OUTPUT")"
docker save -o "$OUTPUT" "$IMAGE_NAME"

printf '%s\n' "Exported $IMAGE_NAME to $OUTPUT"
