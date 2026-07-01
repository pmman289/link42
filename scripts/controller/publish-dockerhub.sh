#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -f "$ROOT_DIR/scripts/release.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT_DIR/scripts/release.env"
  set +a
fi

IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
IMAGE_TAG="${1:-${IMAGE_TAG:-$(date +%Y%m%d-%H%M%S)}}"
IMAGE_NAME="$IMAGE_REPO:$IMAGE_TAG"
PUSH_LATEST="${PUSH_LATEST:-1}"
SKIP_VERIFY="${SKIP_VERIFY:-0}"
LOCAL_VERIFY="${LOCAL_VERIFY:-1}"
TEST_CONTAINER="${TEST_CONTAINER:-link42-publish-test}"
TEST_VOLUME="${TEST_VOLUME:-link42-publish-test-runtime}"

cd "$ROOT_DIR"

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

cleanup_test_container() {
  docker rm -f "$TEST_CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$TEST_VOLUME" >/dev/null 2>&1 || true
}

if [[ "$SKIP_VERIFY" != "1" ]]; then
  log "running Python tests"
  .venv/bin/python -m pytest -q

  log "running Python compile check"
  .venv/bin/python -m compileall apps/api apps/agent packages tests

  log "building web"
  npm run build --prefix apps/web

  log "checking whitespace"
  git diff --check
fi

log "preparing controller embedded agent releases"
scripts/agent/prepare-release-assets.sh

log "building controller image $IMAGE_NAME"
IMAGE_REPO="$IMAGE_REPO" IMAGE_TAG="$IMAGE_TAG" scripts/controller/build-image.sh

if [[ "$LOCAL_VERIFY" == "1" ]]; then
  log "verifying local container"
  cleanup_test_container
  docker run -d \
    --name "$TEST_CONTAINER" \
    -p 127.0.0.1::8000 \
    -v "$TEST_VOLUME:/link42" \
    "$IMAGE_NAME" >/dev/null

  host_port="$(docker port "$TEST_CONTAINER" 8000/tcp | sed 's/.*://')"
  sleep 2
  auth_status="$(curl -sS -o /tmp/link42-auth-me.out -w '%{http_code}' "http://127.0.0.1:$host_port/api/auth/me")"
  if [[ "$auth_status" != "401" ]]; then
    echo "expected /api/auth/me to return 401, got $auth_status" >&2
    exit 1
  fi
  curl -fsS "http://127.0.0.1:$host_port/api/agent/releases" >/dev/null
  cleanup_test_container
fi

log "pushing $IMAGE_NAME"
docker push "$IMAGE_NAME"

if [[ "$PUSH_LATEST" == "1" ]]; then
  log "pushing $IMAGE_REPO:latest"
  docker tag "$IMAGE_NAME" "$IMAGE_REPO:latest"
  docker push "$IMAGE_REPO:latest"

  log "verifying remote digests"
  tag_digest="$(docker buildx imagetools inspect "$IMAGE_NAME" | awk '/Digest:/ {print $2; exit}')"
  latest_digest="$(docker buildx imagetools inspect "$IMAGE_REPO:latest" | awk '/Digest:/ {print $2; exit}')"
  if [[ "$tag_digest" != "$latest_digest" ]]; then
    echo "digest mismatch: $IMAGE_NAME=$tag_digest latest=$latest_digest" >&2
    exit 1
  fi
  printf '%s\n' "$IMAGE_REPO@$tag_digest"
else
  docker buildx imagetools inspect "$IMAGE_NAME" | awk '/Digest:/ {print "'"$IMAGE_REPO"'@" $2; exit}'
fi

log "published controller image $IMAGE_NAME"
