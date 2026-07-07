#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck disable=SC1091
. "$ROOT_DIR/scripts/lib/release.sh"
link42_load_release_env

IMAGE_REPO="${IMAGE_REPO:-pmman/link42}"
IMAGE_TAG="${1:-${IMAGE_TAG:-$(date +%Y%m%d-%H%M%S)}}"
IMAGE_NAME="$IMAGE_REPO:$IMAGE_TAG"
PUSH_LATEST="${PUSH_LATEST:-1}"
SKIP_VERIFY="${SKIP_VERIFY:-0}"
LOCAL_VERIFY="${LOCAL_VERIFY:-1}"
TEST_CONTAINER="${TEST_CONTAINER:-link42-publish-test}"
TEST_VOLUME="${TEST_VOLUME:-link42-publish-test-runtime}"

cd "$ROOT_DIR"

# 清理本地镜像验证容器和数据卷。
cleanup_test_container() {
  docker rm -f "$TEST_CONTAINER" >/dev/null 2>&1 || true
  docker volume rm "$TEST_VOLUME" >/dev/null 2>&1 || true
}

# 读取验证容器日志并遮盖敏感字段。
redacted_test_logs() {
  docker logs --tail 80 "$TEST_CONTAINER" 2>&1 \
    | link42_redact_secrets
}

if [[ "$SKIP_VERIFY" != "1" ]]; then
  link42_log "running Python tests"
  .venv/bin/python -m pytest -q

  link42_log "running Python compile check"
  .venv/bin/python -m compileall apps/api apps/agent packages tests

  link42_log "building web"
  npm run build --prefix apps/web

  link42_log "checking whitespace"
  git diff --check
fi

link42_log "preparing controller embedded agent releases"
scripts/agent/prepare-release-assets.sh

link42_log "building controller image $IMAGE_NAME"
IMAGE_REPO="$IMAGE_REPO" IMAGE_TAG="$IMAGE_TAG" SKIP_PREPARE_AGENT_RELEASES=1 scripts/controller/build-image.sh

if [[ "$LOCAL_VERIFY" == "1" ]]; then
  link42_log "verifying local container"
  cleanup_test_container
  verify_tmp="$(mktemp -d)"
  cleanup_verify() {
    cleanup_test_container
    rm -rf "$verify_tmp"
  }
  trap cleanup_verify EXIT
  docker run -d \
    --name "$TEST_CONTAINER" \
    -p 127.0.0.1::8000 \
    -v "$TEST_VOLUME:/link42" \
    "$IMAGE_NAME" >/dev/null

  host_port="$(docker port "$TEST_CONTAINER" 8000/tcp | sed 's/.*://')"
  auth_status=""
  for _ in {1..30}; do
    auth_status="$(curl -s -o "$verify_tmp/auth-me.out" -w '%{http_code}' "http://127.0.0.1:$host_port/api/auth/me" || true)"
    [[ "$auth_status" == "401" ]] && break
    sleep 1
  done
  if [[ "$auth_status" != "401" ]]; then
    echo "expected /api/auth/me to return 401, got $auth_status" >&2
    redacted_test_logs >&2 || true
    exit 1
  fi

  password="$(
    docker logs "$TEST_CONTAINER" 2>&1 \
      | sed -n -E 's/.*(Link42 initial login:|Link42 初始登录信息) username=pmman password=//p' \
      | tail -1
  )"
  if [[ -z "$password" ]]; then
    echo "failed to read initial login password from test container logs" >&2
    redacted_test_logs >&2 || true
    exit 1
  fi

  login_payload="$(
    LINK42_INITIAL_PASSWORD="$password" python3 -c 'import json, os; print(json.dumps({"username": "pmman", "password": os.environ["LINK42_INITIAL_PASSWORD"]}))'
  )"
  login_json="$(
    printf '%s' "$login_payload" \
      | curl -fsS -H 'Content-Type: application/json' -d @- "http://127.0.0.1:$host_port/api/auth/login"
  )"
  token="$(printf '%s' "$login_json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])')"
  release_json="$(curl -fsS -H "Authorization: Bearer $token" "http://127.0.0.1:$host_port/api/agent/releases")"
  release_latest="$(printf '%s' "$release_json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["latest"])')"
  [[ -n "$release_latest" ]] || {
    echo "failed to detect latest agent release from /api/agent/releases" >&2
    exit 1
  }
  printf 'local agent release latest: %s\n' "$release_latest"
  cleanup_verify
  trap - EXIT
fi

link42_log "pushing $IMAGE_NAME"
docker push "$IMAGE_NAME"

if [[ "$PUSH_LATEST" == "1" ]]; then
  link42_log "pushing $IMAGE_REPO:latest"
  docker tag "$IMAGE_NAME" "$IMAGE_REPO:latest"
  docker push "$IMAGE_REPO:latest"

  link42_log "verifying remote digests"
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

link42_log "published controller image $IMAGE_NAME"
