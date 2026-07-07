#!/usr/bin/env bash

# 输出带时间戳的发布日志。
link42_log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

# 读取发布环境文件并导出允许的变量。
link42_load_release_env() {
  local env_file="${1:-$ROOT_DIR/scripts/release.env}"
  [[ -f "$env_file" ]] || return 0

  local vars=(
    LINK42_PUBLIC_HOST
    LINK42_PUBLIC_ROOT
    LINK42_PUBLIC_BASE_URL
    IMAGE_REPO
    IMAGE_TAG
    IMAGE_NAME
    PUSH_LATEST
    SKIP_VERIFY
    LOCAL_VERIFY
    TEST_CONTAINER
    TEST_VOLUME
    SKIP_AGENT_PUBLIC
    SKIP_CONTROLLER
    SKIP_BUILD
    SKIP_PREPARE_AGENT_RELEASES
    REBUILD_AGENT_RELEASES
    LINK42_AGENT_PLATFORM
    LINK42_AGENT_BUILD_MODE
    LINK42_AGENT_BUILD_IMAGE
    PYTHON_BIN
    DOCKERFILE
    OUTPUT
  )

  local tmp var quoted_value
  tmp="$(mktemp)"
  (
    set +u
    set -a
    # shellcheck disable=SC1090
    . "$env_file"
    set +a
    for var in "${vars[@]}"; do
      if [[ -v $var ]]; then
        printf '%s=%q\n' "$var" "${!var}"
      fi
    done
  ) > "$tmp"

  while IFS='=' read -r var quoted_value; do
    [[ -n "$var" ]] || continue
    if [[ ! -v $var ]]; then
      eval "$var=$quoted_value"
      export "$var"
    fi
  done < "$tmp"
  rm -f "$tmp"
}

# 检查发布流程所需文件是否存在。
link42_require_files() {
  local file
  for file in "$@"; do
    [[ -f "$file" ]] || {
      echo "missing required file: $file" >&2
      return 1
    }
  done
}

# 为指定文件生成 sha256 校验文件。
link42_write_sha256() {
  local file="$1"
  local dir base
  dir="$(dirname "$file")"
  base="$(basename "$file")"
  (cd "$dir" && sha256sum "$base") > "$file.sha256"
}

# 校验文件内容是否匹配 sha256 文件。
link42_verify_sha256() {
  local file="$1"
  local checksum_file="$2"
  local expected actual

  [[ -f "$file" ]] || {
    echo "missing file for checksum verification: $file" >&2
    return 1
  }
  [[ -f "$checksum_file" ]] || {
    echo "missing checksum file: $checksum_file" >&2
    return 1
  }

  expected="$(awk 'NF {print $1; exit}' "$checksum_file")"
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [[ -z "$expected" || "$actual" != "$expected" ]]; then
    echo "sha256 mismatch: $file expected=$expected actual=$actual" >&2
    return 1
  fi
  printf '%s: OK\n' "$file"
}

# 从日志中遮盖可能的敏感字段。
link42_redact_secrets() {
  sed -E 's/(password|PASSWORD|token|TOKEN|secret|SECRET)=[^ ]+/\1=<redacted>/g'
}
