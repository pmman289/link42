#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# 只输出文件名，避免扫描日志把误提交的凭据再次扩散到 CI 日志。
pattern='l42(agent|web)_[A-Za-z0-9_-]{20,}|l42lg_[A-Za-z0-9_-]{6,}_[A-Za-z0-9_-]{20,}'
matches="$(git grep -I -l -E "$pattern" -- . || true)"
if [[ -n "$matches" ]]; then
  echo "检测到疑似 Link42 明文凭据，请删除或替换为明显占位符：" >&2
  printf '%s\n' "$matches" >&2
  exit 1
fi

echo "未发现 Link42 明文凭据。"
