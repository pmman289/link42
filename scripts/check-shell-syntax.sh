#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
while IFS= read -r -d '' script; do
  [[ -f "$script" ]] || continue
  IFS= read -r shebang < "$script"
  case "$shebang" in
    *bash*) bash -n "$script" ;;
    *) sh -n "$script" ;;
  esac
done < <(git ls-files -z --cached --others --exclude-standard '*.sh')
