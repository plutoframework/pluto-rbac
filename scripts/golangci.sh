#!/usr/bin/env bash
# One pinned version for mise tasks, direct scripts, and CI.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(python3 - <<'PYTHON'
import tomllib
from pathlib import Path
print(tomllib.loads(Path('mise.toml').read_text())['tools']['golangci-lint'])
PYTHON
)

if command -v golangci-lint >/dev/null 2>&1; then
  installed=$(golangci-lint version --short)
  if [[ "$installed" == "$version" ]]; then
    exec golangci-lint "$@"
  fi
fi

if command -v mise >/dev/null 2>&1; then
  exec mise exec "golangci-lint@$version" -- golangci-lint "$@"
fi

echo "Install golangci-lint $version or run 'mise install' in this project." >&2
exit 1
