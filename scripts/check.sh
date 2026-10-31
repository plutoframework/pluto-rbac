#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

format_diff=$(mktemp)
trap 'rm -f "$format_diff"' EXIT
if ! ./scripts/golangci.sh fmt --diff ./... > "$format_diff"; then
  cat "$format_diff"
  rm -f "$format_diff"
  echo "Formatter failed; run make fmt and resolve any errors" >&2
  exit 1
fi
if [[ -s "$format_diff" ]]; then
  cat "$format_diff"
  rm -f "$format_diff"
  echo "Formatting differs; run make fmt" >&2
  exit 1
fi
rm -f "$format_diff"
./scripts/golangci.sh run ./...
python3 - <<'PYTHON'
from pathlib import Path

for path in Path('.').rglob('*'):
    if not path.is_file() or '.git' in path.parts:
        continue
    data = path.read_bytes()
    if b'\0' not in data and len(data.splitlines()) > 1000:
        raise SystemExit(f'File exceeds 1,000 lines: {path}')
PYTHON
go test ./...
go vet ./...
go build ./...
