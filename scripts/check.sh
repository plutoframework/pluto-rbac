#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go run ./scripts/commentspacing -formatter "$PWD/scripts/golangci.sh" .

task_root="$PWD"
for module in . identity; do
  (cd "$task_root/$module" && GOWORK=off "$task_root/scripts/lint.sh" ./...)
done
python3 - <<'PYTHON'
from pathlib import Path

for path in Path('.').rglob('*'):
    if not path.is_file() or '.git' in path.parts:
        continue
    data = path.read_bytes()
    if b'\0' not in data and len(data.splitlines()) > 1000:
        raise SystemExit(f'File exceeds 1,000 lines: {path}')
PYTHON
for module in . identity; do
  cd "$task_root/$module"
  GOWORK=off go test ./...
  GOWORK=off go vet ./...
  GOWORK=off go build ./...
done
