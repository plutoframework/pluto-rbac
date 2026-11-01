#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# fmt wraps long declarations/calls and orders imports. Spacing is supplied by
# an analyzer, so fmt alone cannot apply the wsl_v5 fixes.
task_root="$PWD"
for module in . identity; do
  cd "$task_root/$module"
  GOWORK=off "$task_root/scripts/golangci.sh" fmt ./...
  GOWORK=off "$task_root/scripts/golangci.sh" run \
    --enable-only wsl_v5 --fix ./...
  GOWORK=off "$task_root/scripts/golangci.sh" fmt ./...
done
cd "$task_root"

# The same non-mutating check used by local/CI validation must accept the
# result.
for module in . identity; do
  (cd "$task_root/$module" && GOWORK=off "$task_root/scripts/lint.sh" ./...)
done

go run ./scripts/commentspacing -write .
