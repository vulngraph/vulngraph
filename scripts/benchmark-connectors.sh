#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
output="${1:-$(mktemp -d "${TMPDIR:-/tmp}/vg-connectors.XXXXXX")}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
if [[ -e "$output/collect.log" ]]; then echo "choose a fresh output directory" >&2; exit 2; fi
cd "$root"
export PERF_CONNECTORS=1 PERF_CONNECTOR_DIR="$output"
export GOMAXPROCS="${GOMAXPROCS:-4}"
printf 'request_delay_ms=%s\n' "${PERF_REQUEST_DELAY_MS:-0}" > "$output/environment.txt"
git rev-parse HEAD >> "$output/environment.txt"
git status --short >> "$output/environment.txt"
go test -p 1 ./internal/collect/... -run '^TestConnectorScale$' -count=1 -timeout=20m -v 2>&1 | tee "$output/collect.log"
scripts/benchmark-pipeline.sh smoke "$output/storage"
