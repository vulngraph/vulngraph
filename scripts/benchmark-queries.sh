#!/usr/bin/env bash
# Disposable, local-only storage: never reads application database credentials.
set -euo pipefail

profile="${1:-small}"
case "$profile" in smoke) rows=1000;; small) rows=10000;; target) rows=100000;; stress) rows=1000000;; *) echo "usage: $0 [smoke|small|target|stress] [fresh output-directory]" >&2; exit 2;; esac
root="$(cd "$(dirname "$0")/.." && pwd)"
case "${PERF_QUERY_VERSIONS:-1}" in 1|2|3|4|5|10|20) ;; *) echo "unsupported retained-version count" >&2; exit 2;; esac
case "${PERF_QUERY_EXPERIMENT:-}" in ''|keys|buffers) ;; *) echo "unsupported query experiment" >&2; exit 2;; esac
output="${2:-$(mktemp -d "${TMPDIR:-/tmp}/vg-query-perf-report.XXXXXX")}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
if [[ -n "$(find "$output" -mindepth 1 -print -quit)" ]]; then
  echo "choose a fresh output directory; prior benchmark results exist in $output" >&2
  exit 2
fi
tmp="$(mktemp -d "${TMPDIR:-/tmp}/vg-query-perf.XXXXXX")"
suffix="$(basename "$tmp" | tr '[:upper:].' '[:lower:]-')"
pg="${suffix}-pg"
ch="${suffix}-ch"
stats_pid=""
cleanup() {
  if [[ -n "$stats_pid" ]]; then kill "$stats_pid" 2>/dev/null || true; wait "$stats_pid" 2>/dev/null || true; fi
  docker logs "$pg" >"$output/postgres.log" 2>&1 || true
  docker logs "$ch" >"$output/clickhouse.log" 2>&1 || true
  docker rm -fv "$pg" "$ch" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
password="$(openssl rand -hex 16)"
pg_image="postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
ch_image="clickhouse/clickhouse-server:26.8.47.5@sha256:13f4949b03320e04fe1d2f75ed38734530e78b55469168cc6d5062f198563269"
docker run -d --name "$pg" --memory 512m --cpus 1 \
  -e POSTGRES_USER=bench -e "POSTGRES_PASSWORD=$password" -e POSTGRES_DB=vg_query_perf \
  -p 127.0.0.1::5432 "$pg_image" > /dev/null
docker run -d --name "$ch" --memory "${PERF_CH_MEMORY:-8g}" --cpus "${PERF_CH_CPUS:-4}" \
  -e CLICKHOUSE_USER=bench -e "CLICKHOUSE_PASSWORD=$password" -e CLICKHOUSE_DB=vg_query_perf \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  -p 127.0.0.1::9000 "$ch_image" > /dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$pg" pg_isready -U bench -d vg_query_perf >/dev/null 2>&1 && \
     docker exec "$ch" clickhouse-client --user bench --password "$password" --query 'SELECT 1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then echo "benchmark databases did not become ready; logs: $output" >&2; exit 1; fi
pg_port="$(docker port "$pg" 5432/tcp | sed 's/.*://')"
ch_port="$(docker port "$ch" 9000/tcp | sed 's/.*://')"

# Keep exact image identities and resource limits with the measurements.
docker inspect --format '{{.Name}} image={{.Image}} memory={{.HostConfig.Memory}} nanocpus={{.HostConfig.NanoCpus}}' "$pg" "$ch" > "$output/environment.txt"
cd "$root"
git status --short >> "$output/environment.txt"
python3 scripts/performance_trend.py environment "$pg" "$ch" > "$output/environment.json"
export PERF_QUERY_ISOLATED=1 PERF_QUERY_ROWS="$rows" PERF_QUERY_DIR="$output"
export PERF_COMMIT="$(git rev-parse HEAD)"
export PERF_POSTGRES_URL="postgres://bench:$password@127.0.0.1:$pg_port/vg_query_perf?sslmode=disable"
export PERF_CLICKHOUSE_URL="clickhouse://bench:$password@127.0.0.1:$ch_port/vg_query_perf"
export GOMAXPROCS="${GOMAXPROCS:-4}"
git ls-files -z --cached --others --exclude-standard | xargs -0 shasum -a 256 > "$output/source-files.sha256"
# A temporary index includes new benchmark files without changing the user's stage.
GIT_INDEX_FILE="$tmp/source-index" git read-tree HEAD
GIT_INDEX_FILE="$tmp/source-index" git add -A
GIT_INDEX_FILE="$tmp/source-index" git diff --cached --binary HEAD > "$output/source.patch"
shasum -a 256 "$output/source.patch" > "$output/source-patch.sha256"
export TEST_CLICKHOUSE_URL="$PERF_CLICKHOUSE_URL"
docker stats --format '{{json .}}' "$pg" "$ch" > "$output/container-stats.jsonl" &
stats_pid=$!
go test -tags=integration ./internal/perfassurance -run '^TestPrepareQueryDatabases$' -count=1 -v 2>&1 | tee "$output/migrations.log"
docker exec "$ch" clickhouse-client --user bench --password "$password" --query 'SELECT version()' > "$output/clickhouse-version.txt"
docker exec "$ch" clickhouse-client --user bench --password "$password" --query "SELECT name,value FROM system.settings WHERE name IN ('max_threads','max_block_size','query_plan_optimize_lazy_materialization','max_memory_usage') FORMAT JSON" > "$output/query-settings.json"
go test -p 1 -tags=integration ./internal/app/asset ./internal/app/finding -run "${PERF_QUERY_TESTS:-^(TestInventoryQueryCosts|TestDashboardQueryCosts)$}" -count=1 -timeout=20m -v 2>&1 | tee "$output/run.log"
