#!/usr/bin/env bash
# Disposable, local-only storage: never reads application database credentials.
set -euo pipefail

profile="${1:-smoke}"
case "$profile" in smoke|medium|core|2m|20m) ;; *) echo "usage: $0 [smoke|medium|core|2m|20m] [output-directory]" >&2; exit 2;; esac
root="$(cd "$(dirname "$0")/.." && pwd)"
output="${2:-$(mktemp -d "${TMPDIR:-/tmp}/vg-perf-report.XXXXXX")}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
if [[ -e "$output/report.json" || -e "$output/run.log" ]]; then
  echo "choose a fresh output directory; prior benchmark results exist in $output" >&2
  exit 2
fi
tmp="$(mktemp -d "${TMPDIR:-/tmp}/vg-perf.XXXXXX")"
suffix="$(basename "$tmp" | tr '[:upper:].' '[:lower:]-')"
pg="${suffix}-pg"
ch="${suffix}-ch"
cleanup() {
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
  -e POSTGRES_USER=bench -e "POSTGRES_PASSWORD=$password" -e POSTGRES_DB=vg_perf \
  -p 127.0.0.1::5432 "$pg_image" > /dev/null
docker run -d --name "$ch" --memory "${PERF_CH_MEMORY:-8g}" --cpus "${PERF_CH_CPUS:-4}" \
  -e CLICKHOUSE_USER=bench -e "CLICKHOUSE_PASSWORD=$password" -e CLICKHOUSE_DB=vg_perf \
  -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
  -p 127.0.0.1::9000 "$ch_image" > /dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$pg" pg_isready -U bench -d vg_perf >/dev/null 2>&1 && \
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
export PERF_ISOLATED=1 PERF_PROFILE="$profile" PERF_REPORT="$output/report.json"
export PERF_COMMIT="$(git rev-parse HEAD)"
export PERF_POSTGRES_URL="postgres://bench:$password@127.0.0.1:$pg_port/vg_perf?sslmode=disable"
export PERF_CLICKHOUSE_URL="clickhouse://bench:$password@127.0.0.1:$ch_port/vg_perf"
export GOMAXPROCS="${GOMAXPROCS:-4}"
echo "Benchmark profile: $profile; output: $output"
go test -tags=integration ./internal/throughput -run '^TestPipelineThroughput$' -count=1 -timeout=50m -v 2>&1 | tee "$output/run.log"
if [[ -n "${PERF_CONNECTOR_DIR:-}" ]]; then
  go test -tags=integration ./internal/jobs -run '^TestConnectorSyncThroughput$' -count=1 -timeout=20m -v 2>&1 | tee "$PERF_CONNECTOR_DIR/sync.log"
  go test -tags=integration ./internal/app/connector -run '^TestAWSOrgThroughput$' -count=1 -timeout=20m -v 2>&1 | tee "$PERF_CONNECTOR_DIR/aws_org.log"
fi
export TEST_DATABASE_URL="$PERF_POSTGRES_URL" TEST_CLICKHOUSE_URL="$PERF_CLICKHOUSE_URL"
go test -p 1 -tags=integration ./internal/app/asset ./internal/app/finding ./internal/app/connector ./internal/jobs ./internal/migrate ./migrations/clickhouse \
  -run '^(TestWideInventoryBatchesPreserveEveryRow|TestBoundedLineageFreshnessVersionsAndExposureGrade|TestPackageSignalsFollowInventoryProducer|TestRecordObservedLargeBatchPreservesFirstDetection|TestRapidFindingUpdatesReadBack|TestOrgBatchWriteFailureRecoversExistingChildren|TestEnrichBatchQueuePreservesPriorityUniquenessAndCapacity|TestDeletionBacklogRequiresConfirmationAndDrains|TestAuditedFamiliesRetireOnlyProvenAbsence|TestDeletionConfirmationMigrationUpgradeRollbackReplay|TestEdgeTypeIndexMigrationExistingDataRollbackReplay|TestPreciseVersions.*|TestPreciseObservations.*|TestRetirementPreservesPreciseAndLegacyObservations)$' \
  -count=1 -timeout=10m -v 2>&1 | tee "$output/regressions.log"
echo "Report: $output/report.json"
