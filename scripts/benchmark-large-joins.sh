#!/usr/bin/env bash
# Local fixtures only. Render deployed tuning; retain exact config/image/source.
set -euo pipefail
profile="${1:-smoke}"
case "$profile" in smoke|target|large|stress-cardinality) ;; *) echo 'expected smoke, target, large or stress-cardinality' >&2; exit 2;; esac
root="$(cd "$(dirname "$0")/.." && pwd)"
bounded() { python3 "$root/scripts/run_bounded.py" "$@"; }
resources="${PERF_JOIN_RESOURCES:-deployed}"
case "$resources" in
 deployed) ch_cpus=2; ch_memory=4g; server_memory=3221225472; query_memory=2147483648;;
 local16g)
  ch_cpus=8; ch_memory=16g; server_memory=12884901888; query_memory=4294967296;;
 local32g)
  ch_cpus=16; ch_memory=32g; server_memory=25769803776; query_memory=4294967296;;
 *) echo 'expected deployed, local16g or local32g resources' >&2; exit 2;;
esac
merge_threads="${PERF_JOIN_MERGE_THREADS:-16}"
case "$merge_threads" in 4|16) ;; *) echo 'expected 4 or 16 merge threads' >&2; exit 2;; esac
merge_ratio=$((32 / merge_threads))
helm_limits=(--set-string "clickhouse.tuning.backgroundPoolSize=$merge_threads" --set-string "clickhouse.tuning.maxServerMemoryBytes=$server_memory" --set-string "clickhouse.tuning.maxMemoryBytes=$query_memory")
output="${2:?choose a fresh output directory}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
if [[ -n "$(find "$output" -mindepth 1 -print -quit)" ]]; then echo 'output must be fresh' >&2; exit 2; fi
ch_image="${PERF_JOIN_IMAGE:-clickhouse/clickhouse-server:26.8-alpine@sha256:31d60795ca6ac748a20712b5d8d047e415c44d370a86e89a63cd251b0eaed9e9}"
case "$ch_image" in clickhouse/clickhouse-server:*@sha256:*) ;; *) echo 'pin an official ClickHouse image digest' >&2; exit 2;; esac
pg_image='postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d'
tmp="$(mktemp -d "${TMPDIR:-/tmp}/vg-large-joins.XXXXXX")"
suffix="$(basename "$tmp" | tr '[:upper:].' '[:lower:]-')"
ch="$suffix-ch"; pg="$suffix-pg"; stats_pid=''; resources_pid=''; completed=0
cleanup() {
 local result=$?
 local resources_status=0 stats_status=0
 trap - EXIT
 if [[ "$result" = 0 && "$completed" != 1 ]]; then result=1; fi
 if [[ -n "$resources_pid" ]]; then kill "$resources_pid" 2>/dev/null || true; wait "$resources_pid" 2>/dev/null || resources_status=$?; fi
 if [[ -n "$stats_pid" ]]; then kill "$stats_pid" 2>/dev/null || true; wait "$stats_pid" 2>/dev/null || stats_status=$?; fi
 printf '{"resource_sampler_exit":%d,"statistics_exit":%d}\n' "$resources_status" "$stats_status" > "$output/cleanup-status.json"
 case "$resources_status" in 0|143) ;; *) result=1;; esac
 case "$stats_status" in 0|143) ;; *) result=1;; esac
 bounded 10 docker logs "$ch" > "$output/clickhouse.log" 2>&1 || true
 bounded 10 docker logs "$pg" > "$output/postgres.log" 2>&1 || true
 bounded 15 docker rm -fv "$ch" "$pg" >/dev/null 2>&1 || true
 rm -rf "$tmp"
 exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$root"
helm template graph deploy/helm-chart/graph --set secret.create=false --show-only templates/clickhouse-config.yaml > "$output/deployed-config.yaml"
helm template graph deploy/helm-chart/graph --set secret.create=false "${helm_limits[@]}" --show-only templates/clickhouse-config.yaml > "$output/effective-config.yaml"
cp deploy/helm-chart/graph/values.yaml "$output/deployed-values.yaml"
python3 - "$output" "$resources" "$ch_cpus" "$server_memory" "$query_memory" "$merge_threads" "$merge_ratio" <<'PY'
import json,pathlib,re,shutil,subprocess,sys
root=pathlib.Path(sys.argv[1]);src=(root/'effective-config.yaml').read_text()
src=src.replace('<background_merges_mutations_concurrency_ratio>2</background_merges_mutations_concurrency_ratio>','<background_merges_mutations_concurrency_ratio>'+sys.argv[7]+'</background_merges_mutations_concurrency_ratio>')
(root/'effective-config.yaml').write_text(src)
host=json.loads(subprocess.check_output(['docker','info','--format','{"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}}}']))
free=shutil.disk_usage(root).free
if free<40*1024**3:raise SystemExit('less than 40 GiB free workspace disk')
if sys.argv[2]=='local16g' and (host['memory_bytes']<24*1024**3 or host['cpus']<8):raise SystemExit('local16g requires at least 24 GiB Docker memory and 8 CPUs')
if sys.argv[2]=='local32g' and (host['memory_bytes']<38*1024**3 or host['cpus']<16):raise SystemExit('local32g requires at least 38 GiB Docker memory and 16 CPUs')
(root/'resource-profile.json').write_text(json.dumps({'cohort':sys.argv[2],'clickhouse_cpus':int(sys.argv[3]),'server_memory_bytes':int(sys.argv[4]),'query_memory_bytes':int(sys.argv[5]),'per_query_threads':2,'background_pool_size':int(sys.argv[6]),'background_merges_mutations_concurrency_ratio':int(sys.argv[7]),'fixed_comparison_query_budget_bytes':512*1024**2,'docker':host,'workspace_free_bytes':free,'limitation':'local cardinality/resource cohort, not the declared native 128 GiB stress host'},indent=2)+'\n')
for name in ['config.xml','users.xml','graph-users.xml']:
 m=re.search(r'^  '+re.escape(name)+r': \|\n((?:    .*\n|\n)+)',src,re.M)
 if not m: raise SystemExit('missing rendered '+name)
 text='\n'.join(line[4:] if line.startswith('    ') else line for line in m[1].splitlines())+'\n'
 # Preserve production grants under the isolated fixture database name.
 if name=='graph-users.xml':
  text=text.replace(' ON graph.',' ON vg_query_perf.').replace('<default_database>graph</','<default_database>vg_query_perf</')
 (root/name).write_text(text)
PY
cat > "$output/fixture-admin.xml" <<'XML'
<clickhouse><users><bench>
<password from_env="CLICKHOUSE_PASSWORD"/><networks><ip>::/0</ip></networks>
<profile>default</profile><quota>default</quota><access_management>1</access_management>
</bench></users></clickhouse>
XML
printf "stage=database-start time=%s\n" "$(date -u +%FT%TZ)"
password="$(openssl rand -hex 16)"
app_password="$(openssl rand -hex 16)"
bounded 180 docker run -d --name "$pg" --cpus 2 --memory 4g --memory-swap 4g \
 -e POSTGRES_USER=bench -e "POSTGRES_PASSWORD=$password" -e POSTGRES_DB=vg_query_perf \
 -p 127.0.0.1::5432 "$pg_image" > /dev/null
bounded 180 docker run -d --name "$ch" --cpus "$ch_cpus" --memory "$ch_memory" --memory-swap "$ch_memory" \
 -e CLICKHOUSE_SKIP_USER_SETUP=1 -e CLICKHOUSE_USER=bench -e "CLICKHOUSE_PASSWORD=$password" -e CLICKHOUSE_DB=vg_query_perf \
 -e "GRAPH_CH_APP_PASSWORD=$app_password" -e "GRAPH_CH_MIGRATE_PASSWORD=$password" -e "GRAPH_CH_SCANNER_PASSWORD=$password" \
 -v "$output/config.xml:/etc/clickhouse-server/config.d/zz-fixture.xml:ro" \
 -v "$output/users.xml:/etc/clickhouse-server/users.d/zz-profile.xml:ro" \
 -v "$output/graph-users.xml:/etc/clickhouse-server/users.d/graph-users.xml:ro" \
 -v "$output/fixture-admin.xml:/etc/clickhouse-server/users.d/fixture-admin.xml:ro" \
 -p 127.0.0.1::9000 "$ch_image" > /dev/null
ready=0
ready_deadline=$((SECONDS + 90))
while (( SECONDS < ready_deadline )); do
 ch_process="$(bounded 5 docker exec "$ch" cat /proc/1/comm 2>/dev/null || true)"
 pg_process="$(bounded 5 docker exec "$pg" cat /proc/1/comm 2>/dev/null || true)"
 if [[ "$ch_process" = clickhouse* && "$pg_process" = postgres ]] && \
  bounded 5 docker exec "$pg" pg_isready -h 127.0.0.1 -U bench -d vg_query_perf >/dev/null 2>&1 && \
  bounded 5 docker exec "$ch" clickhouse-client --user bench --password "$password" --query 'SELECT 1' >/dev/null 2>&1; then ready=1; break; fi
 sleep 1
done
if [[ "$ready" != 1 ]]; then echo 'isolated databases not ready; inspect retained logs' >&2; exit 1; fi
pg_port="$(bounded 5 docker port "$pg" 5432/tcp | sed 's/.*://')"
ch_port="$(bounded 5 docker port "$ch" 9000/tcp | sed 's/.*://')"
export PERF_QUERY_ISOLATED=1 PERF_LARGE_JOIN_ISOLATED=1 PERF_JOIN_PROFILE="$profile" PERF_QUERY_DIR="$output" PERF_JOIN_RESOURCES="$resources"
export PERF_COMMIT="$(git rev-parse HEAD)" GOMAXPROCS="${GOMAXPROCS:-4}"
export PERF_POSTGRES_URL="postgres://bench:$password@127.0.0.1:$pg_port/vg_query_perf?sslmode=disable"
export PERF_CLICKHOUSE_URL="clickhouse://bench:$password@127.0.0.1:$ch_port/vg_query_perf"
export PERF_APP_CLICKHOUSE_URL="clickhouse://graph:$app_password@127.0.0.1:$ch_port/vg_query_perf"
helm version --short > "$output/helm-version.txt"
python3 scripts/performance_trend.py environment "$pg" "$ch" > "$output/environment.json"
bounded 10 docker inspect --format '{{.Name}} image={{.Image}} memory={{.HostConfig.Memory}} memoryswap={{.HostConfig.MemorySwap}} nanocpus={{.HostConfig.NanoCpus}}' "$pg" "$ch" > "$output/environment.txt"
git ls-files -z --cached --others --exclude-standard | xargs -0 shasum -a 256 > "$output/source-files.sha256"
GIT_INDEX_FILE="$tmp/source-index" git read-tree HEAD
GIT_INDEX_FILE="$tmp/source-index" git add -A
GIT_INDEX_FILE="$tmp/source-index" git diff --cached --binary HEAD > "$output/source.patch"
shasum -a 256 "$output/source.patch" > "$output/source-patch.sha256"
python3 "$root/scripts/run_bounded.py" 3600 docker stats --format '{{json .}}' "$pg" "$ch" > "$output/container-stats.jsonl" &
stats_pid=$!
python3 "$root/scripts/run_bounded.py" 3600 python3 scripts/sample-container-resources.py "$ch" > "$output/clickhouse-resources.jsonl" &
resources_pid=$!
printf "stage=migrations time=%s\n" "$(date -u +%FT%TZ)"
bounded 600 go test -tags=integration ./internal/perfassurance -run '^TestPrepareQueryDatabases$' -count=1 -v > "$output/migrations.log" 2>&1
bounded 10 docker exec "$ch" clickhouse-client --user bench --password "$password" --query 'SELECT version()' > "$output/clickhouse-version.txt"
bounded 10 docker exec "$ch" clickhouse-client --user graph --password "$app_password" --query "SELECT getSetting('max_threads') AS max_threads,getSetting('max_block_size') AS max_block_size,getSetting('max_memory_usage') AS max_memory_usage,getSetting('max_execution_time') AS max_execution_time FORMAT JSON" > "$output/query-settings.json"
printf "stage=measurements time=%s\n" "$(date -u +%FT%TZ)"
bounded 3300 go test -p 1 -tags=integration ./internal/throughput -run '^TestLargeJoin(Costs|TimeoutTelemetry)$' -count=1 -timeout=50m -v 2>&1 | tee "$output/run.log"
completed=1
printf "stage=complete time=%s\n" "$(date -u +%FT%TZ)"
