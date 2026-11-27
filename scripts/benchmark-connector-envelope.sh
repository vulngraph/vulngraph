#!/usr/bin/env bash
# Local fixtures only. Render deployed tuning; retain exact config/image/source.
set -euo pipefail
profile="${1:-smoke}"
case "$profile" in smoke|target|million|two-million) ;; *) echo 'expected smoke, target, million or two-million' >&2; exit 2;; esac
root="$(cd "$(dirname "$0")/.." && pwd)"
bounded() { python3 "$root/scripts/run_bounded.py" "$@"; }
resources="${PERF_ENVELOPE_RESOURCES:-deployed}"
case "$resources" in
 deployed) ch_cpus=2; ch_memory=4g; server_memory=3221225472; query_memory=2147483648; worker_cpus=1; worker_memory=4g;;
 local16g) ch_cpus=4; ch_memory=8g; server_memory=6442450944; query_memory=2147483648; worker_cpus=4; worker_memory=16g;;
 *) echo 'expected deployed or local16g resources' >&2; exit 2;;
esac
case "$profile" in
 smoke) connectors=25; assets=5000;;
 target) connectors=500; assets=100000;;
 million) connectors=500; assets=1000000;;
 two-million) connectors=500; assets=2000000;;
esac
if [[ -n "${PERF_ENVELOPE_SCOPE_COUNTS:-}" ]]; then
  connectors="$(python3 -c 'import json,sys; x=json.loads(sys.argv[1]); assert set(x)<=set(("aws","gcp","kubernetes","github")); assert all(type(v) is int and 0<=v<=10000 for v in x.values()); print(sum(x.values()))' "$PERF_ENVELOPE_SCOPE_COUNTS")"
fi
helm_limits=(--set-string "clickhouse.tuning.maxServerMemoryBytes=$server_memory" --set-string "clickhouse.tuning.maxMemoryBytes=$query_memory")
output="${2:?choose a fresh output directory}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
if [[ -n "$(find "$output" -mindepth 1 -print -quit)" ]]; then echo 'output must be fresh' >&2; exit 2; fi
ch_image="${PERF_ENVELOPE_IMAGE:-clickhouse/clickhouse-server:26.8-alpine@sha256:31d60795ca6ac748a20712b5d8d047e415c44d370a86e89a63cd251b0eaed9e9}"
case "$ch_image" in clickhouse/clickhouse-server:*@sha256:*) ;; *) echo 'pin an official ClickHouse image digest' >&2; exit 2;; esac
pg_image='postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d'
tmp="$(mktemp -d "${TMPDIR:-/tmp}/vg-connector-envelope.XXXXXX")"
suffix="$(basename "$tmp" | tr '[:upper:].' '[:lower:]-')"
ch="$suffix-ch"; pg="$suffix-pg"; worker="$suffix-worker"; builder="$suffix-build"; pg_resources_pid=''; stats_pid=''; resources_pid=''; completed=0; measurements_started=0
cleanup() {
 local result=$?
 local resources_status=0 stats_status=0
 if [[ -n "$pg_resources_pid" ]]; then kill "$pg_resources_pid" 2>/dev/null || true; wait "$pg_resources_pid" 2>/dev/null || true; fi
 trap - EXIT
 if [[ "$result" = 0 && "$completed" != 1 ]]; then result=1; fi
 if [[ -n "$resources_pid" ]]; then kill "$resources_pid" 2>/dev/null || true; wait "$resources_pid" 2>/dev/null || resources_status=$?; fi
 if [[ -n "$stats_pid" ]]; then kill "$stats_pid" 2>/dev/null || true; wait "$stats_pid" 2>/dev/null || stats_status=$?; fi
 printf '{"resource_sampler_exit":%d,"statistics_exit":%d}\n' "$resources_status" "$stats_status" > "$output/cleanup-status.json"
 case "$resources_status" in 0|143) ;; *) result=1;; esac
 case "$stats_status" in 0|143) ;; *) result=1;; esac
 if [[ "$measurements_started" = 1 ]]; then
  bounded 20 docker exec "$ch" clickhouse-client --user bench --password "$password" --query 'SYSTEM FLUSH LOGS' > "$output/query-log-flush.log" 2>&1 || result=1
  bounded 30 docker exec "$ch" clickhouse-client --user bench --password "$password" --query "SELECT event_time_microseconds, query_id, type, log_comment, normalizeQuery(query) AS normalized_query, query_duration_ms, read_rows, read_bytes, written_rows, written_bytes, memory_usage, ProfileEvents, exception_code FROM system.query_log WHERE initial_user='graph' AND type!='QueryStart' ORDER BY event_time_microseconds FORMAT JSONEachRow" > "$output/application-query-costs.jsonl" 2> "$output/query-cost-errors.log" || result=1
 fi
 bounded 10 docker logs "$ch" > "$output/clickhouse.log" 2>&1 || true
 bounded 10 docker logs "$pg" > "$output/postgres.log" 2>&1 || true
 bounded 10 docker inspect --format '{{json .State}}' "$worker" > "$output/worker-exit.json" 2>/dev/null || true
 bounded 15 docker rm -fv "$worker" "$builder" "$ch" "$pg" >/dev/null 2>&1 || true
 bounded 10 docker network rm "$suffix" >/dev/null 2>&1 || true
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
python3 - "$output" "$resources" "$ch_cpus" "$server_memory" "$query_memory" <<'PY'
import json,pathlib,re,shutil,subprocess,sys
root=pathlib.Path(sys.argv[1]);src=(root/'effective-config.yaml').read_text()
host=json.loads(subprocess.check_output(['docker','info','--format','{"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}}}']))
free=shutil.disk_usage(root).free
if free<40*1024**3:raise SystemExit('less than 40 GiB free workspace disk')
if sys.argv[2]=='local16g' and (host['memory_bytes']<32*1024**3 or host['cpus']<8):raise SystemExit('local16g requires at least 24 GiB Docker memory and 8 CPUs')
(root/'resource-profile.json').write_text(json.dumps({'cohort':sys.argv[2],'clickhouse_cpus':int(sys.argv[3]),'server_memory_bytes':int(sys.argv[4]),'query_memory_bytes':int(sys.argv[5]),'per_query_threads':2,'fixed_comparison_query_budget_bytes':512*1024**2,'docker':host,'workspace_free_bytes':free,'limitation':'local synthetic one-worker envelope, not SDK or fleet capacity evidence'},indent=2)+'\n')
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
bounded 10 docker network create "$suffix" >/dev/null
bounded 180 docker run -d --network "$suffix" --name "$pg" --cpus 1 --memory 1g \
 -e POSTGRES_USER=bench -e "POSTGRES_PASSWORD=$password" -e POSTGRES_DB=vg_query_perf \
 -p 127.0.0.1::5432 "$pg_image" > /dev/null
bounded 180 docker run -d --network "$suffix" --name "$ch" --cpus "$ch_cpus" --memory "$ch_memory" \
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
export PERF_QUERY_ISOLATED=1 PERF_ENVELOPE_ISOLATED=1 PERF_ENVELOPE_DIR="$output"
export PERF_COMMIT="$(git rev-parse HEAD)" GOMAXPROCS=4
export PERF_POSTGRES_URL="postgres://bench:$password@127.0.0.1:$pg_port/vg_query_perf?sslmode=disable"
export PERF_CLICKHOUSE_URL="clickhouse://bench:$password@127.0.0.1:$ch_port/vg_query_perf"
export PERF_APP_CLICKHOUSE_URL="clickhouse://graph:$app_password@127.0.0.1:$ch_port/vg_query_perf"
helm version --short > "$output/helm-version.txt"
python3 scripts/performance_trend.py environment "$pg" "$ch" > "$output/environment.json"
bounded 10 docker inspect --format '{{.Name}} image={{.Image}} memory={{.HostConfig.Memory}} nanocpus={{.HostConfig.NanoCpus}}' "$pg" "$ch" > "$output/environment.txt"
git ls-files -z --cached --others --exclude-standard | xargs -0 shasum -a 256 > "$output/source-files.sha256"
GIT_INDEX_FILE="$tmp/source-index" git read-tree HEAD
GIT_INDEX_FILE="$tmp/source-index" git add -A
GIT_INDEX_FILE="$tmp/source-index" git diff --cached --binary HEAD > "$output/source.patch"
shasum -a 256 "$output/source.patch" > "$output/source-patch.sha256"
printf "stage=migrations time=%s\n" "$(date -u +%FT%TZ)"
bounded 600 go test -tags=integration ./internal/perfassurance -run '^TestPrepareQueryDatabases$' -count=1 -v > "$output/migrations.log" 2>&1
bounded 10 docker exec "$ch" clickhouse-client --user bench --password "$password" --query 'SELECT version()' > "$output/clickhouse-version.txt"
bounded 10 docker exec "$ch" clickhouse-client --user graph --password "$app_password" --database vg_query_perf --query "SELECT name,value,changed FROM system.settings WHERE name IN ('enable_shared_storage_snapshot_in_query','enable_analyzer','enable_scalar_subquery_optimization','max_threads','max_memory_usage','max_execution_time','join_algorithm') FORMAT JSONEachRow" > "$output/effective-query-settings.jsonl"
modules="$(go env GOMODCACHE)"
cache="${PERF_LINUX_GO_CACHE:?set an isolated or sequentially shared Linux Go cache}"
printf "stage=compile-worker time=%s\n" "$(date -u +%FT%TZ)"
bounded 900 docker run --rm --name "$builder" --cpus 4 --memory 8g \
 --user "$(id -u):$(id -g)" -v "$root:/workspace:ro" -v "$modules:/go/pkg/mod" -v "$cache:/go-cache" -v "$output:/evidence" -w /workspace \
 -e GOTOOLCHAIN=local -e GOMAXPROCS=4 -e GOCACHE=/go-cache -e GOFLAGS=-buildvcs=false \
 golang:1.26.11-trixie go test -c -tags=integration -o /evidence/envelope.test ./internal/jobs > "$output/compile.log" 2>&1
bounded 10 docker image inspect golang:1.26.11-trixie --format '{{.Id}} {{json .RepoDigests}}' > "$output/worker-image.txt"
python3 scripts/sample-container-resources.py "$ch" > "$output/clickhouse-resources.jsonl" &
resources_pid=$!
python3 scripts/sample-container-resources.py "$pg" > "$output/postgres-resources.jsonl" &
pg_resources_pid=$!
python3 scripts/sample-envelope-database.py "$ch" vg_query_perf > "$output/database-timeline.jsonl" &
stats_pid=$!
printf "stage=measurements time=%s\n" "$(date -u +%FT%TZ)"
measurements_started=1
bounded 3500 docker run --name "$worker" --network "$suffix" --cpus "$worker_cpus" --memory "$worker_memory" \
 --user "$(id -u):$(id -g)" -v "$output:/evidence" -v "$root:/workspace:ro" -w /evidence \
 -e GOMAXPROCS="$worker_cpus" -e PERF_ENVELOPE_ISOLATED=1 -e PERF_ENVELOPE_DIR=/evidence \
 -e PERF_ENVELOPE_CONNECTORS="$connectors" -e PERF_ENVELOPE_ASSETS="$assets" -e PERF_COMMIT="$PERF_COMMIT" \
 -e PERF_ENVELOPE_SCOPE_COUNTS="${PERF_ENVELOPE_SCOPE_COUNTS:-}" \
 -e PERF_ENVELOPE_COLLECT_HOLD_MS="${PERF_ENVELOPE_COLLECT_HOLD_MS:-500}" \
 -e PERF_ENVELOPE_REPRODUCE_HISTORICAL_LOST_UPDATE="${PERF_ENVELOPE_REPRODUCE_HISTORICAL_LOST_UPDATE:-0}" \
 -e PERF_POSTGRES_URL="postgres://bench:$password@$pg:5432/vg_query_perf?sslmode=disable" \
 -e PERF_APP_CLICKHOUSE_URL="clickhouse://graph:$app_password@$ch:9000/vg_query_perf" \
 -e PERF_CLICKHOUSE_URL="clickhouse://bench:$password@$ch:9000/vg_query_perf" \
 golang:1.26.11-trixie /evidence/envelope.test -test.run "${PERF_ENVELOPE_TEST:-^TestConnectorMemoryEnvelope$}" -test.v -test.timeout=58m \
 > "$output/run.log" 2>&1
completed=1
printf "stage=complete time=%s\n" "$(date -u +%FT%TZ)"
