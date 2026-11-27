#!/usr/bin/env bash
# Real GitHub collector, deterministic populated APIs; no GitHub network calls.
# Coordinate an exclusive hardware slot before recording comparable results.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
output="${1:?usage: benchmark-github-visibility.sh NEW_OUTPUT_DIRECTORY}"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
if [[ -e "$output/environment.txt" ]]; then
  echo "choose a fresh evidence directory" >&2
  exit 2
fi
cd "$root"
export GOTOOLCHAIN=go1.26.11 GOMAXPROCS="${GOMAXPROCS:-4}"
export PERF_CONNECTORS=1 PERF_CONNECTOR_DIR="$output"
{
  uname -srm
  go version
  git rev-parse HEAD
  git diff HEAD --stat
  printf 'GOMAXPROCS=%s; API fixture transport; no network latency\n' "$GOMAXPROCS"
} > "$output/environment.txt"
git diff HEAD > "$output/source.patch"
shasum -a 256 "$output/source.patch" > "$output/source.sha256"
# Compile once, outside the measured processes. RSS includes the retained
# collector results and JSON evidence writer; per-run total allocations are
# measured by the shared collector harness and carry a separate linear gate.
go test -c -o "$output/github.test" ./internal/collect/github
for size in 100 1000 10000; do
  export PERF_CONNECTOR_MAX="$size"
  if [[ "$(uname -s)" == Darwin ]]; then
    /usr/bin/time -l "$output/github.test" -test.run "^TestConnectorScale$/^github(_denied|_pending)?$/$size$" -test.count=1 -test.v -test.timeout=10m > "$output/run-$size.log" 2> "$output/resources-$size.txt"
  else
    /usr/bin/time -v "$output/github.test" -test.run "^TestConnectorScale$/^github(_denied|_pending)?$/$size$" -test.count=1 -test.v -test.timeout=10m > "$output/run-$size.log" 2> "$output/resources-$size.txt"
  fi
done
python3 - "$output" <<'PY'
import json,pathlib,statistics,sys
root=pathlib.Path(sys.argv[1]); summary=[]
for name in ('github','github_denied','github_pending'):
    for n in (100,1000,10000):
        rows=json.loads((root/f'{name}-{n}.json').read_text())
        assert len(rows)==3
        assert all(r['assets']==6*n+5 and r['edges']==7*n+2 and r['duplicate_asset_rows']==0 and not r['partial'] for r in rows)
        summary.append(dict(scenario=name,repositories=n,runs=3,median_seconds=statistics.median(r['seconds'] for r in rows),max_allocated_bytes=max(r['allocated_bytes'] for r in rows),assets=rows[0]['assets'],edges=rows[0]['edges'],requests=rows[0]['requests']))
(root/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
costs=[json.loads(line.split('SBOM_REQUEST_COST ',1)[1]) for n in (100,1000,10000) for line in (root/f'run-{n}.log').read_text().splitlines() if 'SBOM_REQUEST_COST ' in line]
assert len(costs)==27
(root/'request-cost.json').write_text(json.dumps(costs,indent=2)+'\n')
print(json.dumps(summary,indent=2))
PY
