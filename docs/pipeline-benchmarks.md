# Synthetic pipeline benchmarks

Run the production ClickHouse reads, finding rollups, and Ladybug graph refresh
against generated data, with no cloud account or production dump:

```sh
scripts/fetch-ladybug.sh
scripts/benchmark-pipeline.sh smoke /tmp/vulngraph-smoke
scripts/benchmark-pipeline.sh medium /tmp/vulngraph-medium
```

Requires Docker, the repository's Go toolchain, and the native library dependencies
listed in `scripts/fetch-ladybug.sh`. The script starts fresh Postgres and ClickHouse
containers on random loopback ports, applies the real Goose and River migrations,
and removes those containers and their volumes on exit. It ignores application
database environment variables. Results and failure logs remain in the output
directory; omitting that argument creates a temporary results directory.

| Profile | Resident nodes | Core edges | Package memberships |
| --- | ---: | ---: | ---: |
| `smoke` | 1,350 | 3,250 | 20,000 |
| `medium` | 27,000 | 65,000 | 2,000,000 |
| `core` | 810,000 | 1,950,000 | 0 |
| `2m` | 810,000 | 1,950,000 | 2,000,000 |
| `20m` | 810,000 | 1,950,000 | 20,000,000 |

The three large profiles hold core topology, package nodes and findings constant;
only package memberships change. Run them on the same dedicated machine to compare
the cost of package inventory. They are explicit local runs, not PR defaults:

```sh
scripts/benchmark-pipeline.sh core /tmp/vulngraph-core
scripts/benchmark-pipeline.sh 2m /tmp/vulngraph-2m
scripts/benchmark-pipeline.sh 20m /tmp/vulngraph-20m
```

The deterministic fixture has public and private ingress → service → pod paths,
pods sharing images, workload roles and role chains, shared hot packages and a
rotating package tail, plus direct and package findings with enrichment rows.
One percent of edge sources also receive older row versions. Logical row counts
are checked before timing so duplicate memberships cannot inflate the dataset.
ClickHouse background merges may collapse physical versions during the run.
Bulk seeding uses `INSERT SELECT numbers(...)`; millions of objects are not
allocated in the Go process just to prepare a measurement.

Each run measures an initial build, two unchanged refreshes, a finding-only update,
a name change on one percent of workloads, and another unchanged refresh. A
public graph query verifies the changed node name and its image relationship. The
storage cache is already warm from seeding and validation: the initial build is
not a cold-disk measurement. Snapshots are disabled. Seeding time is separate.

`report.json` records:

- Full elapsed time and graph phase durations, resident counts, and core edges per
  second for successful full builds. Throughput counts the core edges actually
  processed, not the unloaded package memberships.
- Each measured ClickHouse query's duration, rows/bytes read, result rows, memory,
  exception, SQL, and normalized hash. The phase uses a unique `log_comment`; setup,
  validation and telemetry queries are excluded.
- Go allocations and heap after each refresh; process peak RSS includes native
  Ladybug allocations. RSS is the cumulative process high-water mark, not an
  independent per-phase peak. Query memory is a per-query maximum, not total
  ClickHouse server memory or the sum of concurrent peaks.
- Fixture version, source commit, profile and Go platform. `environment.txt`
  records image identities, container limits and working-tree changes.

The ClickHouse container defaults to 8 GiB and four CPUs; override with
`PERF_CH_MEMORY` and `PERF_CH_CPUS`. The Go process defaults to `GOMAXPROCS=4` and
uses a 256 MiB Ladybug buffer pool for small profiles and 1,280 MiB (the worker
default) for the three large profiles. Override with `PERF_LADYBUG_MB` to test memory
pressure. Both configurations use two query threads and two loader threads.
That buffer pool is not a cap on total process memory. Budget additional host
memory for Go, Ladybug and Docker. Run one profile at a time.

The PR workflow runs `smoke`, connector fixtures up to 1,000 resources, and the real
sync worker over those results. It uploads reports, including on failure, and
requires exact resident counts, public/private reachability, expected sync paths,
five graph-source queries per refresh, and a read-row budget of three times the
physical fixture size. The query/read budgets must be reviewed when intentionally
changing the pipeline. Timing and memory are reported without a flaky shared-runner
latency threshold. `workflow_dispatch` also supports `medium`.

For comparisons, use the same fixture version, machine, container limits, build
settings and database versions. Repeat at least three fresh runs and compare
medians plus the slowest run. A single local result is not a production capacity
claim. The graph scenarios alone do not measure concurrent user traffic or queued
correlation/enrichment execution. IDs are highly compressible and metadata is
small; production payload sizes and distributions can cost substantially more.

The report also records signal-refresh native write counts and lock time, bounded
supply-chain lineage query costs, and deletion confirmation at 1,106 hashes for
small profiles and 548,000 for large profiles. The latter verifies two disjoint
5,000-ID batches; it does not claim a timed full drain of 548,000 resources. Separate
real-worker tests verify complete retirement, shared ownership, partial results,
and reappearing resources. Migration tests cover upgrade from existing rows,
rollback, replay and candidate cleanup through foreign keys.

## Connector and sync measurements

```sh
scripts/benchmark-connectors.sh /tmp/vulngraph-connectors
PERF_REQUEST_DELAY_MS=1 scripts/benchmark-connectors.sh /tmp/vulngraph-connectors-latency
PERF_CONNECTOR_MAX=1000 scripts/benchmark-connectors.sh /tmp/vulngraph-connectors-small
```

The default measures 100, 1,000 and 10,000 primary resources three times each.
`PERF_CONNECTOR_MAX` accepts 100, 1000 or 10000. Demo uses its built-in fixed estate.
No cloud credentials are needed: HTTP transports/client interfaces serve local
fixtures. Optional per-request delay is simulated latency, not a live API result.

| Connector | Measured collection path |
| --- | --- |
| AWS | Paginated EC2 collection through the real collector |
| GCP | Compute inventory; unavailable auxiliary families explicitly mark the result partial |
| Azure | ARM SDK VM pages, NIC reads, shared subnet enrichment |
| Kubernetes | Namespaces, pods, application/sidecar/init containers and resolved images; additional real SDK pod pagination with 1% wide annotations |
| GitHub | Repository pagination, SBOM, branch protection, CODEOWNERS and empty trees; successful and denied GraphQL |
| Okta | Users, factors, groups, membership and policy listings |
| Google Workspace | OAuth signing, user pages and MFA metadata |
| Demo | Built-in fixture collection |
| AWS Organizations | Real Postgres reconciliation, child creation, unchanged passes and failed discovery |

Collection JSON records counts, allocations, elapsed time, request counts where
instrumented, and partial status. Kubernetes uses a client-interface fixture, so
its zero HTTP count is not a measurement of Kubernetes API requests. The separate
`kubernetes_paged` fixture counts real SDK requests against a synthetic HTTP
transport and requires one request per 500 pods, including the final partial page.

The largest successful fixture for each connector then runs through the real sync
worker, checks, encrypted connector storage, Postgres hashes, ClickHouse writes and
River insertion. Initial, unchanged, 1% changed, unchanged-again and partial runs
assert fingerprint behavior and read back every expected asset and relationship
through the inventory service. These checks cover names, metadata, tags, endpoint
types and edge properties, including resources omitted by the partial sweep.
Connector sync fixture version 2 changes metadata and edge properties as well as
names in the 1% scenario; compare it only with the same fixture version. `sync.json`
records verified counts, per-phase timing, allocations, queued jobs and ClickHouse
query/read/memory counts. Readback checks run outside the timed region and can
warm storage caches before the next scenario.
The insert-only queue is emptied before each measurement so saturation from a
previous connector cannot hide enqueue costs. Native inventory/finding writes
use at most 2,000 rows and a 4 MiB estimated payload per batch; a single oversized
row is sent alone. Wide, escaped metadata has a separate storage regression test.
Observation history reads only the required date columns. A wide-row storage
regression checks the newest persisted first-seen dates and requires those
lookups to read less than one quarter of the full-row query bytes.
Queued enrichment and scanning jobs are inserted but are not executed by this
benchmark. `aws_org.json` measures account reconciliation separately.

`correlations.log` also records three samples of Kubernetes selector matching
and GCP impersonation at 100, 1,000 and 10,000 resources. These isolated Go
benchmarks check their output on each iteration, exclude fixture construction,
and report elapsed time and allocations. Selector matching uses a cluster- and
namespace-scoped label index; the GCP fan-out cap is applied after a shared
project ordering. Their timing does not include storage or queue execution.

## Consumed queues and sustained reads

```sh
PERF_CONNECTOR_MAX=1000 PERF_SOAK_SECONDS=300 \
  scripts/benchmark-connectors.sh /tmp/vulngraph-soak
```

The optional soak adds actual River consumers at the production queue concurrency
for sync, enrichment, correlation and graph rebuilds. It replays the collected
fixtures through the production workers, four local enrichment sources and 24
correlation rules. Every wave changes 1% of asset and edge properties. It waits
for those queues to drain, then requires the database backlog of findings still
awaiting enrichment to be empty.
The production admission path creates one durable backfill job when work is
deferred. It resumes in bounded batches with queue backpressure; routine drift
keeps its periodic cadence. The harness never injects extra sweep ticks. A
storage regression fills the ingest queue and verifies that all severities
recover, including after the worker is restarted.

At least three waves run. `PERF_SOAK_SECONDS` sets a minimum duration, from 1 to
600 seconds; draining the final wave can exceed it. One collection fails
transiently. Another blocks during a forced worker cancellation; the River client
is reconstructed and its persisted jobs must recover. This tests worker
cancellation and queue recovery, not power loss or a database crash. A fresh
Ladybug engine must also rebuild from stored data without a snapshot.

Concurrent inventory, finding-list and public Cypher service calls record
p50/p95/p99 latency and must have zero errors. These are service calls, not HTTP
middleware or network benchmarks. Every expected stored asset and edge is read
back, and completed enrichment jobs must have the exact returned scores, bands
and factor values persisted, with no final unmeasured sources. Unexpected blast
query failures fail the run, including failures that the scorer can recover
from with a fallback. Soak fixture version 4 records these checks and uses production backfill
scheduling. Earlier fixtures drove backfill ticks directly and are not comparable
end-to-end timing baselines. The query concurrency is recorded as well. The report
includes queue peaks, retries, backfill ticks, ClickHouse query/read/memory costs,
the 25 most costly normalized query shapes by cumulative query duration,
Go heap after GC and cumulative process peak RSS. It also reports graph edges
dropped by type or missing endpoints: the VM-only Azure fixture lacks its NSG
endpoint and the deliberately partial GCP fixture has an absent endpoint.
Stored relationship verification does not imply every relationship is traversable.

External vulnerability feeds, LLM decisions, registry pulls and disk scans are
outside this run. Jobs for those lanes remain unconsumed and are reported.
The PR workflow enables a 60-second minimum soak. Timing and memory remain
measurements; correctness, recovery and complete enrichment are required.

## Repeatable trends

The weekly/manual `Performance trends` workflow runs three fresh complete
benchmarks, each with a five-minute minimum soak, and keeps the samples and
summary for 90 days. Its shared-runner timing results are informational.

```sh
for run in 1 2 3; do
  PERF_CONNECTOR_MAX=1000 PERF_SOAK_SECONDS=300 \
    scripts/benchmark-connectors.sh "/tmp/vulngraph-trend/run-$run"
done
python3 scripts/performance_trend.py summarize /tmp/vulngraph-trend/run-* > /tmp/candidate.json
python3 scripts/performance_trend.py compare /tmp/baseline.json /tmp/candidate.json
```

Create baselines from a clean committed tree. Summaries require three successful,
distinct runs at the same revision and reject missing scenario coverage,
read errors or incomplete recovery. Later waves contribute sustained timing and
memory peaks as well as the initial/restart samples. Summaries include collection, organization
reconciliation, sync, graph and consumed-queue timings and costs. Hardware,
container image identities and limits, toolchain and fixture counts must match
before two summaries can be compared. A regression needs both a median more
than 25% above baseline and non-overlapping measured ranges.

On a dedicated benchmark machine, set the same `PERF_BASELINE_MACHINE` label for
both cohorts and pass `compare --enforce` to make a regression fail the command.
The label is an operator assertion of controlled hardware and load; it does not
reserve a runner. No dedicated runner or strict timing gate is provisioned by
these workflows. Keep baseline JSON outside the source tree and retain the raw
samples so changes can be reviewed.

CI gates cardinality, safety, API request budgets, query counts, result bounds and
signal write counts rather than wall-clock thresholds. Manual workflow runs use
10,000-resource connector fixtures. These representative scenarios cover every
connector type, but not every service family, API quota, throttling pattern or
production payload. Full-suite connector correctness tests remain separate from
performance measurements.

Enrichment retains ten concurrent workers. Its River fetch cooldown is 10 ms;
the default 100 ms would impose a ceiling of 100 short jobs per second even
with idle storage. Idle polling retains River's default. Concurrent finding
reads are combined into fresh queries of at most ten IDs; results are not
cached. The soak uses the same queue configuration and reader as production.

The soak defaults to four concurrent ClickHouse queries. Set
`PERF_SOAK_CH_CONCURRENCY=8` to measure the application's default query
concurrency on the same CPU and memory limits. The report records this value,
and trend comparisons reject mixed concurrency settings. Storage-only phases
retain their four-query limit.

To measure the precision migration with existing rows, point `TEST_CLICKHOUSE_URL`
at a disposable test server and run:

```sh
PERF_MIGRATION_ROWS=20000000 PERF_MIGRATION_REPORT=/tmp/migration.json \
  go test -tags=integration ./migrations/clickhouse \
  -run '^TestPreciseVersionsPopulatedScale$' -count=1 -v
```

This creates and removes its own database, seeds the old schema, and checks the
upgraded relationship values. The elapsed time includes the migration's copy and
verification, with seeding excluded. The ordinary migration integration suite
also covers populated upgrade, rollback, interrupted copies and restricted grants.
