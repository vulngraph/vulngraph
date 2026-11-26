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
a name change on one percent of workloads, and another unchanged refresh. The
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

The PR workflow runs `smoke` and uploads the report, including on failure. It
requires exact resident counts, public/private reachability, expected sync paths,
five graph-source queries per refresh, and a read-row budget of six times the
physical fixture size. The query/read budgets must be reviewed when intentionally
changing the pipeline. Timing and memory are reported without a flaky shared-runner
latency threshold. `workflow_dispatch` also supports `medium`.

For comparisons, use the same fixture version, machine, container limits, build
settings and database versions. Repeat at least three fresh runs and compare
medians plus the slowest run. A single local result is not a production capacity
claim. This harness does not measure connector APIs, correlation/enrichment job
throughput, deletion-backlog draining, concurrent user traffic, or every query
shape. IDs are highly compressible and metadata is deliberately small; production
payload sizes and distributions can cost substantially more. Those cases need
separate scenarios and correctness assertions.
