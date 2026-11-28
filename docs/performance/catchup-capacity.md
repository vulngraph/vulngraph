# Large-join catch-up capacity

Measured 2026-11-28, for PERF-04/07/11. **The current production queries complete
this workload on the measured 16-CPU ClickHouse configuration.** A fresh 8-CPU
control fails four reads. Two further 16-CPU confirmations succeed. This is one
matched pair plus two candidate confirmations, not three matched pairs.

The [sizing guide](sizing.md) distinguishes this database result from whole-estate
capacity. [Compact measurements and artifact hashes](results/catchup-capacity-2026-11-28.json)
retain every run, failed alternatives and resource accounting. No query algorithm,
default deployment limit or full-profile acceptance changes.

## Workload and resources

The synthetic fixture has one million logical assets, five million findings,
25 million enrichment IDs and 100 million package memberships. Initially it
stores 1,011,000 asset rows, 15 million finding rows, 75 million enrichment rows
and 123,266,003 edge rows. Missing/orphan enrichment, three versions, resolved
findings and skewed memberships are included. It uses small representative
payloads and compressible IDs, not a production estate export.

Each fresh-store run offers one alternating summary/cluster read per second for
30 seconds, 200 distinct finding observations per second and one package-risk
read every five seconds. Eight read workers share eight application database
slots. Both configurations accumulate the same five-second write window and use
1,000-row repository calls; enrichment native batches remain 500 rows. Read
deadlines are ten seconds after admission. Slow starts and admission waits count.
Every write window is read back with source times; every successful read matches
independent expected values. Aggregate fields remain invariant during these
writes: this does not prove atomic cross-table publication.

| ClickHouse setting | Control | Successful configuration |
| --- | ---: | ---: |
| CPUs | 8 | 16 |
| Container RAM / swap | 16 GiB / disabled | 32 GiB / disabled |
| Server memory tracker | 12 GiB | 24 GiB |
| Per-query memory limit / threads | 4 GiB / 2 | 4 GiB / 2 |
| Merge threads / task concurrency ratio | 16 / 2 | 16 / 2 |

CPU and RAM limits change together; this does not isolate CPU from memory or
establish a minimum RAM requirement. SQL and arrivals are unchanged. Both use
ClickHouse 26.8.34.13, pinned image digest and rendered deployment XML. The Go
1.26.11 client runs on macOS ARM64 and ClickHouse on Linux ARM64. The host has
64 GiB RAM; Docker has 18 CPUs and approximately 39 GiB RAM. Other containers
remain running. Sampled VM available memory and swap are retained; unavailable
pressure-stall metrics are marked unavailable. This is not the native 128-GiB
stress host.

## Results, including merge recovery

| Run | Reads | Read p95 / p99 | Verified write freshness p95 | Arrival start to merge quiescence |
| --- | ---: | ---: | ---: | ---: |
| 8-CPU control | 26 / 30 | 10.465 / 11.082 s | 16.000 s | 39.389 s |
| 16-CPU run 1 | 30 / 30 | 3.928 / 4.069 s | 6.215 s | 35.563 s |
| 16-CPU run 2 | 30 / 30 | 3.814 / 3.981 s | 6.205 s | 35.545 s |
| 16-CPU run 3 | 30 / 30 | 4.222 / 4.535 s | 6.316 s | 35.554 s |

Each successful run also verifies all six update windows and six package reads,
with zero operation/SQL errors and exactly 66 terminal query records. The control
has three timed-out reads and one server-memory failure; its successful-only
percentiles do not hide those failures. All six control write windows pass.

Quiescence means five stable part/row/byte samples with zero active normal
merges, within three minutes; no `OPTIMIZE FINAL` is used. It is not full
compaction or identical final physical layouts. Part counts and a final exact
summary/cluster readback are retained. CPU and IO include this recovery window,
so work is not simply deferred beyond the 30-second arrival window.

The control uses 259.29 CPU core-seconds through recovery; the three successful
runs use 202.48, 197.83 and 207.05. ClickHouse cgroup peaks are 15.57 GB versus
13.70 / 13.54 / 13.27 GB, with no swap. Cgroup memory includes file cache; these
are not whole-application footprints. Per-device physical writes vary from
1.32 to 3.01 GB in successful runs, versus 1.33 GB in the control. Logical query
`read_bytes` is recorded separately from disk IO. A larger cap is not measured
consumption, and smaller observed consumption does not prove a smaller cap works.

All runs still fail the historical 512-MiB query / 1.5-second p95 comparison
guards. Those failures remain visible and return a failing benchmark test.
Successful runs meet the separate 5/10-second stress latency reference, but do
not accept its different arrivals, payloads, history, hardware or 24-hour budget.

## Rejected alternatives

One matched pair reduced merge execution threads from 16 to 4 while retaining
32 admitted merge tasks: successful reads fell 26 to 24, CPU rose 251.04 to
283.51 core-seconds and quiescence slowed 38.40 to 42.57 seconds. Another pair
filtered latest enrichment through current open finding IDs: reads fell 26 to
17 and quiescence slowed 39.95 to 45.02 seconds. Both retain exact lifecycle
oracles and raw failures; neither is adopted. Earlier lower-memory merge-join
experiments are in [the preceding report](large-corpus-query-costs.md).

## Configuration and replay

[Optional Helm values](clickhouse-catchup-values.yaml) reproduce the measured
database limits. Render them for review; this command deploys nothing:

```sh
helm template graph deploy/helm-chart/graph --set secret.create=false \
  -f docs/performance/clickhouse-catchup-values.yaml
```

The measured Docker cohort disables swap. Match that policy separately on the
target Kubernetes/node environment; Helm values alone cannot establish it.
Provide separate capacity for workers, Postgres, scanners, storage and replicas.

Use fresh output directories and run sequentially:

```sh
PERF_JOIN_EXPERIMENT=merge_cpu scripts/benchmark-large-joins.sh smoke /fresh/smoke
PERF_JOIN_EXPERIMENT=merge_cpu PERF_JOIN_RESOURCES=local32g \
  PERF_JOIN_MERGE_THREADS=16 PERF_JOIN_VARIANT=candidate \
  PERF_JOIN_READ_RATE=1 PERF_JOIN_MIXED_SECONDS=30 PERF_JOIN_PHASE=catchup \
  PERF_JOIN_INGEST=common_flush PERF_JOIN_WRITE_CHUNK=1000 \
  scripts/benchmark-large-joins.sh stress-cardinality /fresh/catchup
```

Use `local16g` and `baseline` for the control; repeat at least three fresh runs
per configuration for deployment qualification. `merge_cpu` enables merge-state
accounting; with 16 merge threads it retains production SQL/settings. Check the
separate correctness/terminal-accounting field, every failed operation, recovery
and original comparison failures. Never treat a nonzero runner exit as a pass.

These finite runs establish a usable query configuration for the declared load.
Sustained ingestion stability, larger read rates, wide/aged estates, native
architecture repetitions and the combined connector/correlation/graph/browser
pipeline remain unproven. No weighted full-profile coverage is awarded.
