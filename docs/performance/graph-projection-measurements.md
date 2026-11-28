# Project graph asset fields before aggregation and transport

`ListAllForSync` now projects the graph's requested metadata keys and omitted
Tags before latest-row aggregation and native-protocol encoding. Previously the
Go decoder discarded these fields after ClickHouse and the driver had already
allocated their wide strings. The zero projection still returns all fields.
The existing current-version selection, risk overlay, liveness predicates,
5-million-row ceiling and output order are preserved. Graph schema and loaded
values are unchanged.

The expression preserves raw JSON string values and duplicate-key order.
Malformed JSON and maps containing non-string values fall back to the original
JSON, preserving the Go decoder's existing behavior. The optimization therefore
does not impose a universal bound on arbitrary metadata. Projection uses bound
key parameters. Ordered aggregation blocks are capped at 4 MiB only for these
projected graph-source queries.

## Repeated measurements

[Machine-readable results](graph-projection-results.json) retain both benefits
and costs. Tests use deployed ClickHouse 26.8.34.13 and deployment XML, Linux
ARM64 containers on a local ARM64 host, Go 1.26.11, two database CPUs, a 3 GiB
server cap and a 2 GiB per-query cap. The worker has one CPU and 4 GiB RAM plus
4 GiB swap allowance. The actual production governor is applied and read back:
GOGC 60, Go memory limit 1,792 MiB and GOMAXPROCS 1. The governor reserves 1,280
MiB for native memory; these source probes do not run native COPY or BFS.

Fixtures contain two versions of every asset, with 512-byte discarded metadata
on 90% of rows and 16-KiB discarded metadata on 10%, plus retained quoted and
Unicode strings. Payloads are synthetic and highly compressible. Bulk fixture
setup is outside measurement; merges are stopped so physical versions stay
matched. Every returned field is compared against independently constructed
expected values. Each size has three alternating baseline/candidate samples.
MB and GB in the table are decimal; memory ceilings use MiB.

| Logical assets | Physical rows | Max query memory, old → new | Median Go allocations, old → new | Median source seconds, old → new |
|---|---|---|---|---|
| 5,000 | 10,000 | 50.64 → 46.33 MB | 96.13 → 13.18 MB | 0.0368 → 0.0716 |
| 100,000 | 200,000 | 258.81 → 60.37 MB | 1.874 → 0.300 GB | 0.437 → 1.008 |
| 1,000,000 | 2,000,000 | 1,632.61 → 310.92 MB | 18.909 → 2.937 GB | 7.230 → 9.621 |

All 18 operations return exact results without query errors. Isolated source
latency regresses at each size. This is a memory/allocation improvement, not a
claim that every read becomes faster.

## Matched concurrent reads and ingestion

Three additional matched pairs use one million logical graph assets plus one
security-group sentinel, two million critical-edge versions, four inventory
reads/second and two 100-row ingestion batches/second for 30 seconds. Source
asset and edge reads run concurrently and their result slices remain resident
until the workload drains. All six runs pass exact asset, edge, inventory and
final ingestion readback: 720 reads, 360 batches and no SQL exceptions. The
production query and parameters are asserted identical to this measured shape.

| Median across three runs | Original | Projected |
|---|---:|---:|
| Source pair elapsed | 12.300 s | 10.755 s |
| Inventory call p95 | 231.6 ms | 106.6 ms |
| Inventory arrival-to-completion p99 | 370.1 ms | 216.2 ms |
| Ingest batch arrival-to-completion p99 | 435.6 ms | 113.5 ms |
| Whole-worker allocated bytes | 20.711 GB | 4.739 GB |
| Aligned combined container resident peak | 4.870 GB | 3.021 GB |
| Worker CPU | 12.13 core-seconds | 3.91 core-seconds |
| ClickHouse CPU | 19.54 core-seconds | 26.63 core-seconds |

ClickHouse CPU increases about 36% as it projects the fields. These are fixed
offered rates, not a saturation or maximum-throughput measurement. Combined
memory sums contemporaneous worker, whole ClickHouse and whole Postgres cgroup
samples, including file cache; maximum alignment span is 257 ms. No swap was
observed in these sampled workload windows, but swap was enabled. This does
not establish a no-swap deployment size or whole-host physical RAM requirement.
CPU and block IO deltas exclude preparation and post-run verification; logical
query read bytes are distinct from physical disk traffic.

## Regression checks and remaining limits

`TestGraphSourceProjectionSemantics` uses the actual graph metadata registry
and all four projection modes, including latest field removal, derived risk
and clearing, absent/deleted/reappeared base assets, package and dead-pod
exclusion, late risk replay, and parity after merges. Twenty-five JSON cases
execute the production expression, including duplicate keys, escapes, invalid
UTF-8, nulls, nested values and malformed input.

Required native AMD64/ARM64 CI runs the lifecycle replay and the three-pair
100,000-asset cost guard. Its 128-MiB query ceiling is stricter than the existing
512-MiB million-asset comparison ceiling. The recorded unprojected 100,000-row
control exceeds 128 MiB; the projected reader remains below it. Shared-runner
wall-clock latency is recorded, not gated. Startup checks reject an unapplied
memory policy, default memory/GC limits or mismatched parallelism.

Reproduce with `scripts/benchmark-connector-envelope.sh target OUTPUT`,
`PERF_ENVELOPE_PACKAGE=./internal/app/asset`,
`PERF_ENVELOPE_TEST=^TestGraphSourceWireProjectionCosts$` and a sequential Linux
Go cache in `PERF_LINUX_GO_CACHE`. Use `smoke` or `million` for other sizes.
`TestGraphSourceWireProjectionMixed` additionally takes
`PERF_GRAPH_WIRE_VARIANT=baseline|projected` and `PERF_GRAPH_WIRE_SECONDS=30`;
each variant needs a fresh isolated output/store. Use a separate smoke run for
`TestGraphSourceProjectionSemantics`.

Earlier experiments after aggregation increased database memory; their results
are retained. A default-Go-runtime mixed matrix was stopped and classified as
diagnostic when its missing production governor was identified. The governed
pairs above supersede it for runtime-policy comparisons. Initial bulk-fixture
preparation also hit part-count backpressure; that failed preparation produced
no query samples. Neither failure is omitted from the evidence history.

These fresh source fixtures do not cover SDK collection, native graph builds,
River queues, aged mixed workloads, sustained overload, multi-worker admission
or a 24-hour soak. Full-profile workload coverage remains zero. The production
600,000 relevant-asset correlation refusal is unchanged.
