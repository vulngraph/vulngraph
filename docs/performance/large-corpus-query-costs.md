# Large-corpus query capacity and memory tradeoffs

Date: 2026-11-28. Tracking: [#19](https://github.com/vulngraph/vulngraph/issues/19).
Workloads: `read.findings.summary`, `read.findings.clusters`, package-risk reads,
and concurrent finding/enrichment ingestion. This extends the
[earlier query rewrite](large-join-measurements.md). These are repository calls,
not the complete HTTP, connector, correlation and native graph workload.

**Retain the production query.** A tested merge-join preset reduces memory but
completes fewer reads during merge catch-up and costs more CPU after merges
settle. It remains a benchmark experiment. No production settings or deployment
budgets change, and no full-profile coverage is awarded.

## Dataset and resource boundaries

The fixture contains one million logical assets, five million findings,
25 million enrichment IDs and 100 million package memberships. Initial physical
storage contains 1,011,000 asset rows, 15 million finding rows, 75 million
enrichment rows and 123,266,003 edge rows. It includes three finding/enrichment
versions, orphan/missing enrichments, resolution and skewed memberships.
Independent expectations verify summary, cluster, package and write readback.
The small lifecycle replay covers enrichment-only updates, deletion, reappearance
and duplicate/out-of-order observations. Representative titles and resource sets
remain simpler than the full stress profile.

Both variants use the current production SQL. Earlier experiments used historical
aggregation SQL as their baseline; those results remain separately labeled.
The candidate changes broad queries to `full_sorting_merge`, a 128 MiB external
sort trigger with its ratio gate disabled, and 4,096-row input blocks. Selective
queries keep their defaults. The preceding unrestricted merge experiment failed
all six selective attempts; their short failed durations are not speedups.

The deployed comparison retains two ClickHouse CPUs, a 4 GiB container,
3 GiB server tracker, 2 GiB query limit and two query threads. The separate
`local16g` comparison uses eight CPUs, a 16 GiB container, 12 GiB server tracker
and 4 GiB query limit, retaining two query threads. Both pin ClickHouse
26.8.34.13 with the deployment XML. Go 1.26.11 runs on macOS ARM64; ClickHouse
runs on Linux ARM64. The host has 64 GiB RAM and Docker approximately 39 GiB.
These are not native results on the declared 128 GiB stress host.

**512 MiB is the preserved per-query comparison guard, not the enforced query
limit or a universal capacity requirement.** A correct query exceeding that
guard is distinct from an out-of-memory failure. Likewise, the older mixed
1,500/3,000 ms p95/p99 guard belongs to the target comparison. The stress
profile's 5,000/10,000 ms reference applies to different declared resources and
arrivals; meeting it here cannot accept that profile.

## Isolated queries

Three alternating pairs per operation use frozen physical rows and identical
limits. All 27 outputs match in the final preset experiment. MB is decimal.

| Broad query | Production / preset median | Production / preset peak query memory |
| --- | ---: | ---: |
| Summary | 3.915 / 4.003 s | 880.22 / 349.98 MB |
| Clusters | 4.099 / 3.668 s | 1,098.21 / 471.95 MB |

The preset passes the 512 MiB guard in these isolated samples. That alone does
not establish a useful concurrent-workload improvement. Earlier spill and merge
variants, their failures, plans, processing counters and sort IO are retained in
the [compact evidence](results/large-corpus-queries-2026-11-28.json).

## Concurrent ingestion and merge phase

Each fresh-store run offers one alternating summary/cluster read per second for
30 seconds, 200 distinct finding observations per second and a package-risk read
every five seconds. Both arms use the same five-second collection window and
1,000-row repository calls; native enrichment batches remain capped at 500.
Eight read workers share eight ClickHouse slots. Read deadlines remain ten
seconds after admission. Verified ingestion latency includes collection and
readback. Summary/cluster fields stay invariant during these writes; this does
not prove atomic publication across tables.

| Local16g phase | Production reads | Preset reads | Ingestion windows, each arm |
| --- | ---: | ---: | ---: |
| Catch-up, three alternating pairs | 69 / 90 | 52 / 90 | 18 / 18 |
| Settled, one diagnostic pair | 30 / 30 | 30 / 30 | 6 / 6 |

Catch-up starts arrivals as normal merges resume. Both variants consume almost
all eight CPUs. Failed reads hit deadlines; retained SQL cancellation records
are not memory exceptions. Production ClickHouse cgroup peaks are
15.06–15.83 GB versus 8.07–8.28 GB for the preset, with no observed swap. The
preset's lower memory accompanies fewer successful reads. All package reads and
ingestion windows pass. Successful-only tails, failed attempts and admission
wait are reported separately; failed requests are not excluded from acceptance.

The settled control waits for five stable part/row/byte samples and zero active
normal merges, without `OPTIMIZE FINAL`. It does not imply full compaction or
identical physical layouts: enrichment starts with three versus four parts and
26.65 versus 27.76 million physical rows. Both arms retain the same logical
outputs. Production read p95/p99 is 1.579/1.614 seconds; the preset is
2.220/2.370 seconds. Whole ClickHouse CPU is 97.5 versus 121.0 core-seconds over
approximately 30 seconds. Verified ingestion p95 is 5.687 versus 5.842 seconds.
ClickHouse cgroup peaks are 8.28 versus 5.50 GB. One pair is diagnostic evidence,
not repeated capacity acceptance. This phase difference includes both merge
competition and changing physical read work; it does not isolate either alone.

Cgroup memory includes file cache. Process RSS and swap are retained separately;
these ClickHouse figures do not represent the entire application footprint.
Query `read_bytes` describes logical scan work, not physical disk traffic.
Resource sampling spans arrival start through tagged server-query drain. IO is
retained per device rather than summed across storage layers.

## Replay and remaining work

```sh
PERF_JOIN_EXPERIMENT=merge_join_blocks scripts/benchmark-large-joins.sh smoke /fresh/smoke
PERF_JOIN_EXPERIMENT=merge_join_blocks scripts/benchmark-large-joins.sh stress-cardinality /fresh/isolated
PERF_JOIN_EXPERIMENT=merge_join_blocks PERF_JOIN_RESOURCES=local16g \
  PERF_JOIN_VARIANT=baseline PERF_JOIN_READ_RATE=1 PERF_JOIN_MIXED_SECONDS=30 \
  PERF_JOIN_PHASE=catchup PERF_JOIN_INGEST=common_flush PERF_JOIN_WRITE_CHUNK=1000 \
  scripts/benchmark-large-joins.sh stress-cardinality /fresh/mixed
```

Use fresh paths, alternate `baseline`/`candidate`, and set `PERF_JOIN_PHASE=settled`
for the control. Expected comparison-guard failures still return a failing test;
the separate correctness/terminal-accounting field does not suppress them.
Every successful mixed run must retain the exact terminal query count even when
a cost guard fails. Source patches, report hashes, effective settings, plans,
raw failures and resource samples are retained with the evidence.

No preset is promoted. Indexed Postgres is an outstanding same-output control,
not a selected replacement. Newer ClickHouse cohorts, real HTTP/browser traffic,
the complete five-million-finding/100-million-membership concurrent pipeline,
native stress hardware, aging and the 24-hour soak remain open.
