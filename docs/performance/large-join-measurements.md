# Large current-state joins

Date: 2026-11-27. Tracking: [#19](https://github.com/vulngraph/vulngraph/issues/19).
Affected families: `read.findings.summary`, `read.findings.clusters`, and their
`http.findings` / `browser.findings` consumers. This measures repository calls;
it does not establish HTTP or browser performance.

The proposed change reads full-table latest replacements directly for summary
and cluster queries, avoiding a per-ID `argMax` state for every projected column.
Source-filtered queries retain their existing aggregation and index pruning.
There is no schema, global setting, count approximation, or enrichment-freshness
change. Historical SQL remains in the benchmark for matched comparisons.

**The focused rewrite improves the baseline; the complete target profile still
fails.** Catch-up latency, five-million-finding capacity, native large repetitions,
and the remaining assurance scenarios stay open. No weighted coverage is awarded.

## Query comparison

The large fixture has one million logical findings, five million enrichments
(including unmatched IDs), three versions of each, 860,000 logical assets and
21,950,000 logical edges including 20 million package memberships. Actual inventory
storage contains 870,000 asset rows and 26,162,611 edge rows. Findings retain three
million rows and enrichment retains 15 million during these measurements.

The independent production-path replay uses three interleaved baseline/candidate
samples per operation in the same isolated
database and limits. All 24 finding outputs and three package-risk outputs match
independent Go expectations. Query memory is the server's tracked peak; MB below
means decimal megabytes.

| Broad query | Baseline median / candidate median | Baseline peak / candidate peak memory |
| --- | ---: | ---: |
| Summary | 662.32 / 505.34 ms | 947.63 / 299.77 MB |
| Clusters | 804.44 / 502.53 ms | 1,400.97 / 360.71 MB |

Both candidate queries pass the unchanged 512 MiB cost guard. The baseline fails
it in all six broad samples. Source-filtered paths remain unchanged. The initial small
prototype also records its timings: summary median 4.73 / 5.13 ms and clusters
5.29 / 4.06 ms; the change is not a universal latency win at every size.

The fixture resolves every seventeenth finding, omits enrichment for every
nineteenth finding, changes ownership across versions, and includes stale and
high-fan-out package relationships. A separate small oracle exercises missing and
orphan enrichment, enrichment-only changes, resolution, producer updates,
reappearance, out-of-order/duplicate replay and removed enrichment. Constant
representative titles and small resource sets per check leave wider projected
payloads and high-cardinality resource-count behavior as separate gaps.

## Concurrent ingestion and merge phase

Each 30-second run offers one broad read per second, 200 distinct finding
observations per second, and package-risk work every five seconds. Both ingestion
arms accumulate the same five-second window, then use either 100-row or 1,000-row
repository calls. Enrichment already caps native batches at 500 rows. Every window
is read back, including observation timestamps at schema precision: seconds for
findings and milliseconds for enrichment.

Three matched pairs per phase compare ingestion chunk size with unchanged SQL.
The settled phase observes five stable part/row snapshots with no active normal
merge; it does not force `OPTIMIZE FINAL` or imply every version has compacted.
Actual part and physical-row counts are retained. Catch-up starts arrivals as
merges resume. All slow starts stay in the reported percentiles.

| Query / merge phase | Verified reads | Verified ingestion windows |
| --- | ---: | ---: |
| Original, settled, 100-row calls | 90 / 90 | 18 / 18 |
| Original, settled, 1,000-row calls | 90 / 90 | 18 / 18 |
| Original, catch-up, 100-row calls | 26 / 90 | 15 / 18 |
| Original, catch-up, 1,000-row calls | 43 / 90 | 16 / 18 |
| Latest-row rewrite, catch-up, 1,000-row calls | 90 / 90 | 18 / 18 |

Larger ingestion calls reduce INSERT records from 120 to 18 per complete run, but
do not consistently improve settled latency or freshness. Original settled
queries still peak near 810 MB, above their memory guard. Catch-up produces server
memory errors and approximately ten-second read tails in both batching arms.

The rewrite's three catch-up runs return all 126 operations correctly, with 198
terminal query records and no query errors. Their combined read p95 values are
2,744.748 / 2,578.563 / 2,539.953 ms; p99 values are
2,746.874 / 2,579.571 / 2,638.626 ms. The 1,500 ms p95 target **fails**; the 3,000 ms
p99 target passes. Query memory passes the 512 MiB guard. Source-time-to-verified
write p95 includes the common collection window; it is not just INSERT duration.

These are direct repository arrivals, not HTTP traffic or River queue measurements.
Admission wait measures scheduled arrival to worker start; internal semaphore,
pool and transport waits remain combined with operation time. The newest harness
drains only its tagged requests after caller deadlines before flushing terminal
telemetry; older failed mixed runs retain an explicit terminal-record gap.

## Larger cardinality is not a capacity pass

The stress-cardinality fixture verifies one million logical assets, five million
findings, 25 million enrichments and 100 million memberships. Storage contains
1,011,000 asset rows, 123,266,003 edge rows, 15 million finding rows and 75 million
enrichment rows. At the same two-CPU / 3 GiB server limits, all 27 samples complete
accounting, with eight operation failures retained.

Original broad summary and cluster queries succeed in zero of three attempts
each. The rewrite succeeds in two of three each; one attempt of each query still
hits server memory limits. Successful-query medians are 3,808.89 / 4,135.48 ms and
peaks are 880.66 / 1,098.38 MB respectively. Those successful attempts still exceed
the fixed 512 MiB guard. Failed timings are never counted as fast successes.
Selective queries pass all 12 samples. The package-risk rollup passes all three
exact-output samples at a 1,191.94 ms median and 50.32 MB peak query memory.

## Reproduction and evidence limits

The runner pins deployed ClickHouse 26.8-alpine digest `31d60795…` (observed
26.8.34.13) and renders the deployed Helm XML. The deployed cohort gives ClickHouse
two CPUs, a 4 GiB container, 3 GiB server tracker, 2 GiB query cap and two query
threads, with deployed cache caps. A separate `local16g` cohort explicitly changes
server CPU/RAM and query cap while retaining query thread settings. It is a capacity
comparison, not a replacement for the fixed-budget result.

The application runs Go 1.26.11 on macOS ARM64 and the database on Linux ARM64.
The host has 64 GiB RAM; Docker has approximately 39 GiB. Other local containers
remain running; these isolated CPU/RAM limits do not make timings portable. This is not acceptance
of the declared 128 GiB native stress host. The runner retains exact image IDs,
rendered XML, effective settings, source patch/hash, query plans, query log costs,
process RSS, cgroup CPU/IO, container stats, part counts and failures. Process
resources are sampled at approximately 250 ms, so peaks are sampled bounds.

```sh
PERF_JOIN_EXPERIMENT=latest_rows scripts/benchmark-large-joins.sh smoke /fresh/smoke
PERF_JOIN_EXPERIMENT=latest_rows scripts/benchmark-large-joins.sh target /fresh/target
PERF_JOIN_EXPERIMENT=latest_rows scripts/benchmark-large-joins.sh large /fresh/large
PERF_JOIN_EXPERIMENT=latest_rows scripts/benchmark-large-joins.sh stress-cardinality /fresh/stress
PERF_JOIN_EXPERIMENT=latest_rows PERF_JOIN_VARIANT=candidate PERF_JOIN_READ_RATE=1 \
  PERF_JOIN_MIXED_SECONDS=30 PERF_JOIN_PHASE=catchup PERF_JOIN_INGEST=common_flush \
  PERF_JOIN_WRITE_CHUNK=1000 scripts/benchmark-large-joins.sh large /fresh/mixed
```

Use fresh output paths and at least three repetitions. `PERF_JOIN_VARIANT=baseline`
selects historical SQL in mixed tests; `PERF_JOIN_PHASE=settled` records normal
merge quiescence before arrivals. The rejected `enrichment_keys`, `ordered` and
`ordered_blocks` experiments remain replayable with their original SQL. They are
not production settings.

Native CI runs small lifecycle checks and the 100,000-finding cost fixture.
At target cardinality, the candidate must consume at most 75% of its matched
baseline's query memory as well as pass absolute budgets and exact outputs.
The 1,000-finding fixture is too sensitive to startup allocation noise for that
relative guard; its failed guard experiment is retained. No wall-clock
performance threshold gates shared CI runners.

[Compact measurements and source/report hashes](results/large-joins-2026-11-27.json)
retain individual successful/failing sample counts and mixed-run totals. Both new
guards were verified by deliberate regressions: restoring the old query shape
fails the target memory comparison; removing latest-enrichment deduplication
fails the independent lifecycle oracle.

Raw artifacts remain retained outside the repository with the established
performance-assurance evidence: `joins-latest-rows-{smoke,large,stress-deployed}`,
`joins-batch-v4-*`, `joins-latest-mixed-catchup-r{1,2,3}-candidate`, plus rejected
keyset/ordering, aborted/setup and cleanup-failure runs. The independent production replay is `joins-production-latest-large`; gate
artifacts are recorded separately. Newer LTS/stable comparisons,
Postgres control, genuine aging, HTTP/browser load, mixed graph publication,
overload recovery and the coordinated 24-hour soak remain unmeasured here.
