# Critical graph-edge source reads

The critical-edge source query uses existing storage order to release aggregation
state incrementally, with a 4 MiB aggregation block target and 4,096-row input
blocks. The input-block comparison below extends the original measurements.
A query-local 4 MiB aggregation block bound was necessary:
enabling ordered aggregation with its default 50 MB block target increased the
100,000-edge fixture peak from 93.8 MB to 162.8 MB. That failed candidate is
retained. The bulk-edge query, all five grouping columns, latest property
selection, freshness predicate, security-group membership filter and uncapped
critical result remain unchanged.

## Reproducible query guard

`TestCriticalEdgeSourceBudget` exercises the actual repository decoder on two
unmerged versions per critical edge, changed properties, quoted/Unicode values,
an invalid security-group destination, an expired edge and a bulk edge. Each
operation must return exactly the expected complete result and exactly one
critical and one bulk terminal query-log record. EXPLAIN must show ordered
aggregation. Three alternating baseline/candidate repeats use identical data
and resource limits; the historical baseline removes the ordered-aggregation and
input-block settings. The following table retains the original comparison before
the input-block change.

The local cohort uses deployed ClickHouse 26.8.34.13 with deployment XML on
Linux ARM64, two database CPUs, a 3 GiB server cap and a 2 GiB query cap. The
worker has one CPU, 4 GiB RAM and an additional 4 GiB swap allowance. These are
query working-set results, not a no-swap or whole-host capacity claim. MB below
means decimal MB; guard budgets use MiB.

| Logical critical edges | Physical edge rows | Maximum query memory, old → new | Median operation including exact oracle, old → new |
|---|---|---|---|
| 5,000 | 10,003 | 8.62 → 9.44 MB | 12.6 → 16.2 ms |
| 100,000 | 200,003 | 91.91 → 65.53 MB | 150.3 → 160.4 ms |
| 1,000,000 | 2,000,003 | 1,082.02 → 88.22 MB | 1.477 → 1.402 s |

All 18 operations returned exact outputs. Read rows and logical read bytes are
unchanged within each size. The small fixture incurs extra memory and latency;
the 100,000-edge case also has a latency cost and narrow memory headroom. The
fixed critical-query ceilings are 64 MiB at 5,000/100,000 edges and 512 MiB at
one million. Timing on shared CI is informational, not a wall-clock gate.

## Concurrent source replay

Three additional production-reader replays on a retained million-asset fixture
return byte-identical sorted asset and edge fields to the historical control.
With an additional historical edge copy, the new critical-query peaks are
91.6–94.5 MB; all three source operations complete. The historical control's
maximum was 816.2 MB. Combined source median is 7.832 s versus 7.481 s, so this
is not a whole-loader latency improvement. The historical and current clones
scan 2,091,828 and 2,087,732 critical-input rows respectively: startup merges
changed physical work despite identical logical output. These separate replays
validate concurrent correctness and budget compliance, not a perfectly matched
causal comparison. The alternating isolated guard above has equal read counts.

Source windows exclude oracle encoding, but its file cache and earlier Go
allocations can survive into later windows. No total-worker footprint reduction
is inferred. There is no concurrent ingestion or native graph construction in
this replay.

## Reproduction and regression protection

Run `scripts/benchmark-connector-envelope.sh target OUTPUT` with
`PERF_ENVELOPE_PACKAGE=./internal/app/asset`,
`PERF_ENVELOPE_TEST=^TestCriticalEdgeSourceBudget$` and an isolated or sequentially
shared Linux Go cache in `PERF_LINUX_GO_CACHE`. `smoke` and `million` select the
other sizes. The runner records source hashes, configuration, limits and query
telemetry in a fresh artifact directory. Required native AMD64/ARM64 PR jobs run
the 100,000-edge guard; million-edge measurements remain manual.

Restoring the old query exceeds the same memory predicate in every 100,000-edge
and million-edge sample; the test explicitly requires that negative control.
The [compact local results](critical-edge-results.json) retain the artifact hashes.
The deployed upstream [ordered aggregation implementation](https://github.com/ClickHouse/ClickHouse/blob/v26.8.34.13-lts/src/Processors/Transforms/AggregatingInOrderTransform.cpp)
checks accumulated state at key boundaries; the block target does not bound all
query or process memory. No query memory ceiling is raised.

## Input-block comparison — 2026-11-28

The unchanged ordered query later exceeded the 64 MiB comparison guard in native
ARM64 CI: 70.14 MB in one sample, versus 41.87 and 60.09 MB in the other two.
All outputs were correct and there were no SQL exceptions. The original failure
is retained; it is not an out-of-memory or full-system capacity failure. The
4 MiB aggregation target does not also bound the rows buffered on its inputs.

A focused experiment limits only critical-query input blocks to 4,096 rows.
Three alternating pairs per fixture compare against the existing ordered query
with default input blocks, preserving the SQL fields, filters and exact outputs.

| Fixture | Existing / bounded peak query memory | Existing / bounded median whole read including oracle | Existing / bounded median critical-query CPU |
| --- | ---: | ---: | ---: |
| 100k critical edges, two versions | 95.49 / 32.78 MB | 169.98 / 174.42 ms | 119.36 / 108.87 ms |
| 1m critical edges, two versions | 101.87 / 43.44 MB | 1.692 / 1.564 s | 1.210 / 1.006 s |

The smaller fixture has a 2.6% elapsed-time cost. The million-edge fixture
improves both memory and elapsed time; the setting is not adopted merely to
make a fluctuating CI sample pass. Both retain the independent exact
property/type/freshness oracle through the actual repository decoder.

On a separate retained versioned clone, all six isolated queries return exactly
999,496 critical rows with byte-identical sorted properties. Existing versus
bounded query memory peaks are 70.07 / 32.25 MB; SQL medians are 449 / 382 ms,
and CPU medians are 0.652 / 0.581 seconds. The first existing query takes 975 ms
and remains included. Source merges are stopped for this comparison; it does
not include concurrent ingestion, asset loading, Go decoding or native graph
construction. The original seed is never started or modified.

The [input-block evidence](critical-edge-input-results.json) retains individual
samples, source/query/report hashes and the failed CI record. A wrapper setup
failure before any aged measurement is retained separately. The production
change applies the same input setting to the critical query only. The bulk query
and the 64/512 MiB guards remain unchanged, and the historical hash-query
negative control still must fail its original memory guard. Fresh production
replay and required native CI validate the committed setting before merge.

## Remaining scope

The stable workload is `graph.refresh`; PERF-05/11 still require integrated native
builds, concurrent ingestion, freshness, recovery and whole-process resource
budgets. This change does not enable staged correlation, change the 600,000
relevant-asset refusal or establish full-profile coverage. Asset-source memory,
Go allocation/GC cost and production periodic enrichment coverage remain open.
