# Critical graph-edge source reads

The critical-edge source query uses existing storage order to release aggregation
state incrementally. A query-local 4 MiB aggregation block bound is necessary:
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
and resource limits; the baseline removes only the two query-local settings.

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

## Remaining scope

The stable workload is `graph.refresh`; PERF-05/11 still require integrated native
builds, concurrent ingestion, freshness, recovery and whole-process resource
budgets. This change does not enable staged correlation, change the 600,000
relevant-asset refusal or establish full-profile coverage. Asset-source memory,
Go allocation/GC cost and production periodic enrichment coverage remain open.
