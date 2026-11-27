# Inventory and dashboard query measurements

Date: 2026-11-27. Tracking: [#19](https://github.com/vulngraph/vulngraph/issues/19).

**Decision: keep production inventory SQL and query settings unchanged.** The
key-selection/hydration rewrite increased work. Limiting List to two query threads
and 512-row blocks reduced individual-query memory but worsened concurrent read
tails without a consistent whole-server memory reduction. Both experiments remain
opt-in test fixtures. No deployment-profile coverage is awarded.

## Matched concurrent reads and ingestion

Three pairs used fresh isolated databases, alternating baseline/candidate order,
100,000 inventory rows with 16 KiB metadata, and 30 seconds of arrivals: 20 reads/s
and five 100-row `IngestAssets` calls/s. Eight reader workers share the application's
four-query semaphore. Writes preserve first-observation time, create versions and
allow merges; their low-ranked resources leave the selected page stable.

All six runs completed exactly 600 reads and 150 ingestion batches, verified every
page and the final persisted versions, and logged no query errors. Each ingestion
call performs one history lookup and three native inserts under the existing
conservative write-size bound. A first smoke incorrectly expected one insert; its
accounting failure is retained separately, and the corrected smoke passed.

| Pair | Read p95 ms, baseline / candidate | Read p99 ms, baseline / candidate | Sampled whole-CH RSS max GB, baseline / candidate |
| --- | ---: | ---: | ---: |
| 1 | 42.640 / 51.532 | 49.829 / 60.897 | 3.490 / 3.442 |
| 2 | 43.011 / 49.429 | 49.546 / 63.803 | 2.864 / 3.171 |
| 3 | 43.625 / 52.404 | 47.814 / 62.979 | 1.968 / 2.632 |

Both variants sustained approximately 20 reads/s and 500 ingested rows/s. Write
p99 ranged 29.46–32.82 ms for baseline and 30.68–34.49 ms for candidate. Harness
admission p99 remained 1.08–1.17 ms. Query CPU totals were 28.63–29.24 seconds for
baseline and 28.23–30.01 seconds for candidate. These results do not establish a
capacity improvement or justify changing the default.

The retained source patches include the evaluated production-setting candidate.
After this result, those exact settings moved into an opt-in test helper and the
production method was restored. This relocation needs a focused replay; it does
not turn the candidate's old measurements into a production-default result.

[Per-run metrics and evidence hashes](results/inventory-mixed-2026-11-27.json)
retain response/call/admission tails, write progress, query work and sampled RSS.
Raw `mixed-{1,2,3}-{baseline,candidate}/` artifacts also retain timestamps, server
samples, container stats, environment, exact source patch and hashes. These are
repository/service calls, not HTTP or River queues. Admission measures arrival to
worker start; internal semaphore/pool wait remains included in call latency rather
than separately measured. RSS is sampled once per second, not an exact peak.

## Individual-query evidence

Inventory fixtures cover all/provider/type/region/account/search/exposure/min-score
filters, two cursor pages and three interleaved repeats. Exact fields match the
retained baseline SQL; independent IDs, metadata and totals are also checked.

The 10k key-selection/argMax-hydration experiment reads 6,950,929,923 cumulative
bytes versus baseline 6,928,932,765, with peak query memory 23,892,229 versus
22,964,978 bytes and cohort median 30.59 versus 27.74 ms. EXPLAIN shows existing
lazy materialization after LIMIT. The rewrite fails its predeclared 25% memory and
read-byte improvement target and remains rejected.

The original 100k fixture fails its fixed memory ceiling: 85,297,928 peak bytes
versus 84,754,432 allowed on the first ordinary page. The ceiling was not raised.
Two threads alone pass fresh 100k but fail a three-version 10k search cursor page
at 39,209,438 bytes versus 38,674,432 allowed. Adding 512-row read blocks passes
both matched cohorts:

| Fixture | Max query bytes, baseline / candidate | Cohort median ms, baseline / candidate | Budget violations, baseline / candidate |
| --- | ---: | ---: | ---: |
| 100k fresh | 89,917,490 / 50,009,480 | 37.46 / 46.28 | 33 / 0 |
| 10k, three versions | 46,493,926 / 36,792,983 | 29.94 / 30.88 | 2 / 0 |

Read volume remains approximately unchanged. This individual-query tradeoff does
not override the concurrent result above. Production remains uncapped; the known
large-fixture memory failure stays open. `PERF_QUERY_EXPERIMENT=buffers` explicitly
selects the retained experiment; `keys` selects the rejected SQL rewrite.

The final scheduled-cohort replay uses **2 CPUs/3 GiB**, 100k rows and three
versions. All 99 samples pass unchanged budgets: baseline/candidate peak query
memory is 64,776,674/69,322,633 bytes and cohort median is 90.04/96.65 ms. Both
already use two threads on this server; the experiment does not improve this
cohort either. This differs from the 4-CPU cohorts above and is not a portable
timing comparison. The test explicitly records the effective server default when
query-log Settings omits an unchanged value. Report SHA256:
`ac8352543023faef59b607881a8dd46a89e472e3e141b16181f360bf9706be71`
(`final-versioned-target-v2/inventory.json`).

At 100k findings and 1m enrichment rows, all 27 dashboard samples pass budgets,
baseline parity and independently calculated summary/risk expectations. Risk,
unfiltered summary and clusters have median 32.14/36.17/40.42 ms and peak query
memory 58,397,981/64,862,031/106,008,054 bytes. Filtered summary/clusters peak below
4.8 MB. Larger joins with versions, skew, fan-out and concurrent writes were unmeasured
at this milestone; the [large-join continuation](large-join-measurements.md) records
subsequent evidence. These figures do not compare ClickHouse with Postgres.

## Reproduction, retention and limitations

Native macOS ARM64 Go 1.26.11; isolated Linux ARM64 ClickHouse 26.8.47.5 with
4 CPUs/8 GiB, Postgres with 1 CPU/512 MiB, GOMAXPROCS 4. The shared workstation
and unrelated containers make timings descriptive. Metadata repeats per-row SHA
digests and is deliberately compressible; query-log read bytes describe
uncompressed work, not physical storage IO. Seeded versions pause merges and do
not establish elapsed aging. The mixed probe enables merges but is not a soak.

These containers use benchmark defaults, not the deployed Compose/Helm XML.
The deployment pin is also different (26.8-alpine digest `31d60795…` versus this
benchmark's 26.8.47.5 digest `13f4949b…`). Deployed thread/server-memory/cache caps
and newer LTS/stable versions require separate matched cohorts before capacity
or upgrade claims. Prior results are not reclassified as deployment evidence.

```sh
scripts/benchmark-queries.sh smoke /fresh/query-smoke
PERF_QUERY_EXPERIMENT=buffers PERF_QUERY_VERSIONS=3 scripts/benchmark-queries.sh target /fresh/versioned
PERF_QUERY_TESTS='^TestInventoryConcurrentCosts$' PERF_QUERY_MIXED_SECONDS=30 PERF_QUERY_VARIANT=baseline scripts/benchmark-queries.sh target /fresh/mixed-baseline
PERF_QUERY_TESTS='^TestInventoryConcurrentCosts$' PERF_QUERY_MIXED_SECONDS=30 PERF_QUERY_VARIANT=candidate scripts/benchmark-queries.sh target /fresh/mixed-candidate
```

Use the same declared resource limits and three matched repetitions; choose new
output paths each time. Native CI uploads future raw reports. Initial raw reports
remain outside the repository under `performance-assurance-evidence/`:

- `inventory-small-candidate/inventory.json`: SHA256 `5456c7c600206470b538e022949a0a6819e1d9e95d0effee51675de192f79abd`.
- `inventory-versioned-blocks/inventory.json`: `0b92ff043892ff7048b4fa59905584db6ca097f2d84fd0fdf4223da278c7272b`.
- `inventory-target-blocks/inventory.json`: `28e24ac79f22ace443b42c91655029e901f306837c6e73b93a4c96373da25a35`.
- `queries-target/` retains the original 100k failure and dashboard success.
- `guards-smoke/` retains the real wide-aggregation mutation: 339,783,296 peak
  query bytes, correctly rejected by the fixed memory guard.

Fixture-preparation and failed candidates remain retained and receive no credit.
Native repetitions, full profile workloads, HTTP/browser traffic, aged storage,
recovery and independent acceptance replay remain open.
