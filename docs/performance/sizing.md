# Sizing and benchmark evidence

Start with estate volume and freshness requirements. **There is no validated
whole-estate sizing guarantee yet.** The measured large-join recommendation is
16 CPUs and a 32-GiB ClickHouse container for the specific workload below;
workers, Postgres, scanners and storage need separate budgets. Quickstart memory
is a bootstrap requirement, not a production capacity claim.

## Describe the estate

Record these values before choosing a size. Connector count alone is insufficient:
one scope can contain more resources than many quiet scopes combined.

| Dimension | Record |
| --- | --- |
| Collection scopes | Accounts/projects/subscriptions, regions, clusters, repository organizations/installations; enabled services and permissions |
| Inventory | Current assets by type, largest scope, p50/p95/p99 metadata bytes and maximum payload |
| Relationships | Traversable core edges, package memberships, shared-image/package concentration and maximum fanout |
| Findings | Current/resolved findings, enrichment IDs including orphans, versions per key and retained history |
| Change load | Observations per second, full-sync cadence, unchanged/changed/deletion fractions, bursts and provider throttling |
| Parallel work | Active collectors per process, replicas, overlapping enrich/correlate/graph builds and scanners |
| User demand | Concurrent sessions, expensive views and read rate, p95/p99 and source-to-visible freshness requirements |
| Storage | Physical rows/parts/bytes, growth, retention, sustained IO quota and merge/recovery time |

Use upper-tail scope sizes and payloads, not just averages. Record configured
scopes separately from simultaneously active collectors. Match enabled coverage:
a benchmark omitting provider families or checks is a different workload.

## What is measured

| Estate/data shape | Measured configuration | Evidence and practical recommendation |
| --- | --- | --- |
| Small smoke and 100k-finding query checks | Small isolated fixtures on native AMD64/ARM64 CI; resource limits recorded by the runner | Correctness/cost guards, not sustained estate capacity. Start with smoke before larger tests; [benchmark procedure](../pipeline-benchmarks.md). |
| 860k assets, 1m findings, 5m enrichment IDs, 20m package memberships | ClickHouse 2 CPUs, 4-GiB container / 3-GiB server cap | Three rewrite catch-up runs return 90/90 reads and 18/18 update windows; read p95 2.540–2.745 s misses the 1.5-s reference. Use as a comparison, not a low-latency guarantee; [proof](large-join-measurements.md). |
| 1m assets, 5m findings, 25m enrichment IDs, 100m memberships; settled parts | ClickHouse 8 CPUs, 16-GiB container / 12-GiB server cap | One diagnostic run returns 30/30 reads, p95 1.579 s. Catch-up fails under the same limits, so this is insufficient evidence for sustained ingestion; [proof](large-corpus-query-costs.md). |
| Same huge corpus during merge catch-up, 1 dashboard read/s + 200 observations/s | ClickHouse 16 CPUs, 32-GiB container / 24-GiB server cap, no swap | **Measured starting configuration for this database workload.** Three runs: 90/90 reads, 18/18 updates, 18/18 package reads, no errors; p95 3.814–4.222 s. [Proof and limits](catchup-capacity.md), [optional Helm values](clickhouse-catchup-values.yaml). |
| Complete estate with collection, enrichment, correlation, native graph, scans and UI together | No accepted size | Do not infer this from database-only rows. The [bounded production correlator](../specs/bounded-correlation.md) completes one million-asset mixed/native cohort with an 8.635-GB resident-plus-swap peak. Its byte limits replace the default row-count refusal; this is not a no-swap or full-estate sizing guarantee. Complete score freshness, aged recovery and 24-hour acceptance remain open. |

These are workload-specific observations, not monotonically increasing product
tiers. A smaller estate with larger payloads, more history, more frequent writes
or higher read concurrency may cost more. CPU/RAM changes in the successful
huge-corpus cohort were joint changes, not proof of a minimum for either.

## Planning budgets to validate

The following existing [assurance profiles](profiles.json) are **unvalidated
engineering targets**, not measured purchasing recommendations. Use them to
budget an isolated acceptance test; do not present them as supported estate sizes.

| Target | Assets / findings / memberships | Host CPU / RAM / SSD | App CPU / RAM | ClickHouse CPU / RAM | Postgres CPU / RAM | Scanner CPU / RAM |
| --- | --- | --- | --- | --- | --- | --- |
| Small | 10k / 10k / 200k | 16 / 32 GiB / 100 GiB | 4 / 4 GiB | 4 / 8 GiB | 1 / 2 GiB | 2 / 4 GiB |
| Target | 100k / 1m / 20m | 32 / 64 GiB / 500 GiB | 8 / 16 GiB | 8 / 24 GiB | 2 / 4 GiB | 4 / 8 GiB |
| Stress | 1m / 5m / 100m | 64 / 128 GiB / 2,000 GiB | 16 / 32 GiB | 16 / 48 GiB | 4 / 8 GiB | 8 / 16 GiB |

The profile file also specifies history, skew, payloads, arrivals and IO quotas.
Host totals include headroom; container figures are separate limits, not observed
peaks. Storage capacities are test budgets, not measured retention sizing. Estimate
production disk from measured bytes/day × retained days, plus retained versions,
indexes, temporary spill, merge overlap, graph snapshots and backup policy; then
verify it under the intended retention/maintenance schedule.

## Benchmark before rollout

1. Run the [smoke and connector fixtures](../pipeline-benchmarks.md) on the intended
   architecture. They use synthetic local responses, not live API quota evidence.
2. Select the closest query fixture: `smoke` (1k findings), `target` (100k),
   `large` (1m) or `stress-cardinality` (5m). These runner names are not assurance
   profile acceptance. Run [catch-up and settled controls](catchup-capacity.md#configuration-and-replay)
   at identical arrivals, output semantics and resource limits. Retain at least
   three fresh runs per size, including failures and post-arrival merge debt.
3. Use the [graph pipeline fixtures](../pipeline-benchmarks.md) for actual native
   construction and traversal. Their package/core graph dimensions differ from
   the join fixture; record both. They do not by themselves exercise every queue.
4. Before a whole-estate claim, exercise the real concurrent queues and UI with
   declared provider sizes, wide/skewed data, aged versions, partial access,
   deletion/reappearance, overload/recovery and a 24-hour sustained interval.
   Current public component runners do not supply this complete acceptance test.

For each result, publish source/image/schema/config hashes; logical and physical
counts; scope/coverage and active concurrency; offered and completed work; errors,
p95/p99 including waits, source freshness and queue age; aligned Go/native/process
and container memory including swap/cache; CPU, disk IO, parts and recovery.
Verify persisted outputs independently, including every expected changed finding.
A completed job count does not prove fresh scores. Avoid summing independent peak
memories or treating logical ClickHouse read bytes as disk traffic.

Accept a size only against its declared latency/freshness/error budgets with
headroom and complete correctness. Upgrade the recommendation when source,
schemas, feature coverage, engine version, resources or workload materially
change; prior measurements then need applicability review or replay. All critical
workloads and at least 90% weighted coverage are still required for full assurance.
