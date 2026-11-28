# Performance assurance worklist

This is the tracking checklist for finding performance gaps across Vulngraph.
Use [pipeline-benchmarks.md](pipeline-benchmarks.md) for the existing harness and
measurement commands. This document tracks the work still needed to establish
broader coverage; its checkboxes do not represent completed benchmarks.

## Target and current position

The target is evidence-backed coverage of every critical workload and at least
90% of the weighted workload inventory for a declared deployment size. This is
an engineering coverage target, not a statistical claim that there is a 90%
probability of having no remaining performance problems.

Current accepted coverage under inventory `2026-11-27.1`: **0 / 1,090 (0%)**
for each small/target/stress native Linux AMD64/ARM64 combination; **0 / 113**
critical families accepted. The [versioned inventory and budgets](performance/README.md)
now establish the initial denominator and reconciliation guard. No prior result
yet satisfies every required scenario under those profiles. Existing synthetic coverage
includes representative connector collection, sync, storage, enrichment,
correlation, graph refresh and worker recovery. Those results apply to their
recorded scenarios, datasets and machines; they do not certify every endpoint,
connector service family or production workload.

To count a workload as covered, it must pass its correctness and performance
budgets across its required scenarios, with retained evidence. A unit test, code
review, bounded response size or benchmark script without results is insufficient.

Tracked implementation: [issue #19](https://github.com/vulngraph/vulngraph/issues/19)
and [implementation spec](specs/performance-assurance.md). PERF-01/02 now have an
executable inventory, mutation guards and fixed profiles. Acceptance/evidence
review remains open. [Initial PERF-03/04 query evidence](performance/query-measurements.md)
rejects a key-hydration rewrite on measured cost and retains the existing query;
larger/versioned/concurrent scenarios remain open. All 15 items remain visible.

## Coverage accounting

- Inventory workload families from HTTP/OpenAPI routes, MCP tools, frontend
  journeys, collector registrations and service families, scanners, feeds, River
  workers, scheduled maintenance, migrations and recovery paths. Reconcile the
  inventory against those registrations so less-used paths remain visible.
- A family groups operations that share a cost model. Separate materially
  different filters, joins, fallback paths or fan-out patterns. Do not inflate
  coverage by counting many cheap routes separately while grouping expensive
  behaviour into one item.
- Assign weights before measurement: **5 critical** (availability, ingestion,
  freshness or recovery), **3 significant** (frequent user work or substantial
  resource consumption), **1 ordinary**. Record the rationale and owner.
- Coverage is `100 × sum(weights of covered families) / sum(all in-scope weights)`.
  Partial, failing, stale and unmeasured families contribute zero to the numerator.
  Use the same granularity and denominator across comparisons. New functionality
  enters the inventory before making a new coverage claim.
- Declare required dataset sizes, scenarios and hardware for each family. Report
  coverage separately for each deployment profile and supported architecture;
  do not average a missing ARM64 result into a passing AMD64 result.
- Every critical family must pass, even if the weighted total already exceeds
  90%. Keep the remaining gap visible with impact, owner and next action. Opt-in
  scanners and other shipped features stay visible as separate scope entries.

## Work to complete

All items below are open. The code references identify investigation candidates,
not newly demonstrated production regressions. Each item needs an owner, recorded
budgets and evidence before it can be checked off.

| ID | Priority | Work | Completion evidence |
| --- | --- | --- | --- |
| PERF-01 | First | Build the coverage inventory and reconcile it with all registered routes, tools, collectors and workers. | Every workload family has an owner, risk weight, scenarios and status; missing registrations are reported. |
| PERF-02 | First | Define small, target and stress deployment profiles and budgets before comparing implementations. | Profiles specify resource counts, payload distributions, change rates, request/job arrival rates, storage age, CPU/memory/storage limits and acceptable latency, freshness and recovery time. |
| PERF-03 | High | Measure general inventory listing: filtered `assets FINAL`, exposed filters, search, risk sorting, pagination and wide metadata. Evaluate selecting page IDs before hydrating full rows where warranted. | Exact result/cursor parity; rows and bytes read, query memory and p95/p99 response time across sizes and concurrent ingest. Start at [`asset/repo.go`](../internal/app/asset/repo.go). |
| PERF-04 | High | Measure findings summaries, clusters and facets, plus identity, posture and drift views. Inspect broad aggregation, enrichment joins, repeated scans and expensive total counts. | Query plans and cumulative database cost under concurrent page visits; correct aggregates and measured improvement for any rewrite. Start at [`finding/summary.go`](../internal/app/finding/summary.go) and [`finding/clusters.go`](../internal/app/finding/clusters.go). |
| PERF-05 | High | Measure graph source reads, digest computation, rebuilds, signals, snapshots and traversal. Include small topology changes in large estates, dense graphs and high-degree nodes; measure ClickHouse fallback paths separately. | Phase timings, query/read budgets, graph correctness, peak native/process memory and read latency during rebuilds. Document remaining whole-estate work before considering incremental loading. Start at [`graphstore/service_sync.go`](../internal/app/graphstore/service_sync.go). |
| PERF-06 | High | Extend connector coverage beyond representative paths to every service family, many accounts/regions/clusters, real pagination and wide payloads. Exercise latency, throttling, retries, partial permissions and overlapping triggers. | Exact inventory/relationship results and request budgets; bounded concurrency, memory and retries; freshness and queue delay at the target arrival rate. Record synthetic and live-provider evidence separately. |
| PERF-07 | High | Cover enrichment sources and correlation rule families beyond the current local fixtures. Include shared packages/images, high fan-out, duplicate events, slow sources, backfill and failure recovery. | Persisted scores and relationships match expectations; all admitted or deferred work completes within its budget, without repeated equivalent lookups or starving another queue. |
| PERF-08 | High | Measure external vulnerability feeds, registry pulls, image/package parsing, opt-in disk scans and LLM/provider work. Include full/delta refresh, cache hits/misses, repeated shared layers, large inputs and provider failures. | Per-family CPU, memory, network/request or token cost and completion latency; correct deduplication, bounded work and recovery. Keep unlike external costs separate from local processing time. |
| PERF-09 | High | Run real HTTP and MCP traffic plus browser journeys during ingest. Include authentication, serialization, large responses, search/filter changes, dashboard fan-out, graph rendering and several simultaneous sessions. | User-visible p95/p99 latency, throughput, errors, response bytes, browser memory/render time and server cost; correct results under concurrent writes. Service-call benchmarks alone do not close this item. |
| PERF-10 | High | Exercise aged Postgres and ClickHouse data: accumulated versions, many parts, realistic historical distributions, retention, compaction, vacuum and River job retention. | Repeat the read/write workload on fresh and aged datasets; measure whole-server CPU/memory, disk growth and maintenance interference. Seeded history and actual elapsed soak time are reported separately. |
| PERF-11 | High | Run mixed sustained workloads: simultaneous connector syncs, enrichment, correlation, scans, maintenance and user traffic. Ramp arrival rates through saturation and recovery; include a 24-hour target-load soak. | Queue age and freshness stay within declared budgets; throughput is sustainable, no queue starves, memory/disk growth is explained and the system recovers after overload. Capture total database memory, not just per-query peaks. |
| PERF-12 | High | Measure cold starts, snapshot restore/rebuild, worker loss, datastore outages and catch-up. Drain a complete large deletion/enrichment backlog while normal work continues. Exercise upgrade/migration cost on aged data. | Full expected backlog drained and independently read back within the recovery budget; no lost work or stale published state. Worker cancellation, two bounded deletion batches and warm-cache starts cannot substitute for these scenarios. |
| PERF-13 | High | Establish native AMD64 and ARM64 baselines on declared hardware and resource limits. Use controlled instances for cloud cost comparisons. | At least three comparable runs with source, CPU, database images, limits and raw samples retained. Measure cost per completed workload including databases, storage and relevant network/API charges. |
| PERF-14 | Ongoing | Add regression protection for each measured cost problem and keep the coverage inventory current as PRs add or change work. | PR checks enforce cheap correctness, cardinality, query/request and allocation budgets; sustained/large runs have retained scheduled results. Strict timing gates run only on controlled hardware with explicit budgets. |
| PERF-15 | Final gate | Independently replay the critical workloads and review the evidence against the declared coverage target. | Fresh datasets or a separate replay confirm persisted outputs, query costs and recovery; every critical family passes, weighted coverage reaches 90%, and residual gaps are explicitly recorded. |

Start implementation with PERF-01/02 and the inventory/dashboard queries in
PERF-03/04. Prioritise subsequent fixes by measured total cost and user impact.
Do not rewrite every occurrence of `FINAL`, a join or a full scan solely because
it appears in source: some scans are necessary and some filters prune effectively.

## Baseline evidence review — 2026-11-27

The continuation starts from public `origin/main` at
`f9e5fa7fd8c3b2873e1ca181731fb36bc0269793`. Reviewed evidence comes from
[pipeline performance work (PR #15)](https://github.com/vulngraph/vulngraph/pull/15),
[native architecture validation (PR #17)](https://github.com/vulngraph/vulngraph/pull/17)
and the [three-run native benchmark matrix](https://github.com/vulngraph/vulngraph/actions/runs/45992613898).
The benchmark source, fixture and hardware recorded in those artifacts govern
their applicability. Passing CI does not establish a project-wide denominator.

| Worklist items | Existing evidence | Remaining gap and next action |
| --- | --- | --- |
| PERF-01/02 | Representative benchmark profiles and per-scenario checks exist. | Reconcile the complete workload inventory, assign owners and weights, and declare budgets before scoring. These are the first implementation tasks. |
| PERF-03/04 | Narrow finding-page reads and selected service reads have measured results. | General asset inventory and dashboard summary/cluster/facet/identity/posture/drift costs remain open. Establish baseline query plans, exact outputs and concurrent-ingest costs next. |
| PERF-05 | Repeated graph builds include a fixture with 20 million stored package memberships, 810,000 graph nodes and 1.95 million core edges; unchanged and topology-change cases were measured. | Complete dense/hub, fallback, snapshot and concurrent-read scenarios with phase and whole-process budgets. Stored package memberships are not resident graph edges. |
| PERF-06 | Eight representative connector fixtures exercise 40 sync scenarios. | Reconcile all service families and extend latency, pagination, quota, partial-access and overlap scenarios. Mock SDK results do not measure live-provider capacity. |
| PERF-07 | Four local enrichment sources, 24 rules and automatic backfill have persisted-output checks. | Cover remaining rule/source families, shared inputs, high fan-out and complete deferred work under load. |
| PERF-08/09 | Existing sustained tests exercise selected service calls. External feeds, scans and LLM work are not consumed by those tests. | Measure external processing separately and add actual HTTP/MCP/browser traffic; service-call latency does not close these items. |
| PERF-10/11 | Fresh synthetic datasets and repeated runs with at least five minutes of sustained work exist. | Add aged datastore profiles, maintenance interference, saturation/recovery and the 24-hour mixed target-load soak. Seeded history and short runs do not establish elapsed-soak evidence. |
| PERF-12 | Worker restart, retry and graph rebuild checks pass for existing fixtures. | Complete datastore-outage, cold-start, large backlog drain and aged upgrade/migration scenarios with independent final-state readback. |
| PERF-13 | Three native Linux AMD64 runs and three native Linux ARM64 runs passed for the recorded synthetic profile; release and PR checks cover both architectures. | Establish the remaining profile coverage and controlled cloud cost measurements. Shared CI and local Apple silicon results are not Graviton capacity or cost measurements. |
| PERF-14 | CI checks correctness, selected query/request/cardinality bounds and native pipeline behavior; scheduled trends retain separate architecture results. | Reconcile protections with the full workload inventory and add a guard for each newly measured cost problem. |
| PERF-15 | Existing profiles have artifact checks and independent persisted-output readback. | Replay the complete critical workload set after PERF-01/02 establishes scope, then calculate weighted coverage with residual gaps. |

All 15 items remain open. This review supplies starting evidence and next actions;
it gives no workload coverage credit by itself. The performance-assurance task
owns this continuation and must assign family-level owners in PERF-01. The
separate GitHub App/workflow feature must enter that inventory when introduced.

Do not calculate speedup ratios across different machines, datastore limits or
fixture versions. In particular, earlier manual enrichment sweeps and the newer
automatic-backfill fixture measure different end-to-end work.

## Required workload dimensions

Use these dimensions to select scenarios for each family; record any omission and
its rationale rather than silently treating one happy-path run as full coverage.

- **Scale and shape:** normal and stress sizes, wide metadata, less-compressible
  IDs, skewed ownership, shared images/packages, dense relationships and hubs.
- **Change:** initial, unchanged, small and large changes, duplicates, deletions,
  reappearance, partial collection and history accumulation.
- **Cache and storage:** warm and cold reads, fresh and aged tables, snapshots on
  and off, maintenance active, and realistic disk/IOPS and memory limits.
- **Concurrency:** isolated work, normal mixed load, bursts, saturation and
  catch-up. Record arrival rate, concurrency and queue wait as well as work time.
- **Dependencies:** latency, throttling, pagination, errors, retries, unavailable
  sources and alternate/fallback execution paths.
- **Hardware:** supported native architectures, CPU identity, process limits,
  database limits, storage class and runtime/dependency versions.

## Patterns to inspect in every family

- [ ] A small `LIMIT` hides a full scan, aggregation, join, traversal or sort.
- [ ] Wide rows are materialised when only IDs or a few columns are needed.
- [ ] Per-resource queries or API calls repeat equivalent work; repeated matching
  or nested loops grow quadratically; pagination or SDK retries amplify calls.
- [ ] Full-estate refreshes run for small changes or overlapping schedules repeat
  the same sweep. Caches cause simultaneous misses, stale results or unbounded growth.
- [ ] Goroutines, buffers, batches, decoded payloads, native allocations or query
  memory remain unbounded despite a bound on returned rows or active workers.
- [ ] Duplicate writes, row versions, tiny parts, snapshots, compaction or
  maintenance multiply storage work or compete with interactive reads.
- [ ] Queue admission, worker concurrency, connection pools or shared locks create
  starvation, large tail latency or a backlog that never catches up.
- [ ] Timeout/cancellation leaves work running, or retries turn overload into more
  load. An apparently fast result silently drops work or returns incomplete data.

## Evidence required to close an item

Keep raw benchmark artifacts outside the source tree and link them from the
completed work item or PR. Each workload record must contain:

| Field | Required contents |
| --- | --- |
| Identity | Workload ID/family, owner, risk weight, tracked issue/PR, status and review date. |
| Scope | Entry points and code revision; fixture version/seed; required scenarios and deployment profile. |
| Environment | Native OS/architecture/CPU, runtime and datastore versions, CPU/memory/storage limits, cache state and database age. |
| Budgets | Agreed throughput, freshness, p95/p99 latency, error, recovery, resource and query/request limits, set before acceptance. |
| Results | Raw repeated samples and baseline/candidate comparison; queue wait, processing time, CPU profiles, Go/native/process memory and total database resource use where relevant. |
| Correctness | Expected versus persisted counts/values, duplicate/deletion semantics, partial-input behaviour and complete backlog recovery; identify the independent readback method. |
| Decision | Pass/fail for each required scenario; measured tradeoffs, remaining limitations and follow-up owner. |
| Protection | Regression test or budget check and where it runs; artifact retention location sufficient for the release being assessed. |

Use the states **unmeasured**, **partial**, **failing**, **covered** and **stale**.
A material change to code, schema, dependency, workload or hardware requires review
of the affected evidence; mark it stale until its applicability is established.
Report the coverage score together with the profile, inventory revision, evidence
date and outstanding critical failures. Documentation alone does not raise it.

## Connector investigation candidate — GCP Asset Inventory

For PERF-06, evaluate an organization/folder/project Cloud Asset Inventory
snapshot plus change-feed path, with native API reads for missing fields and
relationships and periodic full reconciliation. The current collector uses native
APIs; ADR 013/022 describe Asset Inventory/Pub/Sub as future work. This is an
investigation candidate, not an implemented optimization or measured speedup.

Compare API requests, runtime, memory, queue age and freshness against the same
estate through the current collector. Independently verify field/relationship
parity, duplicates, missed events, permissions, reconnection and deletion
semantics. Partial/denied/incomplete feeds cannot establish absence or authorize
retirement. Retain native supplemental reads wherever the Asset Inventory model
is insufficient. See Google's [Asset Inventory overview](https://docs.cloud.google.com/asset-inventory/docs/asset-inventory-overview)
and [asset-change monitoring](https://docs.cloud.google.com/asset-inventory/docs/monitor-asset-changes).

Owner: performance-assurance / GCP collector maintainers. Next action after the
current query milestone: design matched snapshot/feed fixtures and request
budgets. This does not authorize cloud provisioning or paid live calls and does
not expand the current query PR into a connector implementation.

## Async ingest and graph publication acceptance

PERF-05/11/12 preserve the current separation between durable inventory ingestion,
correlation and graph rebuilding. Measure ingestion progress and reader availability
while an off-side graph rebuild runs, including shared CPU/memory/IO contention,
coalesced job replay, worker loss and published freshness/completeness. The
`graph_consistency` scenario class makes these requirements explicit.

Separate queues and an atomic graph-pointer swap do not prove that multiple
ClickHouse source reads observed one committed snapshot. Exercise writes between
those reads and independently verify the published scope/version. Where a
per-scope completion/version boundary is missing, retain that as a gap rather
than labeling the rebuilt graph a consistent snapshot. This acceptance context
does not request an architectural rewrite in the current query milestone.

## Current-state join comparison candidate

PERF-04/07/11 should identify the highest cumulative current-state join costs,
starting with findings plus latest enrichment and package-to-resource rollups.
Reproduce versions, skew, fan-out and concurrent writes before comparing the
current and optimized ClickHouse shape with an indexed Postgres alternative.
The same logical outputs, hardware budget, freshness, update/deletion behavior
and ingest arrivals must govern both sides.

Retain total datastore memory/CPU, ingest and drain rates, p95/p99 read latency,
maintenance and write amplification, and independent persisted-output readback.
A fast graph-source load is not a comparison of full sync/correlation, and one
fast join is not a whole-system result. No storage migration is selected by this
plan. Owner: performance-assurance; next action is a matched local fixture for a
measured costly join, using the existing isolated stores. This follows the first
query milestone and authorizes no paid infrastructure.

Separate staging/batching benefits from database-engine benefits. Replay identical
allowlisted observations from an immutable local spool into ClickHouse batches
and Postgres COPY-to-staging with scoped reconciliation/publication. Exercise
crash replay, duplicates, ordering, incomplete-scope deletion refusal and atomic
publication; do not assume one unbounded transaction across all scopes. Current
collectors return in-memory results and ClickHouse already batches writes, but
durable staged inventory generations remain a gap. A local spool proves neither
S3 latency nor S3 cost and introduces no production storage dependency.

## PERF-04 large-join continuation

[Large current-state join measurements](performance/large-join-measurements.md)
record a focused full-table findings rewrite, three repeated mixed-load runs,
matched batching/merge-phase comparisons and the 100-million-membership fixture.
The rewrite improves the million-finding baseline; catch-up p95 and larger
cardinality budgets still fail. These are partial repository-level results, not
HTTP/browser or full deployment-profile coverage. The remaining worklist stays
open, including native/version cohorts, broader state/update scenarios and recovery.

PERF-03 also tracks [derived-state inventory page costs](specs/asset-derived-state.md#inventory-page-costs).
Version-key hydration passes the measured 100,000-asset query budgets, but an
empty selective page still reads 5,002 rows versus its 2,002-row joined baseline.
Retain that scan tradeoff and the empty-derived-state latency overhead in further
mixed-load work; the focused fix earns no full-profile coverage credit.

PERF-05/11/12 also track delayed correlation writes after an authoritative
resource deletion. The real Postgres/ClickHouse regression writes A → B → C,
retires B, then writes the old relationships again. ClickHouse fallback explore
and blast-radius traversal must consult the durable deletion proof before
expanding the frontier. Missing, never-observed identities remain visible; a
newer observation restores a deleted identity. Proof-read failures are errors,
not empty results. This check does not replace ephemeral-expiry policy or make
raw retained relationship rows disappear.

The three-node, three-repeat replay measures the cost of that correctness check:
explore median 8.47 → 19.99 ms and blast median 14.99 → 26.74 ms, each adding
three bounded Postgres proof lookups and two ClickHouse observation reads.
These are small-fixture costs, not tail-latency or scaling guarantees. The
mixed-provider synthetic harness now includes cross-scope relationships,
round-robin provider admission, and complete/partial/deletion/reappearance waves.
Its 5,000-asset replay passes all six waves. The million-asset diagnostic still
fails the unchanged 600,000-relevant-asset correlation breaker before completing
a wave. Two graph-source asset reads also failed ClickHouse memory limits; HTTP
read success does not establish that a graph rebuild succeeded. Bounded graph
source reads, correlation inputs and a completed larger replay remain required;
neither an aborted run nor synthetic Collect results earn live connector or
whole-profile capacity coverage.


PERF-05/11/12 now track the [production source-reader measurements](performance/source-read-measurements.md):
the projected correlation reader reduces million-input query peak memory to
202.1 MB while retaining the 600,000-row refusal; the graph reader passes three
isolated million-asset retained-result checks. Partial invalidations use bounded
analysis batches, narrow SQL seed pages and explicit busy-lane admission.
The 100,000-row query has a measured latency cost. Whole-system million-asset
acceptance, transient rule-output bounds and swap-disabled capacity remain open;
these focused improvements earn no full-profile coverage credit.

PERF-05 also tracks [critical-edge source measurements](performance/critical-edge-measurements.md).
Ordered aggregation with bounded blocks passes the isolated 5,000/100,000/million-edge
query budgets and exact-output checks, with smaller-input latency costs retained.
Concurrent retained-result replay passes; whole-pipeline freshness, resource and
recovery acceptance remains open, with no full-profile coverage credit.

PERF-07/12 also track [durable enrichment sweep progress](specs/enrichment-sweep-progress.md).
A real-store fixture reproduces starvation behind 2,500 unchanged cached findings.
The checkpointed sweep reaches the changed tail through a fresh worker instance;
committed-enqueue/lost-checkpoint replay preserves pending work. These are bounded
correctness and restart checks, not elapsed scheduling or large-backlog freshness
acceptance. The fixed sweep budget, queue admission and periodic cadence remain
part of the mixed-load measurements, with no full-profile coverage credit.
