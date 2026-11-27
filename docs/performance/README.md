# Workload inventory and fixed budgets

Tracking: [#19](https://github.com/vulngraph/vulngraph/issues/19),
[spec](../specs/performance-assurance.md), [15-item worklist](../performance-assurance.md).

`workloads.json` revision `2026-11-27.1` fixes the initial denominator: **290
families, weight 1,090, including 113 critical families**. Every family has exact
entry memberships, an accountable task owner, risk rationale, scenario classes,
budget class, status and next action. Helpers share a family; materially different
filters, graph fallback, snapshots and mixed-load recovery are separate families.
The GitHub App family includes the parallel feature's proposed scope; its new
registrations must be reconciled when integrated. It has no measured credit.

```sh
GOTOOLCHAIN=go1.26.11 go run ./cmd/perf-inventory -check
GOTOOLCHAIN=go1.26.11 go test ./internal/perfassurance
# Inspect the discovered entry points without assigning them to a family:
go run ./cmd/perf-inventory
```

The root unit suite checks exact membership against HTTP registrations, OpenAPI
paths, MCP tools, collector registration, all collector service modules, named
correlation rules/enrichment sources, workers, job kinds, schedules, browser
route components, migrations (including Go migrations), and application,
scanner/feed, check, storage and startup modules. Module enumeration complements
registrations for direct-call service families. OpenAPI's existing route/operation
contract guard remains authoritative for HTTP-contract parity. Browser component
inventory includes Settings sub-pages, not just top-level routes.

A new or removed entry fails reconciliation until a reviewer assigns it. The
checker does not auto-assign it to an existing family or infer coverage from file
presence. Dynamic unsupported registrations fail closed. Existing-file changes,
configuration, schema/dependency changes and runtime/browser journeys still need
human applicability review; static enumeration is not a proof of execution.

## Profiles and acceptance

`profiles.json` revision `2026-11-27.1` records **engineering targets before new
measurement**, not measured capacity or provisioning advice. Each family requires
small/target/stress on native Linux AMD64 and Linux ARM64 separately. The profiles
fix counts, skew and wide payloads, change/arrival rates, seeded storage age,
process/container limits, total host limits and storage IOPS/throughput. Record
actual CPU model, kernel, storage, database image digests, Go/native-library
versions and enforcement settings. Unenforced or undisclosed hardware limits
cannot establish a profile pass. Local macOS results are exploratory evidence.

| Profile | Assets | Findings | Stored package memberships | HTTP arrivals/s | Enrichment arrivals/s | p95 / p99 reads | Change freshness / full recovery |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| small | 10,000 | 10,000 | 200,000 | 5 | 20 | 500 / 1,500 ms | 15 / 30 min |
| target | 100,000 | 1,000,000 | 20,000,000 | 20 | 100 | 1,500 / 3,000 ms | 30 / 60 min |
| stress | 1,000,000 | 5,000,000 | 100,000,000 | 80 | 400 | 5,000 / 10,000 ms | 60 / 120 min |

Freshness begins at admission; provider polling lag must also be reported. The
higher stress latencies are a declared degradation envelope, not a target-profile
pass. Every run includes zero lost work and zero correctness mismatches, bounded
queue age and whole-server resource budgets. Source/provider timeout/error
scenarios must expose unknown/partial state rather than fabricate successful data.

Scenario classes expand into required named scenarios. Record applicability of
each dimension for each family: a scenario that cannot apply needs an explicit
reviewed rationale, never a silent skip. Synthetic and live-provider connector
scenarios are distinct; mock evidence cannot pass the live scenario. Provider
calls or provisioning require appropriate authorization separately. External
input/network/token ceilings supplement rather than replace per-provider limits.

Existing three-repeat benchmarks inform these targets (especially the small
freshness/recovery envelope), but use different data/arrival/hardware scopes.
Their values are not transplanted into this ledger. A failed target remains a
failure; changing a profile requires a versioned rationale and reevaluation, not
editing a limit to make a candidate pass.

Inventory query experiments add a <=2-query/100-row page budget and seek at least
25% lower wide-fixture read bytes and peak query memory for a rewrite. Dashboard
rewrites must reduce a measured cost without increasing cumulative read bytes or
peak query memory. Results, cursors, totals and liveness must remain exact. Query
plans determine whether a narrow selection helps; the worklist is not evidence
that every existing FINAL is slow.

## Query regression checks

`scripts/benchmark-queries.sh smoke <fresh-output>` runs on both native PR
architectures in the required pipeline check. It applies real migrations to
isolated stores, checks exact results and independent inventory IDs/metadata and
dashboard totals, retains EXPLAIN and query-log costs, and verifies that a real
wide `groupArray` regression exceeds the memory guard. No timing gate is used. The weekly/manual native trend workflow adds three fresh
100k query datasets with three retained inventory versions and the explicitly opt-in
`buffers` experiment, retaining known production-baseline budget violations. These seeded versions
do not substitute for a 24-hour mixed soak.

The fixture cost ceilings, fixed after the initial small baseline and before
larger measurements, are: inventory <=1 query, <=5 physical row passes,
<=20,000 read bytes per physical row, and <=32 MiB + 512 bytes per logical row
peak query memory. Dashboard <=1 query, <=30 finding-row equivalents read,
<=1,024 bytes per finding and <=32 MiB + 2,048 bytes per finding peak query
memory (the fixture includes ten enrichment rows per finding). These are cheap
fixture guards, not whole-server or deployment-profile acceptance. Deliberate
query-count/read-row/read-byte/memory mutations also pin each budget dimension.

Use `small`, `target` or `stress` for 10k/100k/1m query fixtures; these names select
only the query dataset, not every dimension in the full deployment profile.
`PERF_QUERY_VERSIONS=3` seeds retained versions with merges paused; this is seeded
history, not elapsed aging. `PERF_QUERY_EXPERIMENT=keys` replays the rejected
key-selection/argMax experiment; `buffers` replays the rejected default-cap
experiment. Production SQL/settings are unchanged. Failed runs remain in their output directories.
See [initial query evidence and decisions](query-measurements.md).

## Evidence ledger — 2026-11-27

**Accepted coverage: 0 / 1,090 (0%) in each of the six profile/architecture
combinations. Critical passing families: 0 / 113.** These figures describe
accepted evidence under the new inventory, not an assertion that existing
functions are broken. The baseline review in the worklist remains supporting
partial evidence. No family yet passes every required scenario on these profiles.

Reconciliation has no performance numerator: `-check` validates scope/budget
references and rejects a manifest-only `covered` claim. Reviewed evidence reports
must name the inventory/profile revision, scenario decisions, native architecture,
source/schema/dependency identities, independent readback and retained artifact
locations before coverage can change. A material change invalidates affected
acceptance until reviewed. Raw results stay outside the source tree; compact sanitized summaries may be tracked.

Remaining work includes matched query baselines/candidates, HTTP/MCP/browser
traffic, all provider service paths and external processors, aged storage,
complete backlogs/outages, controlled native repeats and the complete 24-hour
mixed target soak. Unit checks and short local measurements do not close those
families. PERF-15 requires a fresh independent replay of every critical family.


## Parallel GitHub App evidence handoff

The peer's populated 100/1k/10k synthetic collector runs retain exact 6N+5 assets,
7N+2 collected edges and initially 813/8,049/80,409 API requests within <12N+200. The peer reports
313/3,049/30,409 after per-repository read reuse, with a tightened <4N+200
ceiling; final native/integration verification remains with that feature. Native graph replay is a separate stage. These are
supporting synthetic results, not live-provider or full-profile acceptance;
source patches/hashes and per-run artifacts remain with the peer's final report.

When integrating that feature, explicitly reconcile its new `app_inventory.go`,
`workflow_visibility.go`, `iac/workflow_supply_chain.go` and
`workflow_lifecycle.go`, `repository_sources.go` and `repository_read_cache.go`
modules/functions, removal of `workflow_ingest.go`, and
expanded CIAccess scenarios. The exact-entry guard intentionally fails until this
mapping is reviewed. Keep `collect.github.apps` and workflow/cloud-declaration
families separate where their pagination, grant membership and fan-out differ.
