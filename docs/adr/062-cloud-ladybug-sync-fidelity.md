# ADR 062: Cloud→Ladybug sync fidelity — close three silent-drop gaps

**Status:** accepted (2026-07-18)

## Context

A review of the cloud→Ladybug pipeline (connector → collector → ClickHouse →
correlate → Ladybug graph rebuild) found three places where data that ClickHouse *had*
never reached the graph, each silent, each degrading a
different slice of coverage. The attack-path core was intact (critical/reach edges
are uncapped and fetched in a separate no-limit pass — see `asset/repo.go`
`criticalEdgesQ`, and reachability is fail-open per ADR 044), so these are
context/inventory-fidelity gaps rather than correctness regressions in the gate —
but two of the three could hide real assets and real attack edges.

### Gap 1 — GCP collect aborted on a disabled Compute API

The GCP collector (`internal/collect/gcp/gcp.go`) documents every collection family
as best-effort: "a connector with compute but not (say) IAM access still yields its
compute inventory rather than failing the whole sync." But the very first call —
`ListInstances` (Compute Engine) — sat *above* that best-effort block as a hard
`return`. Many GCP projects (function-only, storage-only, data projects) have the
Compute Engine API disabled, which returns a 403 on
`ListInstances`. That 403 aborted the entire collect before IAM, Secret Manager,
GCS, Cloud SQL, Cloud Run, Cloud Functions, DNS, or firewall ever ran.

Every project hitting this error produced **zero assets** in ClickHouse, so for
those projects the platform was blind to IAM service accounts, secrets, and
buckets — prime CIEM/exfil targets. The same 403, being a non-permanent hard error
retried on every sync sweep, also filled River's `discarded` sync-job list.

### Gap 2 — `dns_points_to` starved by the per-type bulk cap

Bulk (context) edges are fetched under a per-type cap (`syncBulkPerTypeLimit`) and a
total cap (`syncBulkEdgeLimit`), deduplicated by `argMax(properties, synced_at)`.
`dns_points_to` is the bulk edge type most likely to exceed the per-type cap (75000 at
the time); other bulk types such as `depends_on` sit well below it. When it did, DNS
edges were dropped every rebuild, and
because the fetch query orders deterministically (`ORDER BY edge_type, src_id,
dst_id`) before the `LIMIT … BY edge_type`, the *same* alphabetically-late DNS
records were dropped each time. `DnsPointsTo` is a Loaded, query-traversed rel
(the DNS→internet-exposed-LB named query in `named_queries.go`, and blast-radius
impact in `enrich/safety.go` / `respond/impact.go`), so the same exposed assets were
under-reported on every rebuild.

### Gap 3 — `filterLadybugAssets` retention set drifted from the registry

`filterLadybugAssets` (`internal/app/graphstore/asset_filter.go`) keeps Ladybug's node set
lean by pruning score-0 assets that carry no query-relevant edge. It decided
relevance from a **hand-maintained** `securityEdgeTypes` set. That set had drifted
from the graphschema registry (ADR 048): it was missing the two k8s reach edges
`routes_to` and `targets` (the ADR 056 `internet→ingress→service→pod` chain). A
score-0 k8s service or pod reachable *only* via that chain was therefore pruned from
the node set, and its reach edges were then discarded at Ladybug insert (COPY drops any
edge whose endpoint node is absent — `copy_load.go`, counted as
`droppedEndpointMiss`). The k8s reachability chain that ADR 056 added was silently
losing its own endpoints.

## Decision

Three targeted changes, each closing one gap without touching the attack-path core.

1. **GCP compute is best-effort like every other family.** `ListInstances` is wrapped
   in the existing `bestEffort` helper: a failure flags the sweep `Partial=true` (so
   the sync worker skips deletion reconciliation — an un-fetched asset is not a
   deleted one, ADR 054) and the collect continues to IAM/secrets/GCS/etc. A missing
   `project_id` / ADC failure is still a hard error (nothing is collectable).

2. **Raise `syncBulkPerTypeLimit` 75000 → 150000** (`asset/repo.go`) so
   `dns_points_to` loads in full with headroom. The **total** cap (`syncBulkEdgeLimit`,
   500000 at the time) is unchanged and remains the real runaway guard. No change to
   which edge types are fetched or to determinism. (Both caps have since been raised
   again; see `asset/repo.go` for current values.)

3. **Derive the retention set from the registry.** `retentionEdgeTypes` is now seeded
   from `graphschema.ReachEdgeTypes()` plus the non-reach query-traversed context
   edges (SSO/DSPM/SBOM/DNS/SG). Reach edges can never again drift out of the
   retention set — a reachable node is retained by construction. Pure-topology edges
   (`in_vpc`, `runs_in`, `member_of_zone`, `in_subnet`, `owns`) remain deliberately
   excluded so zero-value adjacency nodes stay pruned. A test
   (`TestRetentionEdgeTypesCoverReachEdges`) pins `retentionEdgeTypes ⊇ ReachEdgeTypes()`.

## Consequences

- GCP projects with Compute disabled still contribute IAM service accounts,
  secrets, buckets, and managed-service inventory, so such a project yields more
  assets and findings than its Compute footprint suggests — size worker memory and
  the enrich backlog for that. A disabled-Compute 403 does not error the sync job, so
  it does not count toward the `discarded` sync-job rate.
- DNS→internet-exposed-LB attribution and DNS blast-radius stop under-reporting the
  same assets every rebuild.
- The k8s exposure chain (ADR 056) retains its score-0 service/pod endpoints, so
  those reach edges survive into Ladybug instead of being dropped at insert.
- Retaining reachable k8s endpoints adds a small, correct increment to the Ladybug node
  count. Node-count management is left to the existing score/edge/type gates; this ADR
  does not change that budget.

Cites ADR 048 (graphschema registry — the single source of truth the retention set
now derives from), 049 (edge staleness — the 48h freshness window these fetches
apply), 054 (partial-sweep semantics that make best-effort GCP collection safe),
056 (the k8s reach edges whose endpoints were being pruned), 044/060 (the fail-open
reachability signal that consumes these edges), 016 (OIDC cloud auth — why GCP
projects fail with a 403 rather than a credential error).
