# ADR 049 — Graph edge staleness: re-stamp + 48h freshness filter, no deletes

**Status:** accepted (implemented 2026-07-10) · amended 2026-08-11 (partial producer sweep), 2026-08-13 (edge count is not a change signal), 2026-08-21 (ephemeral-endpoint edge lifetime)

## Context

`graph_edges` is ReplacingMergeTree with an INSERT-only write path — there is
no delete/tombstone mechanism. When an edge disappears from reality (a security
group detached, a DNS record removed, a correlate rule stops deriving it), its
row simply stops being re-inserted; ClickHouse keeps it until the 180-day TTL.
Every Ladybug rebuild read the current deduplicated edge set, so disappeared edges
stayed traversable for up to six months. Rows left behind by a since-fixed
producer bug (legacy `connected_via_sg` rows) had to be excluded with a
hand-written fetch-time `dst_id IN (…)` guard.

Deleting is the wrong tool here: RMT mutations are expensive, and ADR 022's
diff-sync means we cannot know which rows to delete without diffing the world.

## Decision

Liveness = a fresh `synced_at`. Three moving parts:

1. **Producers re-stamp every live edge, every sweep.** Correlate rules already
   re-derive edges with stable IDs every 30 minutes. Connector sync now
   re-ingests `res.Edges` (and the CIEM `can_escalate_to` edges) even on the
   ADR 022 no-change short-circuit — the fingerprint skip still avoids the
   asset write + enrich pipeline, but edges are always written. RMT dedups
   re-inserted rows on merge.
2. **Every `graph_edges` reader applies `graphschema.EdgeFreshnessCond`**
   (`synced_at > now() - INTERVAL 48 HOUR`): the Ladybug sync fetch, blast-radius
   and lineage lookups, the exposed-filter subquery, explore's ClickHouse
   fallback, and the finding risk rollup. 48h = 24× the 2h collector cadence;
   a connector outage degrades slowly and `graph_connector_stale` alerts long
   before edges age out. `TestGraphEdgesReadersApplyFreshness` (source scan)
   forces every future reader to filter or claim an explicit exemption —
   `asset/drift.go` is exempt because the drift timeline is deliberately
   historical.
3. **TTL 180d → 30d**: with reads freshness-filtered, rows
   older than 48h have no query value; 30 days keeps a forensic window without
   carrying months of dead topology.

## Consequences

- A disappeared edge leaves the traversable graph within one freshness window
  (≤48h) instead of ≤180d.
- Identical read semantics on Ladybug and the ClickHouse fallback — the freshness
  window is part of the shared graph contract in `internal/graphschema`.
- The `connected_via_sg` legacy-row guard in `criticalEdgesQ` becomes redundant
  once the old rows age past 48h, but stays until the 30d TTL clears them
  (remove in a follow-up).
- Slightly more CH insert traffic on no-change sweeps (edges only) — bounded by
  connector edge counts, dedup-merged by RMT.

Cites ADR 022 (diff-sync it amends), 025/026 (graph lifecycle), 048 (the
shared graphschema contract this rides on).

## Amendment 2026-08-11 — a partial producer sweep deletes topology

Re-stamping is the liveness mechanism, so an edge a rule could not derive —
because its endpoint fell outside a truncated or partial view — stops being
re-stamped and leaves the traversable graph within 48h. Incomplete producer
output is therefore destructive, not merely lossy.

Two rules follow, both enforced:

- `correlate.ErrViewTruncated` **fails** the sweep instead of logging a warning
  and continuing. The correlation view is capped at `correlationLimit` rows (`correlate/repo.go`) and the query's
  `LIMIT` has no `ORDER BY`, so correlating a truncated view would drop an
  arbitrary, non-deterministic subset of edges on every sweep. Refusing the
  sweep keeps the last good edge set alive inside the window until the ceiling
  is raised. The partial-view path likewise must not discard the truncation flag.
- The correlate sweep must stay **atomic**. Any future design that ingests edges
  per-chunk must either complete every chunk or write none — otherwise a mid-sweep
  failure leaves the un-reached chunks un-re-stamped, trading a clean visible
  failure for silent partial topology loss. This is the main reason chunking the
  correlation view was rejected (see ADR 024's 2026-08-11 amendment).

## Amendment 2026-08-13 — an edge count is never a change signal

Because producers re-stamp every live edge on every sweep, the number of edges a
sweep writes is positive on every sweep by design and can never answer "did
anything change?". Any such decision must compare content, not counts — see
ADR 074 (the Ladybug rebuild gate).

## Amendment 2026-08-21 — an edge outlives its ephemeral endpoint by up to 48h, and that is not a loss

The freshness window and the asset liveness window are anchored differently.
`EdgeFreshnessCond` gives an edge 48h from its last re-stamp;
`asset.EphemeralLivenessCond` (ADR 068) excludes a pod, container or job from
the load set once it is more than 72h behind the k8s collector's own high-water
mark. A producer re-stamps a pod's edges right up to the moment the pod crosses
that cut, so for the following 48h the edge is fresh and its endpoint is not in
the graph. The loader cannot create the row and previously counted it as
`endpoint_absent` — the same bucket as a genuinely dangling reference. These
expired-endpoint rows can dominate the counter for edge types with ephemeral
endpoints (`executes_as`, `deploys_to`, `targets`).

Dropping those rows is correct — the endpoint is gone, and a departed pod must
not receive an `internet_hops` value or appear in an attack path. The defect was
the accounting: with expired endpoints mixed into `endpoint_absent`, no threshold
on it could be set, so the shapes that are bugs — a producer emitting ids nothing
collects, or an endpoint type wrongly excluded from the graph — had no detector
(for example, regressions affecting `dns_points_to` via `elastic_ip` endpoints and
`contains_data`). This is ADR 048's "zero rows is a finding, not a pass" applied
to drop counters.

Three changes, no new subsystem:

1. **The drop is classified, not summed.** `classifyRelEndpoints` reads the
   declared type of the missing endpoint off the edge row (`src_type`/`dst_type`,
   already fetched from ClickHouse) and reports `endpoint_expired` when it is one
   of `asset.EphemeralTypes` — the same list `EphemeralLivenessCond` filters the
   asset read on, so the two halves of the question cannot disagree. New metric
   outcome `endpoint_expired`; `endpoint_absent` now means what its name says.
2. **`endpoint_absent` gets a declared per-type budget.** `EdgeType.DanglingBudget`
   in `internal/graphschema` (default 5% of fetched, floor 100 rows) is the
   reviewable decision ADR 048 asks for: some dangling is irreducible for
   `can_assume` (cross-account AWS principals), while a large dangling share for a
   type like `dns_points_to` is a regression, and only a per-type declaration can
   tell those apart. The worker evaluates it and publishes
   `graph_ladybug_edge_dangling_over_budget{edge_type}`, so the alarm reads the
   verdict rather than re-deriving the threshold in PromQL. The alarm is intended
   to start silent and move only on a regression.
3. **A producer must not emit an edge to an endpoint it can prove does not exist.**
   The k8s RBAC collector previously emitted `binds` for ServiceAccount subjects in
   system namespaces while skipping the ServiceAccount asset there (leaving
   high-privilege identities, including bindings flagged `dangerous_perms`, without
   a node), and emitted `binds` for RoleBindings whose subjects name ServiceAccounts
   in namespaces that no longer exist (for example, namespaces deleted after the binding
   was created).
   System-namespace ServiceAccounts are now collected, and a subject whose namespace
   does not exist, or whose namespace was listed successfully without it, is not
   emitted. Absence of evidence fails open: a namespace whose ServiceAccount list
   errored proves nothing and its subjects are still emitted, so API throttling
   cannot delete real RBAC topology. Same rule ADR 056 applies to k8s owner
   propagation ("a bare ReplicaSet owner has no asset, so an edge to it would be an
   unresolvable zombie").

No `SchemaVersion` bump: the loaded rel set and the DDL are unchanged, and the new
ServiceAccount nodes are content the ADR 074 load digest already gates.

Expired `targets` rows do not cost a live asset its reachability: the
service→owner-workload `targets` edges (the ADR 056 chain the aggregated finding
reads) have live endpoints, and a service with a dead-pod `targets` row still
reaches its live pods. The missing endpoints are pods that no longer exist, which
cannot hold a finding or a hop count either way; `executes_as` and `deploys_to`
have the same shape. Genuine endpoint loss is concentrated in `binds`/`can_assume`,
which the budget and producer rule above address.

Cites ADR 048 (the registry these budgets live in, and the declared-drop gate),
068 (ephemeral liveness), 056 (the k8s exposure chain), 044 (reachability),
074 (the load digest).
