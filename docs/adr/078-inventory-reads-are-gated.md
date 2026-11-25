# ADR 078: Inventory reads are gated — the Assets page counts live resources, by id

**Status:** accepted (2026-08-21)

## Context

`assets` is a ReplacingMergeTree whose rows are never deleted. ADR 068 settled
what that means: liveness is `last_seen`, not row presence. A resource that is
recreated on every deploy leaves a permanent row behind, so "the row exists" and
"the resource exists" are different questions, and only one of them is inventory.

`asset.EphemeralLivenessCond` expresses the difference, and every WRITE-side and
GRAPH-side path applies it: the Ladybug bulk sync (`listAllForSyncQ`), the correlate
LoadView, the dangling-finding sweep (`LiveIDs`), the optimize job's liveness
helpers. Nothing on the READ path did, so the Assets page total and the Ladybug
graph's asset node count (same table, gate applied) could disagree substantially.

Three distinct defects produced one symptom:

1. **No liveness gate on the read path.** The page counted every historical row
   of ephemeral types (`k8s_pod`, `container`, `k8s_job`), most of which no
   longer exist — the same asymmetry ADR 068 describes for exposure queries.

2. **IaC declarations counted as inventory.** Rows with a blank provider were
   all `declared_*` types: parsed lines of YAML/Terraform/workflow files out
   of git repos, written into `assets` only as correlate join inputs (ADR 061/063/
   065). Each one is not a resource AND double-counts the real resource it
   describes. Two of the five types (`declared_cloud_identity`,
   `declared_image_build`) were also missing from `NeverSyncTypes`, so the graph
   excluded three and included two, for no stated reason.

3. **`count()` over a tuple dedup key.** The table is `ORDER BY (provider, type,
   id)`, so `FINAL` deduplicates on the whole tuple rather than on the id. A
   package discovered in BOTH a container image (`provider=kubernetes`) and a
   GitHub SBOM (`provider=github`) is two permanent rows that no merge can
   collapse, so `count()` overstated the package total relative to distinct ids.

## Decision

**One shared predicate, `asset.inventoryReadCond` = `EphemeralLivenessCond` AND
`type NOT IN NonInventoryTypes`, applied by every UI-facing asset read.** This is
the same single-definition discipline `graphschema.EdgeFreshnessCond` has for
edges (ADR 049), for the same reason: two readers answering "what do we own?"
two ways is drift with a UI on top of it.

- `assetSummary` and the inventory list (`listQuery`) apply it in SQL.
- The risk view (`sort=risk`) ranks ids from the finding store, so it cannot;
  it filters through `LiveIDs`, which embeds the same condition. A failure there
  degrades to the unfiltered ranking — hiding the triage queue is worse than
  showing a stale row.
- `NonInventoryTypes` is a new, separately named list, NOT a reuse of
  `NeverSyncTypes`. `NeverSyncTypes` also holds real resources (`ebs_volume`,
  `vpc`, `nat_gateway`) that are graph noise but genuine inventory; conflating
  "not a graph node" with "not a resource" would remove every EBS volume from
  inventory. The `declared_*` entries of the former are now a subset of the
  latter, and a guard test pins that direction.
- `uniqExact(id)`, not `count()`, wherever the summary counts assets, with all
  three aggregations (total, by provider, by type) from one `GROUPING SETS` pass
  so each is exact rather than summed out of a grid.

**The liveness window stays narrow on purpose.** Only `k8s_pod`, `container`,
`k8s_job` are gated — the types where absence from collection means deletion.
`ec2_instance` (whose rows can be dominated by terminated spot/ASG instances held by
the 180-day TTL) is NOT gated and must not be: it is a cloud resource type, where
a stale row is more often a victim of broken collection than a deletion, and
excluding a live asset from inventory hides risk. Shrinking that number honestly
needs a terminated-state signal from the collector. `dns_record` and the
`NeverSyncTypes` resources are likewise counted, which is why the inventory total
remains above the graph's node count: the graph additionally drops topology types
and edge-gates `dns_record`, neither of which is evidence a resource is gone.

**`sort=risk` rejects inventory filters instead of dropping them.** The handler
short-circuited into the risk view before building the `Filter`, so
`?sort=risk&min_score=90` answered 200 with the unfiltered top-100 — a response
the caller cannot distinguish from a filtered one. All eight inventory parameters
are rejected together (400), because the same silence applied to every one of
them. The UI never sends the combination.

## Consequences

- The Assets page total drops to live resources counted by distinct id; the
  blank-provider pill disappears; `k8s_pod`, `container` and `k8s_job` show only
  live resources; `package` counts distinct ids; the `declared_*` types are no
  longer listed.
- `by_provider` can sum HIGHER than `total` (by the dual-provider packages). That
  is the honest answer to both questions: the package genuinely belongs to both
  providers, and it is one asset.

**Latent, not fixed here: the sort key.** `ORDER BY (provider, type, id)` is
wrong for a table whose identity is the id, and `uniqExact(id)` only makes the
reads honest — the write path still stores the fork, and a package that changes
provider still costs a permanent extra row. A real fix is a new table `ORDER BY
(id)`, `INSERT SELECT` of the current `FINAL` contents, a `RENAME` swap, and
dropping the `idx_id` bloom index that exists only to make id lookups survivable
under the current key. That is a migration plus a full rebuild of the base table
and every projection, which is out of scope for a read-path change; the
constraint is recorded at `assetSummary` so the next reader does not rediscover
it from a wrong number.

## Guard

`TestAssetReadersApplyLiveness` (internal/app/asset), mirroring ADR 049's
`TestGraphEdgesReadersApplyFreshness`:

1. the declared UI readers contain the condition;
2. `listQuery` contains it for every filter combination, cursor page included;
3. no query in the package reads the `assets` table without either the condition
   or an explicit exemption with a stated reason — so a NEW reader cannot repeat
   the bug silently.

`TestNonInventoryTypesCoversEveryDeclaredProducer` walks the collectors and fails
if any of them emits a `declared_*` asset type that is not on the list, which is
how this list would otherwise go stale: a new IaC parser lands with a collector,
nobody touches `asset/repo.go`, and its parsed lines quietly become assets we
claim to own. Both guards have rows in `internal/guardmutation` that reintroduce
the original bug and are verified to bite.
