# ADR 074 — the Ladybug rebuild gate is a content digest, not a version counter

**Status:** accepted (2026-08-13) · amended 2026-08-18, 2026-08-19 (twice) and 2026-08-21; see
the amendment notes at the end. The later amendments narrow what this ADR can
deliver: the gate is correct, but on a corpus that changes between every sweep it
will always choose a full rebuild, and the real lever for rebuild cost is a cheaper
rebuild.

## Context

`SyncFromSources` rebuilds the whole Ladybug graph from ClickHouse: read every asset and
every fresh edge, COPY-load them, run the risk BFS, write a snapshot. It costs
minutes. A cheap alternative existed — `RefreshSignals`, which updates only the
finding-derived signal columns in place — gated on "has topology changed since the
last full build?"

That gate could never fire. `CorrelateWorker.workFull` bumped
`sync_state.topology_version` unconditionally after every sweep, with
`toUnixTimestamp64Milli(now64())` — a fresh value every time. The comparison
`topoVersion == svc.LastTopologyVersion()` therefore never held, every rebuild was a
full one, and `RefreshSignals` never executed.

No metric could express this. The only rebuild metric was a duration histogram, which
samples the runs that happen; "every sync is a full sync" has no shape in it.

### Why the counter could not be repaired in place

The obvious fix — bump only when topology actually changed — is wrong:

- **The bump site cannot see what the gate protects.** Ladybug loads all assets ∪ all
  fresh `graph_edges` ∪ the signal rollup. `correlate.Correlate` sees only its own
  derived edge subset. A hash computed there would miss a newly collected asset that
  produces no derived edge, and that asset would never enter the graph — so its
  findings would get no reach data. A correctness regression is worse than wasted CPU.
- **Making every producer bump is a diffuse contract** spread across connector sync,
  CIEM and correlate — the class of contract ADR 048 and 049 exist to eliminate.
- **No edge count is ever a change signal.** Per ADR 049 producers re-stamp every live
  edge on every sweep, so the number of edges written is positive by design.

## Decision

Compute a **content digest of the load set inside `SyncFromSources`** — the one place
that sees everything Ladybug loads. As originally shipped it had two halves (a third was
added by the 2026-08-18 amendment):

- **Topo**: the node rows, the edge set, `reachComplete`, and `SchemaVersion`.
- **Signals**: only the fields a signal refresh can apply.

Topo match ⟹ identical BFS inputs ⟹ the rebuilt graph would be identical apart from
signal columns, so the signal path is sufficient. Both match ⟹ the rebuild is a no-op.

Five properties carry the correctness:

1. **Derived from the loader, not re-derived.** The topology half runs
   `streamNodeRows` with `nil` signals. That function is the single authority on what
   gets loaded — it applies the exposure map and the reach degradation — so the digest
   cannot drift from the loader. Passing nil signals zeroes the signal columns and
   keeps them out of the topology half. Edges (rel rows go through `writeRelCSV`)
   contribute separately.
2. **Over the post-filter asset slice.** `filterLadybugAssets` drops assets based on the
   edge set, so the digest must fingerprint what will actually load.
3. **Order-independent.** ClickHouse read order is not stable and Go map iteration is
   randomised. Per-row hashes are combined by wrapping addition (not xor, which
   cancels duplicates), row counts are mixed in, and edge properties are iterated in
   sorted key order. An order-dependent combine would silently stop the gate firing.
   `TestLoadDigest_OrderIndependent` is the guard.
4. **Fail open.** A digest that cannot be computed means "rebuild", never "skip", and
   the digest is stored only after the graph swap succeeds — a failed rebuild retries
   rather than latching a baseline for a graph it never loaded.
5. **`SchemaVersion` participates**, so a schema bump with unchanged content cannot
   take a cheap path. The bump that shipped this change forced one full
   rebuild on deploy to establish the first baseline.

### Prerequisite fixes to the cheap path

`RefreshSignals` had never run and was broken in two ways, both fixed before the gate
was enabled:

- It refreshed only `:Asset` and `:IamRole`. `:K8sWorkload` carries the same seven
  signal columns and `:Package` carries its own five;
  neither was matched. This is the same omission `bfsScoreLabels` documents from the
  other side, where workloads served a stale score.
- It wrote `toxic_combo` straight from `sig.ToxicCombo`, which no `SignalSource`
  populates — it is derived at load time as `exposed && privesc_count > 0`. The first
  signal-only sweep would have zeroed it on every matched node.

A third bug was fixed alongside: `NodeSignals` checks its cache before Ladybug, and
`prewarmSignalCache` filled that cache from the raw rollup carrying `Exposed=false`,
so finding-bearing resources read as not-exposed and lost the synthetic exposure peer
that feeds AttackPaths/ToxicCombo. The fix changes scores.

## Consequences

- The ClickHouse read is still paid every sweep; a skip saves only the work after it.
  Avoiding the read would need a cheap upstream watermark, which the argument above
  shows cannot be made correct at the producer.
- `graph_ladybug_sync_total{path="full|signals|noop"}` makes the skip ratio observable,
  and the `GraphLadybugSyncAlwaysFullRebuild` alert flags the case where node count is
  flat but the gate still chooses a full rebuild. The metric is recorded inside
  graphstore rather than in the worker's closure, so a serve-pod rebuild appears on
  that pod's own `/metrics`.
- The serve replica inherits the gate by construction, since the gate lives below
  every caller. It stays `enabled: false` for the memory reason recorded in ADR 041.
- `sync_state.topology_version` still routes: when it has not moved since the
  last full rebuild, the caller takes the signal-only path (`worker_deps.go`), so a
  failed bump defers that sweep's topology to the next successful bump or a worker
  restart. Removing the counter, the bumper chain,
  `SetLastTopologyVersion` (no callers) and the table is a mechanical follow-up, kept
  separate so this change stays independently revertible.

Related: ADR 022 (the content-hash principle applied one layer up), 025/026 (the
graph), 037 (metrics), 041 (the pods that rebuild), 044 (why a missing asset's reach
data matters), 047 (the toxic-combo signal), 048/049 (why edge counts are not a
change signal), 071 (the worker memory budget).

## Amendment notes

### 2026-08-18 — the gate never fired; three-half digest and a durable baseline

Two independent causes kept the shipped gate from ever choosing a cheap path.

**Asset RiskScore was hashed into the topology half.** The node rows' `score` column
holds `asset.RiskScore` on Asset/IamRole/K8sWorkload/Subnet (`bfsScoreLabels`), and
RiskScore is rewritten between sweeps by construction — the collector base scorer,
CIEM `ScoredAssets` and correlate's `scoreAssetsFromFindings` all write it. The Topo
half therefore changed every sweep.

The digest now has three halves. `Scores` fingerprints (id, RiskScore) per
score-bearing node; the `score` column is skipped in the Topo hash via
`riskScoreColIdx`, derived from `nodeCSVCols` and pinned by
`TestRiskScoreColIdxMatchesLoader`. The Topo invariant becomes:

> Topo unchanged ⟹ the rebuilt graph would be identical in every column that is not
> refreshable in place. Only signal and risk-score columns could differ, and each has
> an in-place writer.

RiskScore could not simply be dropped: it is a BFS input (`computeBFSBoost` seeds
neighbour propagation from it) and named queries filter and order on `n.score`. A
Scores-half change takes a new cheap path, `refreshScores`: recompute every node's
post-BFS score in memory (`computeBoostedScores`), diff against a stash of what the
live graph holds (`Service.lastScores`, replaced wholesale on every build), and
UNWIND-SET only changed rows. Any failure falls through to a full rebuild; the stash
is updated only after every write succeeds.

A real topology change is still caught with the score value excluded:
`filterLadybugAssets` keeps `RiskScore > 0` assets and the digest covers the post-filter
slice, so a score change that alters membership adds or removes whole Topo rows.

`days_until_expiry`/`expiring_soon` stay in the Topo half: they are computed at
collect time and stored in asset metadata, so they change only when a collector
rewrites the asset — a genuine content change with no in-place writer.

FNV is byte-linear, so under a wrapping-add combine two independent changes can
cancel (demonstrated in a unit fixture: a `reachComplete` flip and the
`internet_hops` change it causes cancelled exactly). Every per-row hash is now
finalised with a splitmix64 avalanche (`mix64`) before the add; property 3 is
insufficient without it.

**The baseline did not survive a restart.** `lastDigest` was a process-local atomic,
so every worker restart forced a full rebuild even when warm-started from an
identical snapshot. The snapshot header's vestigial `TopologyVersion` field is
replaced by `TopoDigest`. `LoadFromSnapshot` recomputes the digest over the loaded
content and seeds `lastDigest` only when it matches the header; an algorithm change, a
zero header or a corrupt header all fail open into a full rebuild. `SchemaVersion`
was not bumped: gob tolerates the renamed field in both directions. The unused
`Service.WriteSnapshot`, which would have overwritten the snapshot with a header-only
file, was removed.

Each guard is mutation-verified (`internal/guardmutation/mutations_test.go`, "ladybug
rebuild gate" section).

### 2026-08-19 — two defects the gate introduced

Before the gate, a full rebuild every sweep overwrote any transient wrongness in the
graph. The gate removes that free repair, so two previously self-healing problems
became durable.

**A failed BFS write poisoned the score stash.** `propagateRisk` logged a failed
`UNWIND SET` and returned the boost map regardless, and the caller stashed it. The
next sweep's Scores digest then matched, and `refreshScores`' diff compared against
the same wrong stash, so nodes could serve wrong scores until an unrelated Topo
change. `propagateRisk` now returns `(map[string]uint8, bool)`. Withholding the stash
alone is not sufficient — with an unchanged corpus the Scores comparison still
matches and `refreshScores` is never called — so `scoresApplied` gates all three
digest latch sites (the full path's `lastDigest.Store`, the snapshot's `TopoDigest`,
and the snapshot-load seed). The cheap path's latch is gated on `refreshed`.
`TestDigestLatchIsGatedOnScoresApplied` guards the latch sites at source level.

**The in-place score refresh was unbounded.** `refreshScores` applied every changed
row in one `UNWIND SET` under the reader-blocking swap lock, and a cold stash or a
base-scorer sweep makes the diff the whole graph. `maxScoreRefreshRows = 25_000` caps
it; above the cap the caller falls through to the off-side full rebuild, which builds
on a separate handle and takes the lock only for the pointer swap.

Both fixes have behavioural tests in `score_refresh_test.go`
(`TestPropagateRiskReportsWriteFailure`, `TestRefreshScoresRefusesOversizedDiff`).
The write-failure fixture uses a Ladybug handle with no schema applied so the `MATCH`
returns a real error; a closed handle crashes inside the native library.

### 2026-08-19 (second) — the gate is correct and still cannot fire

With the defects above fixed, the gate decides "full" because the load set genuinely
differs between sweeps: `graph_ladybug_node_count` moves between sweeps, and the Topo
digest is an exact match over every asset row and edge. A content-digest skip gate
only pays off on a corpus that is sometimes static; on a continuously changing
corpus, consecutive sweeps practically never see an identical load set. A full
rebuild every sweep is therefore not waste — the graph really changed.

Consequences:

- **The lever for rebuild cost is a cheaper rebuild, not a skip.** First instalment:
  the metadata projection (`graphstore.SyncMetadataKeys` + `asset.decodeMapKeep`),
  so the loader decodes only the 13 metadata keys it reads instead of every key,
  including large permission blobs the graph never uses. A benchmark shows per-asset
  decode time and allocations falling by large factors.
- **The digest pre-pass now costs something for nothing**, since it runs
  `streamNodeRows` over the corpus every sweep to decide "full". Whether to keep
  paying for it is an explicit decision (taken in the next amendment).

Measurement note: `assets.discovered_at` is re-stamped on re-observation, not
first-seen, so churn derived from it measures collection activity, not arrivals —
the same defect ADR 024's amendment records for `findings.detected_at`. Use
`graph_ladybug_node_count` deltas for load-set churn.

### 2026-08-21 — where rebuild time goes; incremental recomputation rejected; gate kept

**The original cost split was wrong.** This ADR assumed the ClickHouse read dominated.
The four rebuild queries (`listAllForSyncQ` node load, reach-tier `graph_edges`,
signal rollup, context-tier `graph_edges`) run concurrently in one errgroup, with the
node load the slowest; together they are a minority of the rebuild. Most of the time
is spent after the COPY. Because the only rebuild signal was a whole-function
duration, this could not be decomposed after the fact.

`graph_ladybug_rebuild_phase_seconds{phase}` now marks eight boundaries in
`SyncFromSources` (`load`, `filter`, `reach`, `digest`, `copy`, `bfs`, `swap`,
`snapshot`), also emitted as `phase_*` fields in the completion log line.
`TestEveryDeclaredPhaseIsMarked` keeps a declared phase from going unmarked, and the
sync warns when phases fail to account for a tenth of elapsed time.

**Rejected: dirty-set incremental recomputation** (recompute only the closure of what
changed). Every derived signal is computed in Go without Ladybug reads (`bfs.go`), the
risk BFS is bounded (`bfsMaxDepth` 4, `bfsMaxNodes` 20) and reach is a bounded forward
BFS from internet seeds. It still fails for two independent reasons:

1. *The sound closure is effectively the whole corpus.* `computeBFSBoost` is bounded
   forward, but incremental recomputation needs the reverse set — which nodes' scores
   move when one node's base score changes. Y contributes to every X whose traversal
   visits Y (the undirected 4-hop ball), and `buildAdjIndex` orders neighbours by
   descending score with a `break` at `bfsMaxNodes`, so changing Y's score reorders
   neighbour lists one hop further. The closure is Ball_5(Y). Graphs with
   high-degree hubs (shared security groups, shared instance roles, the `internet`
   sentinel, `default` ServiceAccounts, shared base images, `dataclass:*` sentinels)
   put most nodes within a hop or two of a hub, and even without hubs a modest mean
   degree raised to the fifth power, multiplied by a typical per-sweep dirty set,
   saturates the graph. The guarantee is broken by any weight change, a change to
   `bfsMaxNodes`/`bfsMaxDepth`, a new loaded edge type, or any score written other
   than via `computeBoostedScores` (so `refreshScores` must remain the only other
   writer).
2. *Membership changes force the off-side rebuild anyway.* New nodes are structural,
   and in-place structural mutation of the engine is out of bounds (transactions are a no-op
   stub, with documented prepare-time crash classes). The graph is rebuilt from
   scratch, COPY loads base scores, and every boosted row must be written regardless.

Treating hubs as propagation barriers could reopen this, but `connected_via_sg` is
DirBoth on purpose (shared membership is propagated as an upper bound on reach; see
the ADR 026 amendment), so that changes
what a risk score means. BFS boosts saturating at the 30-point `bfsMaxBoost` cap for
many instances behind one large security group hints it deserves that argument — in
its own ADR against ADR 026.

**Decision: keep the gate unchanged.** Deleting the comparison would remove
`refreshScores`, `applySignals`, `lastScores` and the snapshot `TopoDigest` seed for a
benefit equal to the `digest` phase, which a benchmark shows is sub-second.
Re-scoping to snapshot integrity removes nothing, since the header digest exists to
seed the gate.

Shipped with this amendment:

- **The reach overlay is derived once per sweep.** `exposedSeedSet` and
  `internetHops` previously ran inside both `streamNodeRows` walks and again after the
  swap. They are now a `reachOverlay` computed once in `SyncFromSources`.
  `TestReachOverlayIsDerivedInOnePlace` pins this; `node_rows.go` documents that
  `exposed[id]` and `hops[id] == 0` are deliberately different predicates, so
  independent derivations risked classification drift.
- **The BFS score write no longer fans out across all four labels.** `propagateRisk`
  sent every row to all four `bfsScoreLabels` and relied on `MATCH` to discard the
  rest. Both it and `refreshScores` now use `scoreRowsByLabel`, routing each row to
  the label the loader gave that node (`NodeLabelFor` restricted to `riskScoreColIdx`,
  first occurrence wins — the same rule as `streamNodeRows`), preserving the
  abort-before-materialising order `maxScoreRefreshRows` depends on.
- The `GraphLadybugSyncAlwaysFullRebuild` alert description now points at the phase
  metric and narrows the actionable case to "node count is flat and the gate still
  says full".

**The dominant phase is the BFS score write.** A one-off phase-breakdown harness
replayed a large synthetic corpus through the real loader. The
`propagateRisk` `UNWIND SET` — one `MATCH (n:Label {id}) SET n.score` per boosted
node, in `unwindBatchSize` (5,000-row) batches — accounts for nearly all of the time
below the ClickHouse read. COPY, the snapshot gob+gzip, the digest, the filter, the
reach overlay and the in-memory BFS (`computeBoostedScores`) are each small by
comparison. This strengthens the rejection above: even a small closure would have
saved almost nothing.

**Not implemented:** remove the write. Because
`computeBoostedScores` is pure, it can run before `bulkSyncCopy`, with
`appendNodeValues` emitting the boosted score into the node CSV so COPY loads the
final value. There is no fixed point: a node's boost depends on its neighbours' base
scores. It is left for its own change because:

- The Scores half would fingerprint the boosted score rather than the base (strictly
  more sensitive, but a change in meaning).
- The `scoresApplied` mechanism collapses, since a failed COPY aborts the build;
  its three latch sites and their tests go with it.
- `bfsScoreLabels` merges into `riskScoreColIdx` — the seam that previously served
  stale K8sWorkload scores.

`refreshScores` keeps its `UNWIND SET` (the cheap path has no COPY). At the per-row
write cost the benchmark shows, the 25,000-row cap holds the swap lock far longer
than the code comment's "~100ms" estimate, so the cap must be revisited.

**Identified, not addressed here:** the node load `listAllForSyncQ` is a filtered
`SELECT … FROM assets FINAL WHERE …`, a pattern the project's ClickHouse guidelines
prohibit because skip indexes are disabled under FINAL (`use_skip_indexes_if_final`
is off). Both `graph_edges` reads also scan most of the table, so `EdgeFreshnessCond`
is not pruning on `synced_at`. Rewriting the node load to the `argMax … GROUP BY`
form in `internal/app/asset/repo.go` is the largest identified win. For graph-shape
analysis: dedup `graph_edges` on `(src_id, src_type, dst_id, dst_type, edge_type)`
(ADR 049 re-stamps unconditionally, so raw rows overcount), and scope to edge types
with `graph_ladybug_edge_type_rows{outcome="loaded"} > 0`, reproducing the loader's
`connected_via_sg` dst guard.
