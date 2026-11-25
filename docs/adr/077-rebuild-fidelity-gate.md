# ADR 077 — a rebuild publishes only a graph it can vouch for

**Status:** accepted (implemented 2026-08-21) · amended 2026-08-21 (four edge cases)

## Context

A Ladybug rebuild could publish a graph missing a large share of its edges and nodes while
every health signal stayed green.

The failure path: the bulk-tier edge read (`bulkEdgesQ`) can fail on ClickHouse's
**server-wide** memory limit (`Code: 241 … Memory limit (total) exceeded`) because of
unrelated concurrent load, even when the query's own memory use is modest.
`asset.AllEdgesForSync` caught the error, set `res.BulkPassFailed = true`, logged
`Warn().Msg("bulk pass failed — graph has critical edges only")` and **continued**,
returning the critical tier alone. Every bulk-tier type (`depends_on`,
`contains_data`, `dns_points_to`, `grants_access_to`, `assigned_to`, `peered_with`)
then loaded zero rows. Nodes were lost downstream: `filterLadybugAssets` prunes score-0
assets with no edges, so packages and DNS records whose only edge was bulk-tier fell
out of the graph. The degraded graph was served until the next healthy sweep. Raising
`syncBulkPerTypeLimit` (now 500,000) so `depends_on` is no longer silently truncated
did not cause the failure, but increased its impact.

Three things were wrong, and they compound.

**1. "Bulk edges are enrichment only" stopped being true.** The continue-on-failure
was written when the bulk tier was context topology whose absence broke no
attack-path query. `depends_on` now carries the supply-chain lineage the must-fix
classifier reads (ADR 044), and `contains_data` is the entire DSPM layer (ADR 047).

**2. The health signals could not express it.** `graph_ladybug_reach_complete` asks only
whether a Reach/Inherit edge *type* hit a fetch cap — and
`graphschema.TestReachAndInheritTypesAreCritical` pins every one of them to the
uncapped critical tier, so in any correct configuration it is the constant 1. It is a
tier-misconfiguration detector (a real one: it previously caught the three Inherit
types being starved by the bulk cap) named as a completeness signal.
`graph_ladybug_edges_dropped` counts drops at load time over the edges the fetch
returned; edges never fetched are never dropped. `GraphLadybugEdgeTypeStoppedLoading`
would have caught it, but only after its `for: 2h` — longer than a single-sweep
degradation lasts.

**3. Publishing was unconditional.** `SyncFromSources` already builds the replacement
graph off to the side and swaps it in atomically (ADR 041), but nothing used that
defensively: every candidate that finished building was swapped in.

This matters more here than in a typical dashboard: the post-BFS risk score and
`InternetHops` this graph serves feed enrich → `must_fix_class` (ADR 044) → respond,
and respond auto-executes cloud mutations (at the time; superseded by ADR 087 — nothing
state-changing runs without a human). A degraded graph's failure mode is action,
not a stale view.

## Decision

**A candidate rebuild that cannot vouch for its own load set is abandoned.** The gate
lives in `internal/app/graphstore/fidelity.go` and runs inside `SyncFromSources`
immediately after `filterLadybugAssets` — ahead of the ADR 074 digest gate, so a degraded
load set cannot take any path (full rebuild, signal refresh or no-op), and ahead of
`openAndInit`, so a refusal costs only the ClickHouse read rather than also COPY, BFS
and snapshot. A refusal returns `ErrRebuildRefused` and the correlate job fails
visibly; worker container logs are short-lived, so a log line is not a record.

Two layers, and only the first is unconditional.

### Layer 1 — a self-reported partial fetch never publishes

`asset.EdgeSyncResult.FetchComplete()` = `!BulkPassFailed && len(TruncatedTypes) == 0`.
This is a report of an error, not a heuristic: it cannot false-refuse a legitimate
estate change, needs no baseline, and works on a cold start. It is excluded from the
accept-on-repeat rule below — when the edge set is known to be incomplete,
repetition changes nothing (see the 2026-08-21 amendment for the cold-start
exception).

### Layer 2 — a shape check against the last published build

For degradations that do not self-report: a partial correlate sweep (ADR 049's
amendment — incomplete producer output deletes topology), a producer that stopped
emitting, a silent truncation. Three rules, compared against the last published build's
`graph_ladybug_edge_type_rows` and `graph_ladybug_node_count`. The thresholds are set wide
of ordinary sweep-to-sweep churn (re-tune them from those two series if a deployment's
churn is larger):

| rule | threshold (constant) |
|---|---|
| total fetched edges vs baseline | ≥ 0.85 (`minVolumeRatio`) |
| post-filter assets vs baseline | ≥ 0.85 (`minVolumeRatio`) |
| a synced type with baseline ≥ 50 rows fetching **zero** | refuse (`minTypeBaselineRows`) |

Legitimate builds stay well within the volume ratios. The per-type rule is a **zero**
rule, not a relative one, deliberately: genuine per-type churn for types such as
`can_escalate_to` and `has_policy` is large enough that any relative floor tight
enough to catch a degradation would refuse healthy builds constantly. Total
disappearance of an established type is the discriminating signal. Types whose
registry tier is `TierUnsynced` are exempt, so retiring a type on purpose (as
`runs_in`, `member_of_zone`, `in_subnet` and `in_vpc` were) never reads as loss.

### The trade: freshness for correctness

A refused rebuild costs **freshness**: the previous graph is at most one correlate
interval old (`jobs.defaultCorrelateInterval`, 30m) and is complete. An accepted
degraded rebuild costs **correctness**: it is incomplete by an unknown amount and every
consumer treats it as whole. Staleness is bounded and alerted
(`GraphLadybugRebuildStalled` at 4h, plus `GraphLadybugPublishRefused` at `for: 15m`);
incompleteness was not observable at all.

The false-refusal case that matters is a **legitimate large change** — an account
purge, an intentional prune, a decommissioned connector. Thresholds cannot tell that
apart from a degradation, because both are a step. So the gate **refuses once and
accepts the same shape on the next sweep** (`sameShapeClass`: identical set of
vanished types, totals within 5% — `repeatVolumeTolerance`). A transient failure does
not reproduce and so never publishes. A real change publishes one sweep late, at
`Error` level, with `graph_ladybug_publish_degraded_accepted_total` incremented so that
someone confirms it was intended.

"The next sweep" is enforced in **wall-clock time** (`minRepeatAge`, 25 min), not just
shape equality. Otherwise a refusal returns an error, River retries `ladybug_rebuild`
within seconds, the retry re-reads ClickHouse, produces the identical degraded shape
and satisfies "arrived twice" before the transient has had any chance to clear.
"Twice" has to mean two independent observations.

This is why the gate cannot wedge the platform: an impossible classification becomes
a one-sweep freshness cost.

### First boot / no baseline

Fails **open** on Layer 2 and keeps Layer 1. With nothing to compare against, refusing
would mean the platform can never establish a graph. A restart is not a first boot:
`LoadFromSnapshot` seeds the baseline from the snapshot's own asset and edge slices,
which are the last published graph, so the gate stays armed across worker restarts. No
new snapshot field and no `SchemaVersion` bump were needed.

### Signals

- `graph_ladybug_reach_complete` → **renamed** `graph_ladybug_reach_edges_untruncated`, with
  help text stating what it can and cannot see.
- `graph_ladybug_edge_fetch_complete` — **new**, the completeness signal the old name was
  mistaken for.
- `graph_ladybug_publish_refused_total`, `graph_ladybug_publish_degraded_accepted_total`,
  `graph_ladybug_last_publish_refusal_timestamp_seconds` — **new**. The refusal counter
  cannot move unless the gate fires.
- `graph_ladybug_edges_dropped` — help text now states its scope (load-time only) and
  points at the fetch-side signals.

New alert rules (`GraphLadybugPublishRefused`, `GraphLadybugEdgeFetchIncomplete`,
`GraphLadybugDegradedGraphAccepted`), plus `GraphLadybugEdgeVolumeCollapse` (`for: 10m`) as
defence in depth on aggregates alone, so it still fires if the in-process gate is
bypassed entirely (an old binary, a rollback, the serve pod's own sync loop). Before
changing that expression, replay recorded metric history through a PromQL-compatible
engine and confirm it fires on degraded builds and stays silent on healthy ones.

## Consequences

- The off-side-build-and-atomic-swap property is unchanged and is now load-bearing: it
  is what makes abandoning a candidate free.
- A persistent upstream failure now **freezes** the graph rather than degrading it,
  with alerts firing. That is intended, and it is a real operational cost.
- `AllEdgesForSync` keeps its continue-on-bulk-failure. It is no longer dangerous
  (nothing downstream publishes the result) and removing it would lose the
  `BulkPassFailed` signal the gate reads. What changed is who decides.
- The underlying trigger is untouched: if ClickHouse runs close to its total memory
  limit, an unrelated concurrent query can still fail the bulk edge read. The gate makes
  that a visible staleness event instead of a silent correctness one; sizing ClickHouse
  memory, or reducing `depends_on` volume (most package dependency edges carry no
  findings), is separate work.
- Two guards, one mutation: `TestSyncFromSources_AbandonsADegradedRebuild`
  (behavioural — the previous graph must still answer) and
  `TestFidelityGateAbandonsBeforeAnySideEffect` (source — every publishing side effect
  stays below the gate, and the refusal branch returns). The catalogued mutation deletes
  the return, which is exactly the original defect: log and continue.

Cites ADR 037 (the metrics), 041 (the off-side build and atomic swap), 044 (the
must-fix consumers of the reach signal), 047 (contains_data / DSPM), 048 (the registry
the tier exemption reads), 049 (its amendment: partial producer output deletes
topology, and an edge count is never a change signal), 074 (the digest gate this sits
in front of).

## Amendment notes

### 2026-08-21 — four edge cases found on review

Review after ship found three refuse-forever traps and one crash hazard. All four are
fixed in `graphstore/fidelity.go` and `graphstore/fidelity_persist.go` (new); none
weakens a refusal — each narrows an escape to exactly the condition that makes it safe,
or makes the gate's own memory durable.

1. **A `SchemaVersion` bump disarmed Layer 2 for the riskiest build.** `ReadSnapshot`
   rejects a stale-schema file, so `LoadFromSnapshot` returned before seeding the
   baseline, and the first build after a deploy ran with Layer 2 in first-boot
   fail-open. Fixed with `ReadSnapshotShapeAnyVersion`, which decodes the same file
   ignoring `SchemaVersion` and returns only its `fidelityShape` — used only to arm the
   baseline, never to warm-start the graph. A version bump gates Ladybug's DDL or loading
   set, not the ClickHouse row counts Layer 2 compares. A stale-but-close baseline can
   only make Layer 2 refuse more readily, never publish falsely.

2. **Layer 1 had no escape on a cold start.** Under sustained ClickHouse pressure with
   no previous graph, refusing forever means no graph at all — worse for every read
   path, and no worse for respond's auto-execute safety, since with nothing built
   `must_fix_class` never fires. Fixed narrowly: a Layer-1 failure may publish on
   repeat only when `noGraphServed` is true (`!s.synced.Load()` — nothing has published
   in this process or its warm-started predecessor). Once that publish happens,
   unconditional refusal resumes.

3. **A monotonic legitimate decline never satisfied `sameShapeClass`.** A multi-day
   teardown shrinks by more than `repeatVolumeTolerance` every sweep, so accept-on-repeat
   never fired. Fixed with a second rule: `monotonicDeclineStreak` (3) consecutive,
   independently-timed refusals, each a further decline on the one before, confirm a
   trend and publish the latest. Three, not two, because a ramp's shape never repeats,
   so a single comparison cannot tell "declining trend" from "dipped and about to
   recover". Excluded from Layer-1 failures for the same reason as the step rule.

4. **A crash between a refusal and its repeat wiped the clock.** `fidelityState` lived
   only in memory, so a worker restart reset `minRepeatAge`, and repeated restarts
   could wedge a step or decline indefinitely. Fixed by persisting the refused shape,
   decline streak and wall-clock timestamp to a small gob sidecar next to the topology
   snapshot (`fidelity_persist.go`), written on every refusal, cleared on every publish,
   and restored by `LoadFromSnapshot` before the snapshot read. Deliberately not gated
   by `SchemaVersion`. A decode or read failure fails open into "nothing pending" —
   one more refused sweep, never a false publish.

The gate's memory is now split: `seedBaseline` (arms the Layer-2 comparison point
only) versus `publishedShape` (arms the baseline and clears any pending refusal).
`LoadFromSnapshot` uses `seedBaseline`, since a snapshot load is not a fresh decision
and must not discard a refusal restored by case 4.

Observability: `graph_ladybug_publish_degraded_accepted_total` gained a `reason` label
(`step` | `cold_start` | `monotonic`); `sum without (reason)` reproduces the
pre-amendment series.

New tests: `TestCheckFidelity_NoBaselineButSnapshotShapeArmsLayer2`,
`TestLoadFromSnapshot_SchemaBumpArmsBaselineFromShapeNotGraph` (case 1);
`TestCheckFidelity_ColdStartEscapesLayer1OnRepeat`,
`TestSyncFromSources_ColdStartPublishesADegradedGraphOnRepeat` (case 2);
`TestCheckFidelity_MonotonicDeclineAcceptsAfterThreeShrinkingSweeps`,
`TestFidelityState_RecordRefusal_TracksDeclineStreak` (case 3);
`TestFidelityPersist_WriteReadClearRoundTrip`,
`TestFidelityPersist_EmptySnapshotPathIsANoOp`,
`TestLoadFromSnapshot_RearmsAPendingRefusalAfterACrash` (case 4).
`TestFidelityGateAbandonsBeforeAnySideEffect` still holds because the new calls
(`clearRefusalRecord`, `writeRefusalRecord`) sit adjacent to the literal
`s.fidelity.publishedShape(cand)` and `return fmt.Errorf(...ErrRebuildRefused...)`
strings it scans for.
