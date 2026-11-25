# ADR 067: Scoring-integrity pipeline — kill reach-poisoning at the source, don't just patch the adjudicator

**Status:** accepted (2026-07-19) · amended 2026-08-26 (same-account identity mesh scored once)

## Context

The node-signal cache in `internal/app/graphstore` is pre-warmed from the finding-signal
rollup (`SignalsByResource`), a struct that never sets `InternetHops`. Go's zero value for
`int` is `0`, and `0` is the semantically loaded value "directly internet-exposed (0-hop)",
not "unknown" (`ReachUnknown = -2`) or "unreachable" (`ReachNone = -1`, both defined in
`internal/app/graphstore/service.go`). Every pre-warm path (`LoadFromSnapshot`,
`RefreshSignals`, `SyncFromSources`) therefore cached `InternetHops = 0` for every
finding-bearing resource, overwriting the real BFS reach computed each correlate sweep.
Enrich read this value as ground truth.

Effect: reachability-relevant findings, especially on IAM principals, scored as directly
internet-reachable, inflating `internet_reach` (+18) and `toxic_combo` (+20 pipeline floor)
and pushing privesc findings on non-exposed principals (for example an outbound-only
`can_assume` role with no `exposed_to_internet` edge) to the top of must-fix/page. The
failure was self-reinforcing: the adjudicator's corroboration gate used
`ReachabilityEvidenced` — the same poisoned signal — as its "independent" witness against
demotions, so it defended the false-highs it existed to catch. Fixing only the adjudicator or
only the cache would have left the other half of that loop intact.

## Decision

Defense in depth across four phases. Phases 0 and 1 each independently break the false-high
loop at runtime; Phase 2 does too when the adjudicator runs, which it does only with
`ADJUDICATOR_ENABLED` set (`cmd/graph/worker.go`; off by default). Phase 3 detects a regression: metrics, unit tests in CI, and an opt-in
`-tags=eval` golden gate.

**Phase 0 — make unknown-reach-as-0-hop unrepresentable.**
`graphstore.NewNodeSignals()` (`internal/app/graphstore/reach.go`) defaults `InternetHops` to
`ReachUnknown`; both signal-build call sites (`cmd/graph/worker.go`, `cmd/graph/serve.go`) use
it. `prewarmSignalCache`/`setLastHops` overlay the authoritative BFS hops from the last
topology build (`internetHops(edges)`) onto the rollup instead of trusting its zero value.
INV-1 is enforced at the reach seed: `internetHops` drops any `exposed_to_internet` edge whose
source is an identity type — a type registry, `graphschema.IsIdentityType`/`IdentityAssetTypes`
in `internal/graphschema/graphschema.go` — and reports the drop count via
`Service.identityZeroHop`. `buildNodeRows` (`internal/app/graphstore/repo.go`) applies the same
filter to the node `Exposed` flag. `readSignals` treats a node missing `internet_hops` as
`ReachUnknown`, and `clampInternetHops` collapses out-of-domain values to `ReachUnknown`.
`enrich.IsIdentityResource` (`internal/app/enrich/mustfix.go`) derives from the same registry
instead of duplicating the type list (keeps ADR 010 layering intact).

**Phase 1 — per-finding scoring-consistency gate at enrich.** `reconcileConsistency`
(`internal/app/enrich/consistency.go`), a pure function between scoring and persist, checks
INV-1 directly: if a finding's resource `IsIdentityResource` and its score carries a factor
with `Source == sourceInternetReach && Points == directExposurePoints`, it strips that factor,
re-aggregates the band, and clears any `must_fix`/`elevated` class gated on
`ReachabilityEvidenced`. Every branch only strips or demotes, never inflates. Wired into
`enrich.Service.Enrich` via `WithConsistencyGate(enabled, shadow, observe)` (default on; shadow
mode logs without applying, for safe rollout of future invariants).

**Phase 2 — the adjudicator verifies against an independent witness.**
`belief.GroundingFacts` gains `ExposedEdgePresent` (`internal/app/belief/fidelity.go`): a fresh
re-query of the resource's own `exposed_to_internet` edge (`asset.IsExposedEdge`, via an
`ExposedEdgeLookup` on `AdjudicateWorker`), deliberately a different lineage than the cached hop
count. `corroborationConflict` is inverted: `ReachabilityEvidenced` alone no longer vetoes a
demotion; a veto requires an independent witness, checked in priority order
`PublicAccessConfirmed` > `ExposedEdgePresent` > `ExposureConfirmed`. The witness is rendered
into the LLM prompt as a "STRUCTURAL CONTRADICTION EXCEPTION", permitting refutation of a direct
0-hop claim only when the fresh edge lookup and the internet-facing check both agree it is false
— narrow enough not to reopen the general identity-trust-path trap.
`belief.NeedsAdjudication` still excludes `must_fix` by design; a poisoned Critical becomes
adjudicable because Phase 1 demotes its class to `""`, not by loosening this gate.

**Phase 3 — observability, CI unit tests, and a manual eval gate.** `internal/obs/metrics.go` adds
`graph_ladybug_identity_zero_hop` (gauge, must stay 0; from `Service.IdentityZeroHop()`),
`graph_ladybug_reachability_rate` (gauge — fraction of the cache at hops 0–3; a spike toward 1.0 is
the leading symptom of this bug class), and
`graph_enrich_consistency_violations_total{invariant}` (counter — nonzero means a Phase 0
regression). Both graphstore gauges are pulled on scrape via `cmd/graph/worker.go`'s
`liveCollector`. CI locks in the semantics (`internal/app/graphstore/reach_test.go`,
`consistency_test.go`, `fidelity_test.go`), and the golden eval in
`internal/reason/adjudicate_eval_test.go` (`//go:build eval`, makes real model calls)
hard-fails on more than one miss (`adjMaxMisses`; previously log-only) when run, with a
golden case for the structural-contradiction exception. It runs only by manual dispatch of
`.github/workflows/eval.yaml`, behind the protected `production` environment, never on
push/PR (see ADR 038).

**Related, not part of this decision.** The same review pass fixed GuardDuty `!DNS` findings
bypassing the corroboration gate via family-name matching (same code path, different bug
class), and produced a separate hardening batch (CIEM boundary intersection, OSV reconcile
lower bound, SCP eligibility fail-open).

## Consequences

- Fail-safe throughout: every new path can only strip signal or under-score. A bug in this
  pipeline degrades toward false negatives, not false positives — an intentional trade-off
  given the cost of false-highs.
- The Phase 1 gate is a redundant safety net expected to fire zero times in steady state; a
  nonzero `consistency_violations_total` is a Phase 0 regression signal.
- The eval's 90% threshold is now a hard failure rather than log-only, but it is a manual
  pre-merge gate for prompt or fidelity changes, not part of push/PR CI. Nothing mechanically
  forces it to run, so it must be dispatched before any prompt, model or fidelity change.
- `ReachabilityStats()` is a lock-free full pass over the node-signal `sync.Map` per scrape:
  O(cache size), cheap, and documented in `reach.go`.
- Post-deploy check: the page-band count should drop as false-highs clear, and principals with
  no exposure edge should leave must-fix/page.

## Amendment (2026-08-26): blast radius of a same-account identity mesh no longer scores as N independent targets

Same defect class, different source. `enrich.blastPoints` (`internal/app/enrich/sources.go`)
counted reachable assets from `BlastRadiusCounter` (Ladybug, primary) or `BlastRadiusProvider`
(ClickHouse, fallback) as a single integer. At `blastDepth = 2`
(`graphschema.BlastDepth`) the walk crosses the GCP service-account impersonation mesh, which
is project-wide rather than finding-specific: a privesc finding reported the project's whole
service-account population as its blast radius, putting every privesc finding in a large
project into the top scoring tier together, indistinguishable from a finding that genuinely
reaches many independent targets across accounts.

**A first same-day fix was redesigned rather than patched.** It capped only the dominant
account, gated the breakdown behind a magic count threshold, and rescaled a ClickHouse
breakdown from a different walk onto Ladybug's count by ratio. Review found it:

1. non-monotonic at the threshold (a larger single-account radius could score lower);
2. justified by a false claim about which tiers counts below the threshold land in;
3. non-deterministic per finding (the same finding scored differently depending on whether Ladybug
   was available);
4. combining a count from one engine's BFS with an account distribution from another's, which
   could demote a genuinely broad finding over a cluster that existed only in the other walk;
5. able to emit a `Detail` claiming a cap that never fired (integer truncation in the scaled
   cap);
6. covered by tests that did not discriminate "cap the dominant account" from "cap every
   account".

**Redesign:**

- **The only count cutoff is exact.** `blastAccountCap` (3) is also the only cutoff
  `confirmBreakdown` uses to skip the ClickHouse round trip: a breakdown cannot change the score
  of a count at or below the cap, because summing `min(contribution, cap)` per account is a
  no-op there.
- **No cross-engine rescaling.** Whenever a ClickHouse breakdown is fetched (via
  `confirmBreakdown` on the Ladybug path, or directly on the fallback path), its own total
  (`BlastBreakdown.Total`) replaces `n`. Count and breakdown always come from the same walk, or
  the breakdown is nil and Ladybug's raw `n` is used. `asset.Service.BlastRadius`
  (`internal/app/asset/service.go`) already returns the hydrated asset list with `AccountID`, so
  no new query is needed.
- **`Detail` is built by the same function, from the same variables, as the score**
  (`blastPoints` returns `(points int, detail string)`).
- **Every account is capped independently:** `effective = Σ min(count, blastAccountCap)` over
  `ByAccount`. Two independent meshes are as much shared-identity fan-out as one large one.
- The unreachable `if capped < 0` guard is removed.

`graphstore` was deliberately not touched (ADR 010 layering). Determinism is structural: the
Ladybug-primary and ClickHouse-only paths produce the same `(n, breakdown)` pair for the same data
at every count.

**Cost trade-off.** Removing the threshold means `BlastRadius.Evaluate` attempts a ClickHouse
breakdown for any finding whose reach exceeds `blastAccountCap`, a larger population than
before; `BlastRadius` runs as a scoring `Source` on every open finding. Several findings often
share a `resource_id`, so a per-sweep, per-resource cache is a real opportunity, but it is not
built here: `BlastRadius` is instantiated once per worker process (`cmd/graph/worker.go`) with
no sweep-boundary hook to invalidate against, and the eligible population could not be sized
without running the BFS itself. It is a follow-up if enrich's ClickHouse load becomes a
measured problem.

**Tests** (`internal/app/enrich/sources_test.go`): `TestBlastPoints_AccountBreakdown`
(including two independent over-cap clusters), `TestBlastPoints_Monotonic` (defect 1),
`TestBlastRadius_Determinism` (defect 3, above and below the cap),
`TestBlastRadius_ClickHouseAuthoritativeAboveCap` (defect 4),
`TestBlastRadius_GCPServiceAccountMeshRegression` (the original case end to end), and
`TestBlastRadius_BroadCrossAccountStaysHigh` (every account individually over the cap still
sums to a top-tier score).
