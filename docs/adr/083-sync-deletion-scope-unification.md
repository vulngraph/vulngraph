# ADR 083 — Sync's deletion path needs the same scope discipline as ADR 081's forget engine

**Status:** accepted — implemented as an additional narrowing behind the existing `Partial`
gate (see Implementation note)

## Context

Two deletion-adjacent decisions exist in this codebase, built at different times for different
reasons, and they did not share a notion of scope.

**`internal/app/forget`** (ADR 081) is the careful one: per (connector, scope, type), it reads
ADR 054's `collect.Result.CompletedEnumerations` — the signal that says which scopes a
collector PROVED it enumerated completely this sweep — and refuses to act on anything else. It
stacks six refusals (unaudited family, partial sweep, unknown/truncated edge health,
unconfirmed absence, population floor, relative/absolute caps) before it will consider a
candidate, and even then it only writes a recoverable tombstone, never a delete, never a
finding resolution.

**The sync worker's own deletion reconciliation** (`internal/jobs/sync.go`) predates it and did
neither. Its gate was a single connector-wide boolean:

```go
deletedIDs := findDeletedAssets(currentHashes, res.Assets)
...
if !res.Partial {
    if len(deletedIDs) > 0 {
        w.connectors.DeleteAssetHashes(ctx, c.ID, deletedIDs)
        resolveFindingsForDeletedAssets(ctx, w.findings, deletedIDs)
    }
}
```

An earlier fix had already stopped `forget`'s own `evaluateForget` from being gated on
connector-wide `Partial` (routing it through per-scope delivery cross-checks), but deliberately
left `findDeletedAssets` untouched.

`findDeletedAssets` was a flat set-difference — every stored asset-hash id absent from this
sweep's collected set, with no per-type or per-scope distinction — and `res.Partial` is one flag
for the ENTIRE connector. A connector runs many collector families across every enabled region,
so:

- a single flaky best-effort family poisons the boolean, and deletion reconciliation for the
  whole connector stops for that sweep; a connector that is persistently `Partial` never
  reconciles, so findings on genuinely deleted resources never resolve with
  `ReasonResourceGone`;
- the inverse is the dangerous case — a connector reporting `Partial=false` overall while one
  family silently truncated still runs this path unscoped, deleting hashes and calling
  `finding.Resolve(..., ReasonResourceGone)` for every type that family touches, whether or not
  that type was proven complete this sweep.

The current mechanism cannot tell a genuinely deleted resource (where it produces false
negatives — findings that should close, don't) from a transiently uncollected one (where a
scope-blind reconciler produces false positives — the class of mistake ADR 081's Context
describes), because it is never given the information that would let it.

`collect.Result.CompletedEnumerations` / `MarkComplete` (ADR 054's 2026-08-21 amendment) exists
to fix this granularity problem; its doc comment stated that nothing yet consumed it as
permission to delete. ADR 081 built refusal thresholds on it, but for a separate, tombstone-only
mechanism, and explicitly deferred wiring anything to `findDeletedAssets` to "a separate, later
decision with its own review". This ADR is that decision.

## Decision

**Make the sync worker's deletion reconciliation scope-aware, using `CompletedEnumerations`,
rather than building a second refusal engine alongside `forget`'s.**

The two mechanisms answer different questions and should keep doing so:

- `forget` (ADR 081) asks "may I assert this asset is gone, durably enough to write a tombstone a
  later decision can act on?" — a narrow claim over a small hand-audited set of types,
  deliberately slow to widen.
- Sync reconciliation asks the question ADR 054 already answered "yes" to for every connector:
  "did THIS sweep's own collector prove it looked at this resource's type in this scope, and is
  it gone?" — the question `findDeletedAssets`/`resolveFindingsForDeletedAssets` has always been
  trying to answer, at the wrong granularity (per-connector instead of per-scope-and-type).

Routing sync through `forget.Service` would collapse two engines with different lifecycles (one
keyed on `connector_asset_hashes` rows refreshed every sync, the other on `forget_scope_state`
history accumulated over weeks) and impose `forget`'s much more conservative posture (caps,
confirm windows, an uncalibrated shrink guard) on a lifecycle action that has been resolving
findings on deleted resources since ADR 054 shipped. The fix is narrower: gate
`findDeletedAssets`'s candidate set by the per-scope-and-type coverage derived from
`res.CompletedEnumerations`, so an absent id is only a deletion candidate when its stored type
(and region, for region-scoped families) was covered by a scope this specific sweep proved it
fully enumerated. A family that never calls `MarkComplete` reconciles nothing — a strictly safer
default that fails toward "reconciles nothing" for an unproven family, never toward "reconciles
based on an unrelated family's success."

| | `forget` (ADR 081) | sync reconciliation (this ADR) |
|---|---|---|
| Question | may I durably assert "gone"? | did THIS sweep prove this type's absence? |
| Action on yes | tombstone (recoverable, inert until consumed) | delete hash row + resolve finding (ADR 054's existing lifecycle action) |
| Scope | 5 hand-audited types, 2 enforced | every (region, type) a completed scope covers |
| Refusal thresholds | 6, calibrated against `forget_scope_state` history | the scope test, plus an absolute per-sweep cap |
| Cost of a false positive | none until a tombstone is consumed | a finding closes and an asset hash is pruned; self-heals only if the resource reappears and re-syncs |

The cost asymmetry in the last row is why this ADR does NOT lift forget's full refusal set into
sync. Sync's action is long-standing and load-bearing, its failure mode (a wrongly resolved
finding) is an accepted risk with an existing mitigation (ADR 055's dangling sweep re-detects from
scratch), and importing forget's posture wholesale would change behaviour on every connector.
What is imported is the one test that addresses the defect — proven-scope membership.

**Rejected: unifying the two engines into one.** The cost/lifecycle asymmetry between a tombstone
and a finding resolution is a permanent property of the two decisions, not a temporary
implementation gap.

## Not decided here

- **Widening `MarkComplete` coverage.** A collector reconciling nothing because none of its scopes
  is proven complete is the correct, safe default under this decision. Earning coverage for an
  additional collector family requires auditing its pagination and error handling — the same
  caveat ADR 081 states for widening `enforceableFamilies`.
- **Retroactively resolving stranded findings.** Whether a backstop sweep should re-evaluate an
  existing backlog once the scope-aware gate ships, or let it self-heal as covered scopes
  accumulate, is an operational question informed by how much of the backlog is genuinely gone
  versus live behind an uncovered scope.

## What would falsify this decision

- If, once coverage is measured against real sweeps, most connectors' types are still never
  covered by any scope, scoping reconciliation this way converges toward "reconciles almost
  nothing" — safe, but it makes a stale-finding backlog permanent, and a dedicated, ADR-055-style
  re-detection sweep for the uncovered majority would be the better fix.
- If a scope-aware gate still lets through a wrong deletion on a covered type whose collector's
  completeness claim was wrong (a `MarkComplete` call that lied), that is a defect in the
  collector, but if it recurs across collectors it argues for importing more of `forget`'s
  refusals.

## Consequences

- Sync's deletion reconciliation stops being all-or-nothing per connector and becomes granular
  per proven-complete scope and type — the same shift ADR 081 made for `forget`, applied to the
  mechanism ADR 081 declined to touch.
- The two deletion-adjacent decisions remain two decisions, sharing one input signal
  (`CompletedEnumerations`), the scope grammar (`forget.ParseScope`), and borrowed constant
  values — not one engine.

## Implementation note

The landed code (`internal/jobs/sync_deletion_scope.go`, called from `internal/jobs/sync.go`)
differs from the decision above in three ways:

- **`res.Partial` remains the outer guard.** Scope coverage (`coveredScopes` → `isCovered`, keyed
  on (region, type), with a region-independent wildcard for non-region-scoped families) is an
  ADDITIONAL narrowing on a non-`Partial` sweep, not a replacement. This closes the dangerous
  case (an unproven type reconciled on a clean-looking sweep) but does not yet make findings
  behind a persistently `Partial` connector reachable.
- **Coverage is limited to `forget`'s audited families.** `coveredScopes` parses scopes with
  `forget.ParseScope` and iterates the audited family's own type list, so a collector cannot
  widen its deletion authority by claiming types; an unrecognised scope contributes no coverage.
- **An absolute per-sweep cap is applied.** `deletionCap` reuses `forget.MaxForgetPerSweep`'s
  value (500). A candidate set above the cap is refused entirely for the sweep, not trimmed, and
  logged with both numbers. Suppressed candidates are logged split into `untyped` (stored type not
  yet backfilled) and `uncovered` (no completed scope proved that (region, type)).

Extends ADR 054 (the lifecycle action this ADR scopes) and its 2026-08-21
`CompletedEnumerations` amendment (the signal this ADR consumes for a live decision).
Deliberately does not merge with ADR 081. Cites ADR 055 (the dangling-finding sweep as a
complementary backstop) and ADR 080 (unmeasured is not zero — an unproven scope is treated as
"not covered", not "safe by omission").
