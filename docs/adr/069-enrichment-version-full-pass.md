# ADR 069: Version-triggered full re-enrichment — feed the idle path, don't build a second one

**Status:** accepted (2026-07-28)

## Context

ClickHouse is supposed to hold the current truth about every finding; it is how the product
answers "did this fix work?". Without a version trigger, a change to enrichment logic does not
reliably reach existing findings, and enrichment for findings on unchanged assets goes stale.

Two independent mechanisms combine into the gap:

1. **Findings are only enqueued when a check re-emits them.** ADR 022 runs CSPM checks on
   changed assets only (`internal/jobs/sync.go`), so a finding on an unchanged asset is never
   re-emitted, never stamped `last_observed_at`, and never enqueued for enrich. The enrich
   change-gate's 24h freshness backstop (ADR 024) never fires, because no job is created for it
   to gate.
2. **A logic change invalidates the cache but enqueues nothing.** `enrichcache.Fingerprint`
   carries a version prefix, and its changelog states the rule: bump it or findings keep their
   stale pre-fix score. But the prefix only makes an enrich recompute once it runs; it cannot
   cause a run.

Consequences of that gap: enrichment age tracks re-observation, not logic changes; a
classifier change shipped without a version bump can leave many findings serving their pre-fix
must-fix class long after the classifier was corrected; and `enrich_sweep`, the designed
backstop, is capped at `enrichSweepMax = 2500` per tick (`defaultEnrichInterval`, 15 minutes),
which bounds how fast it can cover a large corpus.

### The analysis that decided the design

The obvious reading is "the pipeline is too slow; build a faster one". Job timings point the
other way: the enrich workers (`enrichWorkers = 10`) can sit idle most of the time while the
corpus goes stale. The pipeline is starved, not slow. The long full-pass estimate was the sweep's
budget, not the pipeline's capacity; conflating the two would have justified building a second
scoring path to fix a scheduling problem.

## Decision

**A version-triggered, self-pacing pass that feeds the existing per-finding enrich path.**

1. **One version constant, two roles.** `enrichcache.LogicVersion` prefixes the input
   fingerprint and is compared against a Postgres watermark recording the version a full pass
   last completed for (the `enrich_logic_version` table). Two constants could disagree
   and half-apply a change; `TestLogicVersionDrivesTheFingerprintPrefix` recomputes the hash
   independently so `Fingerprint` cannot silently stop using it.
2. **Boot trigger.** `jobs.TriggerFullPassIfVersionChanged` compares deployed against stored and
   enqueues round 0. The insert is raw SQL guarded by `WHERE NOT EXISTS (… state IN available/
   pending/running/retryable/scheduled)`: River's `UniqueOpts` cannot help before the client
   starts, and a crashlooping worker would otherwise start a fresh pass per restart.
3. **Self-continuing rounds, not one long job.** Each round takes a chunk of open findings
   behind the cutoff, `InsertMany`s an enrich job per finding, and schedules the next round
   after `reenrichRoundDelay` (5 minutes). Each round runs for seconds; pacing lives between
   rounds.
4. **Termination is "no open finding is older than the cutoff".**
5. **The cutoff is stamped once and carried.** Re-deriving "now" each round would chase its own
   tail and never end.
6. **Paced to the pessimistic drain rate.** A version bump defeats the change-gate, so during a
   pass every job does real work. `reenrichChunk` is sized below the worst-case drain rate so
   queue depth trends down; pacing against the average job time (which includes cheap gate
   skips) would enqueue well above the real drain rate and rebuild the kind of backlog that has
   previously exhausted worker memory. `TestReenrichPacingDrainsEachRoundAndFinishesWithinADay`
   asserts that each round's chunk fits within an assumed pessimistic drain rate (4/s, a
   constant in the test, not a measurement) over the round delay, and that a full pass
   finishes within a day.
7. **Backpressure and a runaway backstop.** A round is skipped and rescheduled when the enrich
   queue exceeds `reenrichQueueCeiling`. `reenrichMaxRounds` stops a pass that never converges
   and deliberately does not advance the watermark, because the corpus has not converged.

The current values of these constants, and the reasoning for each, live in
`internal/jobs/reenrich.go`.

## Alternatives rejected

**A bulk-compute pass (minutes instead of hours).** Preload the graph and asset context once,
score in memory, bulk-write. The read side is feasible (projecting the handful of metadata keys
enrichment reads shrinks the asset payload dramatically). Rejected anyway:

- It needs a second set of providers that must never disagree with the live ones, forever.
  During prototyping the equivalence test passed with a deliberately broken reach provider,
  because INV-1 (ADR 067) masked the fault — the guarantee is subtle enough to give false
  confidence.
- It rewrites every row from one snapshot, so one degraded provider poisons the whole corpus at
  once. The per-finding path fails open per finding.
- Its benefit depended on an unmeasured cost (a Ladybug blast-radius traversal per finding) that
  could only be measured by building it.
- Hours is sufficient. Fix verification is not a sub-minute loop.

**Raising `enrichWorkers` / lowering the sweep interval.** Memory, not CPU, is the binding
constraint on the worker (ADR 071), and utilisation shows concurrency was never the limit.

**Deriving the trigger from a hash of source names**, like `checks.Fingerprint` (which hashes
sorted check IDs). That carries the blind spot this ADR closes: editing a check's predicate
without renaming it never triggers a backfill. `LogicVersion` is a human-maintained constant
coupled to `TestClassifyMustFixDecisionTableIsPinned`, which fails when classifier behaviour
changes.

## Consequences

- Bumping `LogicVersion` reprocesses the whole corpus within hours, automatically. That is an
  obligation: bump it for semantic changes, not refactors.
- The watermark advances only after a pass converges — not on failure, and not on hitting the
  backstop. A half-run pass must not look done.
- Rounds add enrich queue depth by design. `reenrichQueueCeiling` bounds it, but worker memory
  is worth watching on the first pass.
- `reenrich_all` is registered in `rescueRegistrations()`. Without it the leader's `JobRescuer`
  permanently discards the job after an OOM (`internal/jobs/rescue.go`).
- The page query deliberately bypasses `finding.DefaultLimit` (200), which `List` clamps to
  silently. Same reasoning as `asset.ListAllForSync`: the page cap is for the web UI and must
  never truncate a bulk walk.
- Not addressed: findings that are never re-observed because collection itself is stale. This
  pass converges enrichment over them; it does not make collection fresher.

## Note on later evolution

The implementation has since changed in ways that refine, not reverse, this decision: rounds
run on their own single-worker queue (`reenrich_all`, `queueReenrich`), and the pass now walks
by finding id with a cursor carried in the job args (`ReenrichAllArgs.AfterID`) instead of
ordering by `enriched_at`, because ordering over a column the write path resets did not
converge. See `internal/jobs/reenrich.go`.
