# ADR 082: A pattern verdict stops the agent re-asking, but is never standing consent

**Status:** accepted (2026-08-24) · amended 2026-08-24 (revision: wider suppression key, 90-day expiry) · superseded in part by [ADR 087](087-no-autonomous-remediation.md) (there is no auto-execution path left for an approval to open)

## Context

The agent decision trail grows much faster than the set of findings it is about. An earlier
change stopped re-recording a byte-identical repeat of the SAME finding's decision, and made a
human denial record negative confidence evidence. Neither touches the other half of the churn:
**a human ruling on a PATTERN does not stop the agent re-asking the same question about new
findings of that pattern.** A governor who denies "trim privesc on 7 human users" today still
gets asked about finding #8 of that exact pattern tomorrow, and #9 the day after — each one a
fresh row in the audit trail and, while it escalates, a fresh entry in
`ListPendingReasoning`'s human queue.

The record was durable but never consulted: Postgres table
`pattern_verdicts` (columns `verdict`/`decided_by`/`decided_at`), written by
`govern.Service.Resolve` with the key derived server-side from the resolved findings, plus
`govern.Service.PatternVerdict` / `govern.PGRepo.PatternVerdict` with a sentinel-error-free
"not found" contract. Its key is `(check_id, action_class,
resource_type)` (see "Blast radius of a denial"). This ADR wires the record into
`respond.Decide`.

## Decision

**A pattern verdict is evidence that a human already ruled on this whole pattern — never
standing consent to act.** The two recorded verdict values get opposite, deliberately
asymmetric treatment:

- **DENIED suppresses, within a bounded scope.** Re-escalating the same question for every new
  finding of an already-denied pattern is noise — the human said no once; asking again teaches
  nothing and burns their attention. `Decide` short-circuits to a new terminal outcome,
  `OutcomeSuppressedByVerdict` (`"suppressed_by_verdict"`), before the confidence/gate/CoVe
  pipeline decides. The decision is still audited (`escalation_reason: "pattern_denied"`), but
  it does **not** notify the webhook and does **not** record a memory outcome. Those are
  precisely the re-asking/re-evidencing channels the pattern denial exists to close: the
  human's ruling lives once in `pattern_verdicts`, not once per finding in the confidence
  ledger. `ListPendingReasoning`'s `WHERE outcome IN ('parked_for_approval', 'escalated')`
  filter drops the new outcome out of the human queue with no query change.

  **This does not save reasoning cost.** The check sits after `planFor`, because the key needs
  the plan's action class — so the LLM reason call (on a cache miss), the blast walk and the
  full context-pack assembly are still paid on a suppressed finding. The savings are audit
  rows, webhook traffic and human attention.

- **APPROVED annotates, never grants authority.** The gate and the confidence ledger already
  own autonomy end to end; a prior approval bypassing them would be a second, unaudited path to
  auto-execution — exactly the shape of bug ADR 080 names. So an approved pattern only appends
  a `PlanNotes` entry ("pattern previously approved by a human governor for this check and
  action class") and changes nothing else: outcome, gate result, confidence band, and memory
  recording all proceed exactly as if no verdict existed.

- **No verdict, a lookup error, or no lookup wired all fail open.** A lookup failure is not
  evidence of anything — logging it and deciding as if nothing was recorded is the only safe
  response, matching every other optional seam on `respond.Service` (nil disables, an error
  never fails the decision).

- **`risk_accepted` is deliberately not recorded** by `govern.Resolve` and is therefore never
  seen here: it would need expiry and scope semantics that do not exist yet, and a standing
  "risk accepted" pattern must never be mistaken for consent to act. `respond`'s verdict switch
  has no case for it — an unrecognized string behaves exactly like "no verdict found."

**Repeat dedup applies to the suppressed path too.** A byte-identical suppressed repeat (same
cached outcome, same action class) is not re-recorded — the same no-op-repeat logic, narrowed
to the two fields this terminal path depends on (there is no gate/CoVe/confidence result to
compare against).

**A suppressed decision carries forward real measurements.** When a suppressed finding is
re-reasoned (cache reuse, or a cache miss after the 7-day forced re-reason, `maxCacheAge`),
`planFor` returns the prior cache entry so the decision record keeps the prior measurements
instead of zeros. The carry-forward is keyed on "a prior entry exists", not "this call reused
it".

### Layering

`internal/app/govern` already imports `internal/app/respond` (for `respond.AuditEvent`), so
`respond` importing `govern` would be an import cycle (ADR 010's enforced layering forbids it
regardless). This follows the precedent `ActionApplicability`/`WithExecutorCapability` set for
the same problem (`respond` consulting `internal/app/executor`, which it also cannot import):

- `respond` declares its own narrow interface, `PatternVerdicts`, whose method returns a
  **plain `string`** for the verdict — not `govern.Verdict` — so the interface carries no
  govern type.
- `PatternVerdictsFunc` adapts a plain closure to it, mirroring `ActionApplicabilityFunc`.
- `cmd/graph/worker.go` — which already wires
  `WithExecutorCapability(respond.ActionApplicabilityFunc(executor.HasExecutableAction))` —
  constructs the full `govern.Service` (not a bare `govern.PGRepo`, so any policy later added at
  the service layer reaches the worker) and wires `WithPatternVerdicts` with a closure over
  `govern.Service.PatternVerdict`, converting its `govern.Verdict` result to a plain string.
- A `cmd/graph` test feeds the real `govern.VerdictApproved`/`VerdictDenied` constants through
  the real closure into a real `respond.Service.Decide`, so a rename on the govern side that
  silently degraded every denial to fail-open fails a test.

## Consequences

- The two verdicts have intentionally asymmetric power: DENIED can silence the agent, APPROVED
  can only leave a note. A false negative (an approved pattern that keeps asking) costs a
  redundant reasoning pass; a false positive (an approval treated as blanket consent) is an
  unaudited autonomy escalation. So APPROVED is deliberately under-trusted.
- DENIED is not free either. A denial silences a question; if the world changes so that the
  question deserves a different answer, silence is itself a failure mode. That is why its scope
  is bounded in two ways (below).
- `suppressed_by_verdict` decisions still land in ClickHouse's `audit_events`/`decisions`
  trail, so `DecisionsSummary` gains a `SuppressedByVerdict` count ("N questions a human already
  answered") and `escalation_reasons` gains `pattern_denied` through the existing
  `GROUP BY action_class, confidence_band, escalation_reason` scan.
- The finding-level `decision_verdicts` table, `ResolvedFingerprints`, and the per-finding
  re-surfacing logic in the governor queue are untouched — this is a second, coarser-grained
  signal layered on top, not a replacement.

### Blast radius of a denial

A denial suppresses re-asking for the key `(check_id, action_class, resource_type)`, for
**90 days** (`respond.PatternVerdictMaxAge`), after which the question is asked again. It is not
per-resource, per-account or per-environment: denying `remediate` on `aws-s3-public-bucket` /
`s3_bucket` covers every S3 bucket in the estate for that window.

Two properties make that acceptable:

1. **The finding itself never goes quiet.** Suppression touches the *decision* loop only. The
   finding still exists, still scores, still alerts (`internal/jobs/enrich.go` dispatches on
   new/changed high|critical|KEV independently of `respond`), still appears in the Findings UI,
   and still counts toward must-fix. What stops is the agent asking "should I act on this?".
2. **It expires.** A human ruling is evidence about the world as it was; the ruling is re-tested
   rather than trusted forever.

**Rejected as too broad:** a `(check_id, action_class)` key with no expiry. Under it, one denial
covering a deliberately public marketing bucket would permanently silence the question for a
sensitive bucket that went public later — and, because `govern.ResolveByFindingID` expands one
email-link click to a whole cluster, a single click in an email could arm that estate-wide,
permanent suppression. That path still arms the scoped, expiring version, which is why both
bounds exist.

One click can still write MULTIPLE pattern rows when a cluster spans multiple resource types:
`govern.Resolve` writes one row per distinct resource type among the cluster's findings, so a
cluster of 20 findings across 5 resource types arms 5 keys. This is bounded by the resource types
the click's own findings cover, but it is a real multiplier on the blast radius.

### Precedence against per-finding verdicts

`respond.Decide` reads `pattern_verdicts`, never the per-finding `decision_verdicts`, so a
pattern DENIED overrides a per-finding APPROVED for later sweeps of that finding: since execution
flows through the webhook handoff, an approval goes inert once anyone denies the pattern. "The
latest human ruling on the pattern wins" is the intended contract, but it is not obvious from
either table alone, and any future change here must decide it deliberately.

## Out of scope

- **The policy gate is unchanged.** Its `allow_auto` conditions are not touched: on the denied
  path `Decide` short-circuits before the gate is evaluated, and on the approved path the gate
  runs exactly as before. (The gate is now the Go function `policy.Decide`; see ADR 006.)
- **No execution path.** A suppressed decision never executes: its outcome is
  `suppressed_by_verdict`, which, like parked and escalated, claims nothing ran (ADR 087).
- **`risk_accepted` pattern semantics.** Risk acceptance is a statement about a specific exposure
  being tolerable, which does not generalise across an estate the way "do not take this action"
  does. Until designed, `govern.Resolve` does not write it and `respond` does not read it.
- **Per-account / per-environment scoping.** The key stops at resource type. A denial that should
  apply to staging but not production is not expressible; the 90-day expiry is the backstop for
  that gap, not a solution to it.
- **No change to `decision_verdicts` or the governor queue's re-surfacing rules.**

## Guard

Core semantics (`internal/app/respond`): `TestDecide_PatternDenied_Suppresses` (also pins that the
lookup is scoped by the finding's own check_id/action class/resource type),
`TestDecide_PatternDenied_DestroyClass_StaysSuppressed` (a denied pattern on a destroy-class
plan must still suppress, never turn back into a proposal — the gate is proven uncalled via a
call-counting fake; the ADR 087 no-autonomy guarantee is
`TestDecide_NoStateChangingPlanEverAutoExecutes`), `TestDecide_PatternApproved_AnnotatesOnly`,
`TestDecide_NoPatternVerdictFound_Unchanged`, `TestDecide_PatternVerdictLookupError_FailsOpen`,
and `TestDecide_PatternDenied_RepeatSkipsRecording`.

Scoping and expiry: `TestDecide_PatternVerdict_ExpiredIsTreatedAsNotFound`,
`TestDecide_PatternVerdict_AtMaxAgeStillSuppresses` (the exact 90-day boundary — still trusted).

Measurement carry-forward: `TestDecide_PatternDenied_ReusedEntry_PreservesMeasurements`,
exercising both the cache-hit and cache-miss paths.

Repeat counter: `TestDecide_RepeatTracker_IncrementsOnlyOnMatchedRepeat`,
`TestDecide_RepeatTracker_NotIncrementedOnDivergingDecision`; the reader is
`reasoncache.Service.TopEscalatedRepeats`, wired in `serve.go` via `respond.RepeatHotspotsFunc`.

Cross-package pinning (`cmd/graph`): `TestPatternVerdictStrings_GovernAndRespondAgree`.

govern-side (`internal/app/govern`): `TestResolve_WritesOnePatternVerdictPerDistinctResourceType`,
`TestResolve_UnknownResourceTypeWritesNoPatternRowForThatFinding`.

## Amendment history

- **2026-08-24 (revision).** The suppression key was widened from `(check_id, action_class)` to
  include `resource_type`, and the 90-day expiry was added, to bound a denial's blast radius
  (`pattern_verdicts`' primary key). Two claims in the first draft were corrected: suppression does not skip the
  reasoning/gate cost (the check runs after `planFor`), and DENIED is not a "safe to over-trust"
  direction. The measurement carry-forward was extended to the cache-miss path after review found
  suppressed decisions recorded zeroed measurements on a forced re-reason. The worker wiring was
  switched from `govern.PGRepo` to `govern.Service`.
