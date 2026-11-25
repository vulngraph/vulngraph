# ADR 053 — Continuous severity adjudication: grounded severity beliefs that crystallize into rules

**Status:** accepted (2026-07-10) · amended (adjudicator model default and sweep cap; 2026-08-11 single-row insert cost) — slices 1–2 implemented (slice 2 off by default behind `ADJUDICATOR_ENABLED`); slice 3 (crystallization) partly implemented — candidate mining only, promotion not built; slice 4 not built.

## Context

Severity is a deterministic additive enrich score. It is fast and reproducible
but static: it cannot ask "why is this high, and does that make sense?", cannot
re-frame a mis-framed finding (a hypothetical example: an `admin` role that is unused
and assumable only through SSO, scored as "overprivileged" when the real signal is
"decommission"), and
cannot investigate. A live investigation exists, but only manually, per finding,
through chat. The score and the must-fix classification can also disagree: a
finding can carry a very high score while must-fix (ADR 044) classifies it as
not urgent.

Naive fixes fail. Bare-LLM severity is the least reliable configuration
(uncalibrated, biased, non-reproducible) and does not scale to large finding
volumes; a purely deterministic combinatorial scorer cannot reason. Trustworthy
LLM judgment requires grounding, rubrics, self-consistency and calibration;
expensive reasoning should be spent where signals disagree; and self-improving
loops collapse if a model grades its own output.

## Decision

Make the unit of judgment a durable, grounded **Belief**, produced by an
agent-primary loop disciplined by the deterministic graph:

1. **Belief object** — claim + cited evidence + a coarse confidence band
   (low/medium/high; deterministic beliefs are high by construction, adjudicator
   beliefs take their band from sample convergence; not calibrated) + provenance +
   status; persisted in ClickHouse, re-examined when cited evidence
   changes. Grounding contract: no clause without a sensor-observed fact.
2. **Adjudicator** — full-context, N independent adversarial reasoning samples
   that try to *refute* the high severity; a verdict is issued only on
   convergence; divergence escalates to a human. Probing a sensor for a missing
   fact is not built (slice 4).
3. **Attention by disagreement** — the adjudicator runs only on findings where
   the concrete sensors conflict (query-by-committee); agreed cases stay
   deterministic and free.
4. **Crystallization (keystone)** — a belief pattern confirmed N times against
   objective ground truth and passing the eval harness is promoted to a
   deterministic enrich rule; the LLM stops spending attention there. Promotion
   is not built (slice 3 part 2 below), so neither the cost nor the accuracy
   effect has been measured.
5. **Ground truth and anti-collapse** — calibrate only on objective (live-verify)
   and human labels, never the model's own output (extends ADR 005). ECE/Brier
   calibration and demotion precision/recall are not built: they need a labeled
   corpus (ADR 038), and today's gate is the coarse N-correct/N golden-set eval.
6. **Guardrails** — demote or re-frame, never silently drop; irreversible actions
   stay human-gated (ADR 030); every verdict is auditable. Behavioral live
   signals that override a standing demotion and page someone are not
   built.

New domain `internal/app/belief/` (four-file layering, ADR 010), depending on
small sensor interfaces (context pack, live-verify, enrich, memory, eval, reason),
LLM via the existing `reason` seam, no new nuclei import (ADR 009). Build order:
accuracy → explainability → autonomy, with slices 1–3 as the shippable core.

### Implementation

- **Slice 1 (accuracy floor + belief substrate) — implemented.** `internal/app/belief`
  (Belief + grounding-contract `Validate`, deterministic `Reconcile` closing the
  score↔must-fix incoherence), ClickHouse persistence (the `beliefs` table,
  RMT + 90d TTL), read API `GET /api/beliefs/{finding_id}`, and enrich-time
  population via the fail-open `BeliefFormer` seam. No LLM in this slice.
- **Slice 2 (adversarial adjudication + real LLM) — implemented, off by default.**
  `NeedsAdjudication` (attention-by-disagreement gate), `Adjudicate` (N-sample
  convergence over a `Sampler` seam), and the cost-bounded `Adjudicator.Run`
  (score-priority, `DefaultSweepConfig` = 40/sweep cap, N-cascade: one cheap
  sample, escalate to N only on disagreement with the deterministic severity;
  overflow is deferred and reported, never silently dropped). The real sampler is
  `reason.Reasoner.Sample` — one adversarial "try to refute this high score"
  pass, untrusted fields fenced, returning a grounded `Verdict`. Wired as a River
  periodic job (`adjudicate`, on its own `adjudicate` queue with a single worker so the
  20-minute sweep never blocks respond, 30-minute cadence) that gates
  high-band findings, assembles the same `respond.ContextPack` the remediation
  reasoner sees, and persists `provenance=adjudicator` beliefs. Gated behind
  `ADJUDICATOR_ENABLED` (off until deliberately enabled); the model defaults to the
  configured LLM provider's default (for Anthropic, `llm.DefaultAnthropicModel` in
  `internal/llm/config.go`), overridable via `ADJUDICATOR_MODEL`.
  Metric `graph_adjudicator_outcomes_total{outcome}` — watch `deferred` (cap
  throttling coverage). Enabling it is gated on the eval harness (ADR 038).
  - **Change-driven memory (do-once):** each adjudicated belief stores an
    `input_fingerprint` (hash of score/band/deterministic-severity/context). The sweep skips any finding whose standing adjudicator
    belief carries the same fingerprint and is within `RevalidateAfter` (7d), so
    a stable finding is adjudicated once and remembered; LLM cost recurs only
    when its evidence drifts or the belief ages out. Both agreement and
    disagreement write a belief so the next sweep finds them cached
    (`outcome=cached`). This is the per-finding precursor to crystallization.
- **Runtime corroboration gate — implemented.** After a verdict, before
  persistence, `belief.corroborationConflict` (`internal/app/belief/fidelity.go`,
  wired in `Adjudicator.Run`) cross-checks a *demotion* against an independent,
  different-lineage exposure witness — chiefly the resource's
  `public_access=confirmed` (config lineage, not in the reachability context the
  LLM saw). A demotion the witness contradicts is not silently accepted: the
  belief is downgraded to `proposed`/`ConfidenceLow` with the cited conflict,
  surfacing in the finding's true-severity panel as "needs review". It fires only
  in the risky direction (a demotion of a genuinely public resource); identity
  demotions with no public witness are untouched. This applies ADR 051's
  corroboration-first principle to the adjudicator and guards against confidently
  wrong demotions. Metric:
  `graph_adjudicator_outcomes_total{outcome="corroboration_downgrade"}`.
  **Future:** resolve `proposed` conflicts with a read-only cloud describe via the
  serve-pod live-AWS sensor (`internal/app/mcp/live_aws.go`) — not built here
  because the worker lacks the connector-credential path.
- **Slice 3, part 1: crystallization candidate mining (report-only) — implemented.**
  `belief.MineCandidates` (`crystallize.go`, wired via
  `Adjudicator.MineCrystallization` and the sweep job) groups beliefs that
  survived the corroboration gate (`provenance=adjudicator`, `status=confirmed`;
  this is the anti-collapse ground truth, not the model's unchecked output) by a
  tenant-agnostic structural signature `(resource_type, band, must_fix_class)`. A
  signature that maps to one severity across ≥20 verdicts with no dissent is a
  crystallization candidate, surfaced via log and
  `graph_adjudicator_outcomes_total{outcome="crystallization_candidate"}`. It only
  identifies candidates; enrich/Reconcile are untouched. **Slice 3, part 2
  (eval-gated promotion to an enrich-time rule)** is deliberately not built:
  auto-applying LLM-derived patterns is the collapse risk, so promotion must pass
  the eval harness (ADR 038) and human sign-off.
- **Slice 4 (not built):** bounded agentic evidence gathering (sensor probes on
  missing facts), and confidence calibration (ECE/Brier) against a labeled corpus.

## Consequences

- An auditable "true severity" with a cited evidence chain per verdict.
- Once promotion is built, reasoning becomes durable knowledge: crystallized
  patterns are reusable structural shapes, not one-off verdicts.
- Real cost and complexity: an LLM reasoning path in the severity loop with its
  own calibration and eval discipline. Mitigated by disagreement-gating (spend
  only on ambiguity) and, once promotion is built, crystallization (never re-judge
  a solved pattern).
- Risk: a wrongful demotion hides real risk. Built guards: demote-don't-drop,
  the corroboration gate (`internal/app/belief/fidelity.go`) and escalation to a
  human when samples diverge. Not built: behavioral alerts that override
  a demotion, demotion recall as an eval metric, and re-validation of
  crystallized rules against fresh labels (no rules are crystallized yet).

Cites ADR 005 (real-only memory it extends), 021/030 (change-driven + agentic
decision pipeline it builds on), 038 (eval harness / promotion gate), 044
(must-fix evidence), 045 (read-only live verification), 050 (trust/access-pattern
context), 051 (verification fabric — the sensors), 052 (CIEM findings it reasons
over). Amends the implicit "severity = additive enrich score" model.

## Amendment — adjudicator model default and sweep cap

The adjudicator originally defaulted to a separate, cheaper model with a
100/sweep cap. A configured model that is unavailable makes every sample call
fail, so the default was changed to the provider's default model (`llm.DefaultAnthropicModel` for Anthropic), the model already
exercised by the remediation-reasoner path; a cheaper tier remains selectable via
`ADJUDICATOR_MODEL`. Because real model calls take longer than immediate errors,
the cap was lowered to 20 to keep a sweep inside its job timeout, then raised to
40 once a backlog-cursor fix made a larger cap useful again. The Helm defaults
(`values.yaml`, `_helpers.tpl`) were updated to match.

## Amendment 2026-08-11 — single-row insert cost; async insert rejected

Enrich runs one River job per finding, which means one single-row ClickHouse
INSERT per finding into `beliefs`, and the same shape into `signals`, each
landing one row per part. Active part counts stay low, so this does not look like
a part explosion; it is merge write amplification (merges repeatedly rewrite far
more data than the tables hold live), visible only in `system.part_log`. Together
with `findings`, it becomes a significant ClickHouse merge cost at high finding
volumes.

**Server-side async insert is rejected.** `async_insert=1,
wait_for_async_insert=0, async_insert_busy_timeout_ms=3000` coalesced single-row
`PrepareBatch` sends over the native protocol when this was checked against
ClickHouse 24.8. That has not been re-checked on the ClickHouse 26.8 the stack
now runs, and nothing in the code depends on it: the rejection holds whatever
the coalescing does. With `wait_for_async_insert=0` the insert returns before the
row is written, so it is not visible when the write returns, and both tables are
read back on paths that matter:

- `beliefs` has an explicit read-after-write contract. `AdjudicationCandidates`
  reads the table to exclude findings whose belief was just written, and
  `GetByFinding` must return a belief the caller has just persisted.
  `TestCHRepo_RoundTrip` and `TestCHRepo_AdjudicationCandidates` assert this and
  both fail under async insert: the round-trip returns `belief: not found`, and a
  freshly adjudicated finding stays in the candidate cursor and would be
  re-adjudicated (a duplicate LLM call).
- `signals` has no test asserting immediate read-back, but `respond.Context` reads
  the factors on the decide path, and a decide job on an idle respond queue can
  run inside the flush window. The read is guarded by `len(factors) > 0`, so a
  miss does not fail — it silently feeds the LLM less evidence than enrichment
  produced, which is worse than a visible failure.

General rule: "derived and idempotently recomputed" is not sufficient licence for
a bounded-loss writer. The test is whether anything reads the row back inside the
loss window. `findings` is excluded for a stronger reason: it carries the score and
the ADR 054 lifecycle columns, and `EnrichWorker` aborts on its write error so
River retries.

**The real fix is upstream and out of scope:** the amplification exists because
there is one River job per finding. Batching at the source means restructuring
enrich away from per-finding jobs, an ADR 024 decision with a much larger blast
radius. Until then the merge cost stands. `belief/sweep.go`'s one-element `Upsert`
calls are not a significant contributor (bounded by the sweep cap, `DefaultSweepConfig`'s
40 adjudications per 30-minute tick) and
are left as is.
