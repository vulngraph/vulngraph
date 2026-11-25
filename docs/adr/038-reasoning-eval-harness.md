# ADR 038 — Reasoning evaluation harness (golden-set regression gate)

**Status:** accepted (2026-07-03; amended 2026-07-06, 2026-07-12, 2026-10-24)

## Context

The reasoning path (ADR 004/021/030) sends a graph-grounded `ContextPack` to Claude and
gets back a `Plan{action_class, rationale}`. Its decision quality is central to the product,
yet the existing tests only covered response parsing and the `respond` wiring. Nothing guarded
*decision quality*: a system-prompt edit, a model upgrade, or provider-side drift could silently
flip decisions on the "observe vs act" boundary — where false alarms and missed risk live —
without any test failing. An auditable AI decision path needs a regression gate on its judgement.

## Decision

A golden-set eval, `internal/reason/eval_test.go`, gated behind `//go:build eval` — opt-in
like the integration tests, because it makes real Anthropic calls:

    REASON_API_KEY=sk-... go test -tags=eval ./internal/reason/ -run TestReasoningGolden -v

- **Coarse, unambiguous expectations only.** Each case asserts `mustObserve` (the only correct
  answer is `observe`) or its negation (must NOT be `observe`). Judgement calls between adjacent
  action classes (remediate vs modify) are deliberately excluded — the gate catches real
  regressions, not debatable class choices.
- **The set covers the decision boundaries**, not just the two extremes: the deployed-vs-installed
  false positive (KEV CVE present but not reachable → observe), medium-EPSS-but-isolated → observe,
  dev-noise → observe, versus publicly-exposed-DB-with-KEV, exposed-secret-on-prod-host, and
  internet-facing-privesc-to-admin → act.
- **It grows by accretion.** Whenever a finding is mis-decided, it is added with the correct
  expectation so the gate locks the fix in.

It never runs in normal CI (no key, `//go:build eval`), so it costs nothing by default and never
flakes the pipeline. It is meant to be run by hand before a prompt or model change; nothing
enforces that.

## Amendment 2026-07-12 — Adjudicator gate (ADR 053)

The severity adjudicator (`reason.Reasoner.Sample`) gets the same treatment:
`internal/reason/adjudicate_eval_test.go`, `//go:build eval`, run as `TestAdjudicatorGolden`.
Without it, adjudicator verdicts were plausible but unmeasured.

- **Coarse, bidirectional expectations.** Each case asserts `mustHold` (a genuinely
  reachable, uncontrolled critical MUST stay high/critical) or its negation (a
  contained / unreachable / mislabeled high MUST demote to medium/low). Only the
  hold-vs-demote boundary is pinned, never a one-band judgement call.
- **`mustHold` cases exist specifically to detect demotion bias.** A purely adversarial
  prompt ("assume the score is wrong and refute it") tends to demote everything; a
  `mustHold` case that comes back medium/low fails the gate and shows the bias has
  regressed. The prompt must pass both directions.
- **Grows by accretion** from observed mis-adjudications, same as the respond set.
- **Runnable in CI on demand:** `.github/workflows/eval.yaml` (`workflow_dispatch`) runs both
  golden sets with `secrets.ANTHROPIC_API_KEY` (behind a protected environment), so baselining
  and pre-change checks need no local key. It is manual-only — never on push/PR — so LLM cost
  and LLM non-determinism never touch the normal pipeline.
- **Limit (unchanged):** a regression gate, not a statistical benchmark. It emits a coarse
  N-correct/N read, not a calibrated accuracy/ECE score — that needs a labeled corpus, which
  the golden set accretes toward over time. Runtime cross-checking of cited facts against the
  live-verify component (grounding fidelity) is not built.

## Amendment 2026-10-24 — What the gates measure, exactly

Stated precisely so nothing reads as more validation than exists:

- **Automated coverage.** Normal CI unit-tests the reasoning path against a fake model
  (`internal/reason/reason_test.go`: prompt building, fencing, parsing, canaries). That catches
  structural regressions. It measures nothing about decision quality.
- **When the gates run.** Only when a person runs them: locally with `-tags=eval`, or by
  dispatching `.github/workflows/eval.yaml`. No trigger runs them on a prompt, model or provider
  change, and no results are recorded or published per model or version.
- **`TestReasoningGolden`** (`eval_test.go`, 10 cases): each case sends one `ContextPack` once
  and checks a single boolean, whether `action_class` is `observe`. Every case must pass. The
  rationale is not graded, and neither is which non-observe class is proposed.
- **`TestAdjudicatorGolden`** (`adjudicate_eval_test.go`, 8 cases): each case samples one
  verdict once and checks whether the severity stays high/critical or is demoted. A miss is
  logged; the test fails on more than 1 miss (`adjMaxMisses`), so it passes at 7 of 8.
- **No repeat sampling.** Each case is one draw from a non-deterministic model, so a green run
  says those cases held on that run. It is not a pass rate.

## Consequences

- A prompt or model change can be checked before it ships: run the eval and confirm the boundary
  cases hold. A prompt edit that flips a boundary case on the run fails the gate. Nothing makes
  anyone run it.
- A run is evidence that these 20 hand-picked boundary cases held for the model and prompt it
  ran against, on that run. It is not evidence of decision quality in general.
- **Limit:** it is a *regression* gate, not a benchmark. It does not produce an accuracy score,
  and its size reflects hand-curated unambiguous cases, not statistical coverage. Growing it
  against observed mis-decisions is ongoing work. The safety backstop is not this gate:
  every state-changing plan waits for a person's approval (ADR 087), so a bad decision
  becomes a bad proposal, not an action.

Cites ADR 004 (Anthropic-direct), 021 (change-driven reasoning), 030 (the decision pipeline),
005 (autonomy confidence — the other half of AI trust).
