# ADR 030 — The decision → govern → execute pipeline (its autonomous path withdrawn by ADR 087)

**Status:** accepted · amended 2026-07-06 (simulated executions do not train autonomy) · **superseded in part by [ADR 087](087-no-autonomous-remediation.md)** (no auto mode, no autonomous execution, no execute-class jobs)

The policy gate this ADR calls OPA (ADR 006) is now the Go function `policy.Decide`; OPA is no longer a dependency.

## Context

Several ADRs describe pieces of the agent (004 Anthropic-direct, 006 embedded OPA, 015 MCP
write tools, 021 change-driven reasoning, 005 decaying memory) but none states the
**overall posture** or documents the **decision→execute pipeline** as a whole. That posture
is the product thesis and deserves to be written down: this is not a scanner with an LLM
bolted on for summaries — every actionable finding is *reasoned about* by an agent with full
graph context, and the agent can *act* under governance. The pipeline decides on findings
rather than only scoring them. New contributors need one place that explains how a finding becomes an action
and what stops a bad one.

## Decision

**Agentic-first** means the enriched finding is an *input to a decision*, not an endpoint.
The pipeline, in order:

1. **Enrich** (ADR 014/024) — score the finding through the sources registered in
   `cmd/graph/worker.go` into a 0–100 contextual
   score and a band: `monitor` (0–49), `pipeline` (50–60), `high` (61–80), `page` (≥81)
   (`ThresholdPipeline`/`ThresholdHigh`/`ThresholdPage` in `internal/app/enrich/domain.go`).
2. **Decide** (`internal/app/respond`) — for findings above the pipeline threshold,
   `respond.Decide` calls the **Reasoner** (Claude, ADR 004) with a `ContextPack`: blast
   radius, exposure, provenance (ADR 023), score breakdown, peer findings, EPSS/KEV, identity
   chain, supply-chain path. The model returns a `Plan{action_class, summary, rationale}`
   where action_class ∈ {observe, remediate, modify, isolate, destroy} — least-invasive by
   default, and the rationale must cite specific graph signals. Cached by context fingerprint
   (ADR 021) so unchanged context skips the LLM call.
3. **Govern** — the plan passes the policy gate (OPA, ADR 006) and the `AutomationPolicy`:
   per-action-class mode (`auto` / `jit` (approval) / `disabled`) plus auto/suggest score
   thresholds and a blast-radius cap. This is the safety boundary — the agent proposes,
   policy disposes.
4. **Execute** (`internal/app/executor`) — approved mutating actions run against the cloud
   via execute-class River jobs (`MaxAttempts: 1` — they either ran or errored, never
   silently retried): SG-rule removal, IAM-key disable, EC2 stop/start, S3 public-block, etc.
   Every decision — including `observe` — is recorded as an audit event and fanned out to
   decision notifiers (ADR 033).

The operator seam (MCP, ADR 015) is the *same* services with session-role gating — a human
or A2A agent (ADR 011) can drive any step directly.

## Consequences

- One documented path from detection to action, with a single governance choke (OPA +
  AutomationPolicy) — the place to reason about "could the agent do something bad" is one gate.
- Least-invasive-default + JIT approval + blast-radius cap means autonomy is opt-in per action
  class; the safe default is `observe`/suggest, not act.
- Execute-class jobs are `MaxAttempts: 1` by design — a cloud mutation that errors is surfaced,
  never auto-replayed (ADR 002).
- **Trade-off / current state:** the reasoning + governance + audit + notification path is
  fully live; cloud *execution* runs through the executor seam but several actions are
  conservatively gated/simulated pending per-action hardening — the decision and its
  rationale are always real and recorded even when the mutation is held.
- **Amendment (2026-07-06) — simulated executions do not train autonomy.** Because execution was
  gated/simulated, the outcome recorded at decide time was not a real result, so those outcomes
  were tagged `simulated` and excluded from the ADR 005 confidence computation: the agent could
  not self-promote to autonomy on simulated "successes". ADR 087 removed the auto mode, and with
  it every simulated outcome, the tag and the exclusion. Until a real executor→memory feedback
  loop exists, confidence stays `insufficient` and every action escalates to a human
  (fail-closed).
- Reasoning is cost-bounded by the ADR 021 cache and the band threshold (only `pipeline`+
  findings are reasoned), so the LLM spend tracks *changed, material* findings, not volume.

Cites ADR 004 (Anthropic-direct), 006 (OPA governance), 014/024 (enrichment + change-gate),
021 (reasoning cache), 005 (decaying memory informs action confidence), 015 (operator MCP
seam), 023 (provenance in the context pack), 002 (execute-class job semantics), 033 (decision
notifications).
