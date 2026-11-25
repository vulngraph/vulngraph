# ADR 005 — Decaying outcome memory replaces a per-tenant neural model

**Status:** accepted · amended 2026-07-06 (confidence trains only on real outcomes) · **superseded in part by [ADR 087](087-no-autonomous-remediation.md)** (confidence never grants autonomy; only human verdicts are recorded)

## Context

For each proposed remediation the platform must decide whether to act autonomously, park
for approval, or escalate. One option is a small learned model (for example an MLP served
by a Python service and online-learned from run outcomes). Such a model earns its
complexity only with a large volume of outcomes. A single-tenant deployment produces far
too few outcomes to train it — especially for the rare, destructive actions where
confidence matters most.

## Decision

A pure-Go exponentially-decayed outcome ledger. `action_outcomes` (Postgres) records every
executed action's context and result. Confidence for an (action class, asset context) pair:

    confidence = Σ wᵢ·outcomeᵢ / Σ wᵢ   where wᵢ = e^(−λ·age(i))

- Configurable half-life (default 30 days): recent reality dominates, stale lessons fade.
- Confidence band → decision: high = autonomous (still OPA-gated), medium = park for
  approval, low or insufficient samples = always escalate. **No history = ask the human.**
- A minimum-sample threshold stops a lucky streak from unlocking autonomy.

## Alternatives considered

- **A learned (neural) autonomy model** — rejected: insufficient training data per
  deployment, opaque decisions, and a Python/PyTorch serving dependency.

## Consequences

- Interpretable: "high confidence because 14 of 15 similar actions in 60 days succeeded"
  is an audit-grade answer a neural model cannot give.
- Pure math, table-driven unit tests, no Python or PyTorch in the stack.

## Amendment (2026-07-06) — confidence trains only on real outcomes

An outcome recorded at decide time, before anything ran, would be an optimistic guess,
and feeding guesses into the ledger would let confidence climb on outcomes that never
happened.

**Decision (fail-closed):** the decide path writes no outcome (ADR 087). The only writers
of `action_outcomes` are a human denial (`govern.Resolve`) and a fix that actually ran
(`govern.RecordExecution`), so confidence only ever builds on real results, and a context
with too few of them stays `insufficient` → escalate to a human. Code:
`internal/app/memory`.
