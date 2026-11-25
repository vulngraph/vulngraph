# ADR 021 — Change-driven, context-aware reasoning

**Status:** accepted

## Context

The platform's value is that the inventory is one connected graph: a finding is not "bucket X is public" but "bucket X, reachable from an internet-facing LB, owned by a privileged role, in a production environment" — or, just as importantly, "an isolated bucket on no critical path: low real risk." Separating real risk from noise is the job of the reasoning engine.

Two gaps undercut that:

1. **No change detection — the reasoner re-runs on everything, every sweep.** The periodic `enrich_sweep` (ADR 013) re-enriches every finding every 30 minutes; every finding scoring `>= ThresholdPipeline` re-enters `respond.Decide`, which calls the LLM (`reason.Reason`) regardless of whether anything changed. River uniqueness (`ByArgs`/`ByState`) prevents *concurrent* duplicates but not *cross-sweep* re-runs. The result is LLM token spend re-deciding identical, unchanged findings indefinitely.

2. **Reasoning is context-blind.** `reason.buildPrompt` feeds the model only the raw finding fields (title, severity, type, resource, check, description). It does not include the enriched score, blast radius, attack path (`can_assume` chain), peer findings on the resource, asset metadata/tags, or exposure signals — even though `enrich` already computes most of it. So the model cannot reason over the connected graph; it plans remediation for a finding in isolation.

## Decision

**1. A context fingerprint gates the LLM call.** `respond.Decide` computes blast radius first, then a `sha256` fingerprint over exactly the inputs that change the answer: finding identity + `Score`/`ScoreBand`/`KnownExploited`, the sorted blast-radius asset-ID set (+ a stable sentinel when the walk is truncated), the peer-finding signature on the resource, the reachable `can_assume`/`can_escalate` attack-path signature, the bucketed cross-cluster tier, the exposure flags, and the set of enrich factor source names. Volatile-but-irrelevant inputs (timestamps, edge order, raw counts, within-band score wiggle, neighbour `last_seen`) are excluded.

The last fingerprint + plan + outcome are stored per finding in a new Postgres table `reasoning_cache`, behind a small `reasoncache` domain (ADR 010 layering; `respond` depends on an interface). On a fingerprint match, `Decide` **skips the LLM and reuses the cached plan**, but still re-runs confidence + policy gate + CoVe + audit (cheap, no LLM — a policy change must never be masked by a cache hit). The sweep stays cheap and keeps findings fresh; tokens are spent only when connected context actually changed. A max-age fallback re-reasons stale entries regardless.

**2. A graph ContextPack is fed to the reasoner.** `respond` assembles a `ContextPack` (reusing the already-computed blast radius plus `explore`, `finding.List`, the enrich signals table, and `asset.Get`) — the finding, its score factors, its asset, a blast-radius summary, the attack path, peer findings, cross-cluster spread, and derived exposure flags (internet-facing / privileged / prod). `reason.Reason` takes the pack; the system prompt is rewritten so the model reasons over the connected graph and may justify `observe` (no meaningful risk) or a real action with a rationale that references the graph. Output stays strict, validated JSON; `maxTokens` is raised and the (now stable) system prompt is prompt-cached so the larger prompt does not raise per-call cost materially.

This builds on ADR 002 (River jobs), ADR 004 (Anthropic SDK direct, structured output), ADR 005 (decaying memory for confidence), and ADR 013 (reconciliation sweep).

## Consequences

- The LLM is invoked on new or changed context only; sweeps over stable findings cost zero tokens. Combined with system-prompt caching, spend drops sharply.
- Reasoning becomes graph-aware. Plans cite blast radius, attack path, and exposure, and genuinely-isolated findings are classified as observe with a graph-grounded rationale.
- Two fingerprint failure modes must be guarded: **too sticky** (never re-reasons a real escalation) — mitigated by hashing every answer-relevant input plus the max-age fallback; and **too sensitive** (always re-reasons) — mitigated by sorting sets, bucketing counts, excluding timestamps/order, and a stable sentinel for truncated blast radius (whose 500-node budget would otherwise flap the set, re-reasoning the largest findings).
- New Postgres table (`reasoning_cache`) + sqlc queries + a `reasoncache` domain. `reasoncache` stays infra-pure (stores the plan as primitive fields) so the dependency is one-way `respond → reasoncache`.

## Not built

Provenance depth — "who shipped this, from where, what drifted" — is not built here. It requires instrumentation that does not exist yet: collectors stamping the source connector on each asset (assets carry no connector link today; drift is only inferrable from `synced_at`/`last_seen` deltas), supply-chain `github_repo --deploys_to--> workload` lineage edges, and explicit critical-path tagging.
