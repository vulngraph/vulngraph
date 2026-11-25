# ADR 043 — "Safe to fix" signal computed at enrich time

**Status:** accepted (implemented 2026-07-07) · amended 2026-10-23 (storage superseded by ADR 075)

> **Amendment (2026-10-23) — storage superseded by ADR 075.** These outputs live in
> `finding_enrichment` (ClickHouse), written by enrichment writers (enrich and the
> KEV refresh) and LEFT JOINed on read; `findings` has no enrichment columns.

## Context

When a large environment is onboarded it produces a large volume of findings. The platform scores
them well (contextual risk, blast radius, KEV) so "what matters?" is answered — but
the analyst still can't *act*, because nothing tells them "will fixing this break
anything?" That confidence gap is what makes a freshly-onboarded env feel
un-actionable: a wall of undifferentiated issues, none obviously safe to touch.

The "will it break?" axis already existed as `respond/impact.go`: `ImpactAssessment`
(dependents = inbound `dns_points_to`/`executes_as`/`federated_access` edges, i.e.
what *relies on* this resource — the inverse of attack blast radius — plus a
liveness/unused heuristic and a fix location) and a `safety_band` (safe/caution/
risky) that folds in the chosen action. But it was computed **only inside the
per-finding LLM reasoning path** (`buildContextPack` → `Decide`) and read from
`reasoncache`. On a fresh large env almost nothing is reasoned yet (the decide
queue is depth-capped at 500 and drops under load — ADR 030/002), so the band is
empty for most findings, and the "safe to fix — start here" filter
is empty exactly when it is needed most. The signal was also absent from the
findings list entirely — it only appeared on the detail page and the agent queue.

## Decision

Compute a **structural, action-independent safety signal at enrich time** for
*every* finding, and persist it on the finding.

- `internal/app/enrich/safety.go` classifies `safety_class` (safe | caution |
  risky) from graph structure alone — **no LLM**: dependents (distinct inbound
  dependent edges), `unused` (inactive IAM principal or an asset stale past the
  same window `respond` uses), production/internet-facing flags. It is fail-open:
  a nil provider or a graph read error leaves the class empty, exactly like a
  not-yet-enriched finding — a hiccup never mislabels something "safe".
- **"Present and unreferenced"** by decision (see *Why "present", not "unused"*
  below): `safe` = the asset is still **present** (seen within the freshness
  window), **0 dependents** (nothing routes to or runs as it), and **not**
  production or internet-facing. `risky` = depended-on / prod / internet-facing;
  a stale/gone/uncorrelated resource is `caution`, never safe (its finding is
  moot, not a quick win). Production is matched *structurally* — any tag key
  containing `env`/`stage` (so `env`, `example.com/env`, `example.com/stage`
  are all caught without hardcoding organization-specific keys) against prod/production/prd values.
  An inactive-IAM flag is kept as evidence (`unused`), not as the gate.
- Enrichment already walks the graph to score, so this adds only a few indexed
  edge lookups per finding, gated by the existing enrich change-gate (ADR 024).
  New columns `dependents`, `unused`, `safety_class`, `fix_target` on the
  ClickHouse `findings` table, written in the same full-row
  enrichment upsert as `score` — never a partial row (RMT argMax safety).
- Surfaced on the findings **list** (`safety_class`/`dependents`/`unused`/
  `fix_target` fields + a `?safe=true` filter) and driven into a **"Start here"**
  worklist: high-signal ∩ safe-to-fix, each row showing *why it matters* (score,
  KEV) beside *why it's safe* (0 dependents, unused, fix location), with
  multi-select bulk suppression.

The reasoning path is unchanged and remains authoritative: `respond`'s
`safety_band` folds in the *chosen action class* and supersedes the structural
class once a finding is reasoned. The two use the same vocabulary so the UI renders
one thing; the enrich-time class is the always-present floor, the reasoned band the
refinement. `enrich` does not import `respond` (ADR 010 layering) — the small
structural classifier and the dependent-edge/staleness windows are duplicated
deliberately (and pinned by tests) rather than sharing an abstraction across the
layer boundary.

### Why "present", not "unused"

An earlier draft gated `safe` on `unused = last_seen > 7d`. In environments with
heavy ephemeral churn (short-lived k8s pods/jobs, rotated compute), most assets
look "stale" by that test, so the worklist fills with dead or rotated resources
whose findings are moot. Gating on **present** (fresh) removes that ephemeral noise
and leaves a focused identity-hygiene worklist (`iam_role`/`iam_user`/
`gcp_service_account` with nothing depending on them). The production check is
structural because environment tag keys are commonly namespaced
(e.g. `example.com/env=prod`) rather than a bare `env`.

## Consequences

- The "start here" worklist is populated the moment the first sync + enrichment
  completes — no dependence on the LLM decide backlog. This is the change that
  makes a freshly-onboarded large environment actionable.
- Advisory only, as before: the class does **not** gate the OPA policy (ADR 030).
  It sorts human quick-wins; a future change may feed the reasoned band into the
  gate, but never the structural floor on its own.
- The finding contract moves with the code: the new fields + `safe` param are in
  `openapi/domains/finding.yaml` and the generated client, checked by the
  spec-drift gate (ADR 017). The bulk-suppress endpoints the worklist uses were
  also added to the spec (previously live but undocumented).
- **Limit:** `unused` is a heuristic from existing signals only (no new
  collectors) — a stale/inactive read, not proof of no traffic; hence the
  conservative gate and the "verify" framing in the UI.

Cites ADR 023 (provenance/lineage edges it reads), 024 (the enrich change-gate it
rides), 025/026 (the graph it queries), 030/005 (the reasoner + memory whose
reasoned `safety_band` supersedes it), 010 (the layering it respects), 017 (the API
contract gate).
