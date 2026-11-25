# ADR 014 — Enrichment stage: findings are scored in context, never surfaced raw

**Status:** accepted · amended 2026-10-23 (storage superseded by ADR 075)

> **Amendment (2026-10-23) — storage superseded by ADR 075.** These outputs live in
> `finding_enrichment` (ClickHouse), written by enrichment writers (enrich and the
> KEV refresh) and LEFT JOINed on read; `findings` has no enrichment columns.

## Context

Raw scanner severity is a poor prioritisation signal: the same CVE matters very differently
on an internet-exposed admin workload than on an isolated test box. A better model runs every
detection through a set of intelligence sources and produces a contextual risk score that
*replaces* raw scanner severity; only that enriched score is shown, aggregated, and used to
gate the agent, and reasoning/planning happens only *after* enrichment.

The implementation had drifted from this: findings carried only raw `severity`, and the
decision pipeline triggered on raw high/critical. A monolithic enricher with hardcoded
parallel blocks and a failure bitmask was considered and rejected in favour of a pluggable
design.

## Decision

A first-class **enrichment stage** (`internal/app/enrich`), run as River jobs.

- **Pluggable `Source` registry.** Each intelligence input implements `Source.Evaluate →
  (Factor, applied, err)`; the scorer (`Aggregate`) sums points, applies any source-declared
  floor, clamps to 0–100, and bands it (≥50 pipeline, ≥61 high, ≥81 page; the pipeline
  floor was later raised 31→50). The clamp ordering was corrected by **ADR 076**: the
  *positive* subtotal is clamped to 100 first and negative factors are applied after it, or
  else a demote on a finding whose positives already exceed 100 is silently discarded. A new
  domain (identity, drift, attack paths, supply chain, threat intel) is added by writing one
  `Source` and appending it to the slice in `cmd/graph/worker.go` — the scorer and service
  never change. Initial sources: base severity, KEV (a hit floors the score so it always
  pages), blast radius, team history (asset-type confidence from decaying memory).
- **Score replaces severity as the surfaced value.** It is written back onto the finding (full
  ReplacingMergeTree row rewrite — never a score-only row) and is what the API/UI sort and lead
  on; raw severity is demoted to an input.
- **Plan generated only after enrichment.** Ingest (sync/scan/KEV) enqueues an enrich job for
  *every* finding; the decision (`respond.Decide`) is enqueued only when the enriched score
  reaches the pipeline threshold — never on raw severity. A periodic sweep re-enriches as
  context drifts.
- **Sources degrade gracefully.** Each runs under its own timeout with a panic guard; one that
  errors or panics is logged and skipped — the finding is still scored from the rest.

## Consequences

- Nothing is surfaced raw: the product leads with a contextual, explainable score (the
  per-source breakdown is persisted to the `signals` table).
- Adding intelligence is additive and isolated — one small, independently unit-tested `Source`.
- River, not Temporal: enrichment and reasoning are plain fan-out jobs with no long-running
  waits (approval/parking/verify belong to *execution*, which runs synchronously through the
  executor after a person's approval — ADR 087 — so none of that machinery is needed here).
