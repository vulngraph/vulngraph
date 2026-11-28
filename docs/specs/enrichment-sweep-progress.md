# Bounded enrichment sweep progress

An ordinary sweep can repeatedly enqueue the oldest 2,500 findings when their
inputs match the enrichment cache. Those jobs correctly skip rescoring, but do
not change `enriched_at`; a changed finding after that prefix is never admitted.
A real-store regression reproduces this across two sweeps. This is separate from
whether the periodic scheduler is enabled.

Store one drift-enumeration checkpoint in PostgreSQL: the existing millisecond
stale cursor, a fixed pass cutoff, and a compare-and-swap revision. Each execution
resumes this checkpoint within the existing page and 2,500-item budgets.
The cutoff excludes findings rescored after the pass began, so moving sort keys
cannot cause the pass to chase its own completed work. Backfill remains separate.

Select only candidate IDs and their original enrichment seek keys in one
ClickHouse statement; never derive a durable cursor or EOF from a later hydrated
page. The enrichment worker re-fetches current finding inputs by ID.

Read ClickHouse outside PostgreSQL transactions. Commit each queue batch before
advancing the checkpoint. A crash between these steps repeats the batch safely
under existing job uniqueness; an enqueue error cannot advance it. Revision
conflicts fail explicitly, preventing an older sweep from overwriting newer
progress. End of enumeration clears the checkpoint for a later pass. Empty
results, an exactly full last page, and a deleted cursor finding are valid ends.

This checkpoint proves enumeration and admission, not successful scoring.
Failed or discarded jobs and cache/context freshness remain separate acceptance
requirements. Cache hits do not rewrite enrichment scores or observation rows.
The default schedule still repeats every 15 minutes, with each constructor
scheduling its job eight minutes later. A complete pass ends the job. An incomplete
pass now yields with a two-second River snooze and resumes the same durable job;
snoozes do not consume its two failure attempts. Queue pressure also yields
without resetting the cutoff or advancing the cursor. An overlapping periodic
tick shares the existing job, and a worker restart resumes the persisted pass.

Continuations skip alert pruning and the five initial never-enriched probes.
Demand-driven backfill retains its separate singleton, priority and larger queue
ceiling. Routine drift still checks its 1,000-job ceiling and admits at most
2,500 candidates per execution. This increases work per scheduling interval:
whole-pass database reads, CPU, queue depth and urgent waiting must be measured.
The budget is per execution, not per fifteen minutes. No fixed estate-wide
freshness bound is inferred from this change.

A retained one-million-asset synthetic diagnostic demonstrated the scheduling
limit: after the changed wave, 8,207 of 10,392 independently expected static
factors were stale, with no pending enrichment jobs. The remaining ordinary
intervals could not meet that cohort's thirty-minute deadline. That run remains
a failure; continuation does not retroactively accept its results. Updates
behind an already-enumerated cursor still need a later pass, and successful
enumeration does not certify scored completion.

Validation covers the cached-prefix/changed-tail regression, independent worker
instances, restart and wrap, enqueue/store failures, stale checkpoint revisions,
deleted/resolved findings and sort keys moving beyond the fixed cutoff. The
candidate page uses one query and returns at most the existing page limit;
aggregation work still depends on corpus size. The cutoff adds an enrichment
predicate, not another join. Migration 11 adds only operational checkpoint state
and supports rollback. Native CI replays all three small scenarios and retains
the query-cost and correctness artifacts on success or failure.

The 5,001-finding continuation regression passed three fresh local replays
(42.94, 42.93 and 42.92 seconds for the complete test, including fixture setup).
Each pass made 27 bounded candidate-page queries and five initial backfill
queries; a saturated continuation made no finding queries. Peak observed queue
depths were 2,708, 2,750 and 2,733. The changed tail reached the expected static
factor, while an update behind the cursor remained unchanged until the next
manually admitted pass. Source query logs contain no SQL exceptions. These are
functional tests with ClickHouse 26.8.34.13 and PostgreSQL 16 on local Linux ARM64,
not governed whole-system memory or production arrival-rate measurements. Native
AMD64/ARM64 CI repeats the regression; the larger freshness replay remains open.
