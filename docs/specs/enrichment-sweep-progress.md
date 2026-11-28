# Bounded enrichment sweep progress

An ordinary sweep can repeatedly enqueue the oldest 2,500 findings when their
inputs match the enrichment cache. Those jobs correctly skip rescoring, but do
not change `enriched_at`; a changed finding after that prefix is never admitted.
A real-store regression reproduces this across two sweeps. This is separate from
whether the periodic scheduler is enabled.

Store one drift-enumeration checkpoint in PostgreSQL: the existing millisecond
stale cursor, a fixed pass cutoff, and a compare-and-swap revision. Each ordinary
sweep resumes this checkpoint within the existing page and 2,500-item budgets.
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
The default schedule repeats every 15 minutes, with each constructor scheduling
its job eight minutes later; a large corpus can need multiple ticks. No fixed
estate-wide freshness bound is inferred from this change.

Validation covers the cached-prefix/changed-tail regression, independent worker
instances, restart and wrap, enqueue/store failures, stale checkpoint revisions,
deleted/resolved findings and sort keys moving beyond the fixed cutoff. The
candidate page uses one query and returns at most the existing page limit;
aggregation work still depends on corpus size. The cutoff adds an enrichment
predicate, not another join. Migration 11 adds only operational checkpoint state
and supports rollback. Native CI replays all three small scenarios and retains
the query-cost and correctness artifacts on success or failure.
