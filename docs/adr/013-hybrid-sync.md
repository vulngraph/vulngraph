# ADR 013 — Hybrid sync: periodic reconciliation + optional event freshness

**Status:** accepted · amended 2026-07-30 (an inventory write must outlive the job deadline)

## Context

The asset graph must stay current. Two models exist: poll the providers on a
schedule (full sync), or react to provider change-events (event-driven). A purely
periodic design (for example a daily job reading hostnames from an external inventory
graph) is the simplest option, but Vulngraph owns its inventory, so it owns the full
ingestion.

## Decision

Run **both**, with periodic full sync as the source of truth:

- **Periodic full reconciliation** (River scheduled job, per connector). This is
  authoritative: it is the only thing that reliably catches **deletions** and
  **drift**, and it is the recovery path if the event pipeline is down. Without
  it, an event-fed graph silently goes stale.
- **Optional event-driven freshness**, layered per connector. An inbound change
  event enqueues a *targeted* sync of just the affected resource, so a newly
  public bucket or a wide-open security group surfaces in seconds, not at the
  next sweep.

Both triggers enqueue River jobs that call the **same `asset.Ingest` path** —
the only difference is scope (whole connector vs one resource).

Event sources differ in cost, so they roll out in order, never blocking the
periodic baseline:

| Provider | Event source | Cost | Status |
|---|---|---|---|
| GitHub | webhook (HMAC-verified) → enqueue job | cheap — do first | **implemented** |
| AWS | EventBridge → SNS → SQS (per account) | infra + IAM per account — opt-in | not built |
| GCP | Cloud Asset Inventory feed → Pub/Sub | infra per project — opt-in | not built |

A connector with no configured event source simply runs on the schedule.

*Implemented (GitHub):* `internal/app/webhook` exposes `POST /api/webhooks/github/{id}`
— an unauthenticated, HMAC-gated route (`X-Hub-Signature-256` verified against the
connector's `webhook_secret` config). A verified content event enqueues an immediate
`SyncConnectorArgs` for that connector; because that job is unique-while-queued, a
burst of pushes coalesces into a single sync rather than a thundering herd. The sync
is currently connector-scoped (re-syncs the whole connector), not yet resource-scoped
— the freshness win lands now; per-resource granularity is a later refinement. AWS/GCP
event sources need per-account/project infra (SQS poller, Pub/Sub subscriber) and roll
out after.

## Consequences

- Correctness never depends on event delivery; freshness improves where events
  are wired.
- One ingest path, one set of collectors — events change *when* a sync runs, not
  *how*.
- The connector model carries an optional event-source config; absent it,
  schedule-only.

## Amendment (2026-07-30) — an inventory write must outlive the job deadline

A sync job shares **one** 30-minute deadline (`SyncWorker.Timeout`) across
collect → ingest → check. Collection is the slow, variable part; the ingest that
follows inherits whatever is left of the deadline. When collection runs long, the
write starts against an already-expired context (the ingest fails with a context-deadline
error) and every collected row is thrown away, leaving assets stale.

The failure is self-reinforcing: stale assets all look changed, so every connector writes
at once, saturates the ClickHouse write semaphore (`chMaxConcurrent` = 8, against
`syncWorkers` = 20), and exhausts the next deadline.

**Decision.** `db.WithWriteBudget` grants an idempotent bulk write a floor of wall-clock
(`assetWriteBudget`, 5 min) even when the caller's context is spent, by re-basing onto
`context.WithoutCancel` plus an explicit timeout. `UpsertAssets` and `UpsertEdges` use it.

Discarding an idempotent upsert because time ran out is strictly worse than finishing
it: the rows are already in memory and the target is a `ReplacingMergeTree`, so
re-running the same write is a no-op. Cancellation is re-based, not lost — the budget
bounds the detached write so a terminating pod still drains, and a pod killed mid-write
simply re-collects next sweep. Chunking to `assetBatchSize` was not the issue; the parent
deadline was.

This treats the symptom at the point where data loss occurs. The contention itself
(sync workers outnumbering ClickHouse write slots) remains, and is the next lever if
discards persist — as is giving the ingest phase its own deadline separate from
collection, rather than a floor carved out of a shared one.
