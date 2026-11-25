# ADR 002 — River job queue replaces Temporal

**Status:** accepted · amended 2026-08-04 (a queue is a pod-affinity lane, not a concern), 2026-08-24 (graceful soft stop on shutdown) · superseded in part by ADR 087 (no execute-class jobs)

## Context

The agentic loop (observe → reason → plan → gate → execute → verify → audit) needs durable,
crash-resumable orchestration. A common design uses Temporal plus Redis SETNX locks, which
spreads workflow state across three consistency domains (Temporal, Redis, the databases)
and adds two external services to operate.

## Decision

[River](https://riverqueue.com) — a Postgres-backed job queue that runs in-process.
The agentic loop becomes a job chain: each phase persists its result, then enqueues
the next job.

**Enqueue is best-effort `client.Insert` wherever the domain write lands in ClickHouse.**
ClickHouse cannot join River's Postgres transaction, so there is no shared tx to enlist
the enqueue in. A dropped enqueue is recovered by the periodic sweep + freshness backstop
(the sweep re-finds work whose follow-up job was lost to a crash between the domain write
and the `Insert`). See `internal/jobs/enrich.go` for the rationale in code. Where the
domain write is in Postgres, the enqueue goes on the same transaction with `InsertTx`.
Today the one such path is scan profile runs
(`scan.PGProfileRepo.CreateRunForProfileAndEnqueue` → `jobs.Enqueuer.EnqueueProfileScan`).

Guarantee mapping:

| Temporal/Redis mechanism | River replacement |
|---|---|
| Durable execution, crash-resume | Jobs in Postgres; rescued and retried on worker death |
| `MaximumAttempts: 1` on execute | No execute-class jobs (ADR 087): execution is a synchronous, human-driven `executor.Service.Execute` call with no retry |
| Redis SETNX idempotency lock | River `UniqueOpts` (`ByArgs` + `ByState`; see `internal/jobs/correlate.go`, `enrich.go`) |
| Separate task queues (starvation) | Per-queue worker pools (see 2026-08-04 amendment) |
| Approval timers (JIT, 1h/4h) | No parked or snoozed job: the govern email token (48h, single-use nonce) plus the executor grant (10 min, one execution via `GrantLedger`) |

## Alternatives considered

- **Temporal** — rejected: an external workflow engine with its own state store, and a
  dual-write problem between workflow state and domain state.
- **Hatchet** — rejected: it is a separate orchestrator service reached over gRPC,
  re-introducing the external-workflow-engine topology (and the dual-write problem).
- **Asynq** — rejected: introduces Redis.

## Consequences

- Job *state* is durable in Postgres; the **domain** write (ClickHouse) and the
  follow-up enqueue are not atomic (see Decision). The periodic sweep + backstop
  is the recovery path for an enqueue lost to a mid-chain crash — eventual, not
  transactional. This is the deliberate cost of a ClickHouse store of record.
- Cloud mutations do not run as jobs (ADR 087). `executor.Service.Execute` runs
  synchronously on a human request and is never retried.
- No DAG/fan-in primitives; our pipeline is a linear chain, so none are needed.

## Amendment (2026-08-04) — a queue is a pod-affinity lane, not a concern

The original framing was one queue per *concern* with an explicit worker count. That
framing does not match how River works and led to routing defects.

**River's producer fetches by queue and never by kind.** Consuming a queue is therefore
an unconditional promise to work *every* kind routed to it. A queue's real meaning is
"work this pod can execute" — pod affinity — and concern is at best a naming convention
on top. A single queue shared by two pods with different worker registrations means each
pod fetches jobs it has no worker for, and those jobs stall.

**Decision.** Routing is declared once and derived everywhere else, in
`internal/jobs/routing.go`:

- `allJobArgs()` lists every `JobArgs` type in the package; `queueOfKind()` derives the
  kind → queue table from each type's own `InsertOpts().Queue`. A kind declaring no
  queue maps to `""` and is registered nowhere — River's default queue is literally
  `"default"` and no client consumes it.
- `consumedQueues(rescueOnly)` derives the set a client may consume from the kinds it
  registered a **real** worker for. A hand-maintained per-pod queue list cannot express
  the fetch-by-queue promise; here a queue cannot be consumed unless a real worker for one
  of its kinds exists on that client.
- `heavyScanKinds` declares, by kind, the jobs that do resource-heavy work (a nuclei
  run, a registry pull-and-unpack); `heavyScanLanes()` derives the queues
  from it. Giving one of them a new lane shows up as a new heavy lane rather than as
  extra concurrency nobody chose. `scan` and `content_scan` are both capped at
  `heavyScanWorkers = 1`, so a pod runs at most one heavy scan at a time.
- `queueWorkerCounts` lists **every** queue, including the ones that take 1. Relying on
  River's absent-means-1 default is how splitting a queue silently multiplies
  concurrency: routing and parallelism are separate concerns. Because the worker pod is
  memory-bound, an unplanned extra concurrent heavy job can exhaust its memory, so
  concurrency must always be an explicit choice.

The lanes are `sync`, `enrich`, `respond`, `correlate`, `dangling`, `maintain`,
`graph`, `reenrich`, `adjudicate`, `scan`, `content_scan`. Several exist purely to stop
one long job from occupying a slot another needs — `adjudicate` (a sweep bounded by
`adjudicateJobTimeout` = 20 min, off `respond`), `dangling` (a resolve sweep off
`enrich`/`correlate`), `reenrich` (full-pass rounds off `enrich`). That is starvation
isolation, a scheduling property, not a concern boundary.

A queue may still carry a kind a given client cannot work, but only when that kind's
producer is gated by the same dependency as its worker (`refresh_scc` rides `enrich` and
is enqueued only when the SCC dependency, and therefore the SCC worker, is wired).

**Consequences.** The routing table is code, not prose, and is pinned by guard tests in
`internal/jobs/queue_registration_test.go`: `TestAllJobArgsMatchesDeclaredKinds`,
`TestEachPodOnlyConsumesQueuesItCanWork`, `TestEveryKindIsConsumedBySomePod`,
`TestEveryJobRoutesToARegisteredQueue`, `TestEveryQueueDeclaresItsConcurrency` and
`TestHeavyScanLanesAreSerial`. Adding a queue without a worker count, or a pod that
fetches a kind it cannot work, fails CI.

## Amendment (2026-08-24) — graceful soft stop on shutdown

River jobs are durable, but durability only means a killed job is marked retryable and
tried again; it says nothing about how often jobs are killed mid-run.

`cmd/graph/main.go` passes its `signal.NotifyContext` (SIGINT/SIGTERM) context into
`river.Client.Start`. With `Config.SoftStopTimeout` unset, River's work context inherits
directly from the start context, so cancelling it is equivalent to `StopAndCancel`: every
in-flight job is cancelled the instant a shutdown signal arrives, with no grace period.
Every rolling deploy therefore restarted all in-flight work from scratch, and long jobs
such as the correlate full sweep could be starved of an uninterrupted window.

**Decision.** `river.Config.SoftStopTimeout` is set on both electable clients
(`workerSoftStopTimeout` = 20s, `scannerSoftStopTimeout` = 100s,
`internal/jobs/client.go`), each sized with a margin inside that pod's
`terminationGracePeriodSeconds` (50s / 120s) so River's post-soft-stop cleanup finishes
before Kubernetes escalates to SIGKILL. This lets short jobs complete across a deploy. It
does **not** rescue a correlate full sweep or any other job whose runtime exceeds the
margin — those are still cancelled, and are recorded as `"cancelled"` rather than
`"error"` in `graph_correlate_sweeps_total` (`correlateSweepStatus`,
`internal/jobs/correlate.go`) so routine redeploys do not inflate an error ratio. Pinned
by `TestEveryElectableClientConfiguresSoftStopTimeout` (`internal/jobs/client_test.go`).
