# ADR 003 — Postgres + ClickHouse; graph lives in ClickHouse

**Status:** accepted — *graph-storage decision superseded in part by ADR 025/026*

> **Update:** "two data stores only" and "graph lives in ClickHouse" held until ADR 025.
> ClickHouse remains the durable system of record for nodes/edges, but multi-hop traversal
> now runs on an in-memory **Ladybug** graph engine embedded in the worker pod (ADR 025/026).
> Ladybug is a disposable projection of ClickHouse, not a third source of truth — the storage
> model below is otherwise unchanged.

## Context

A multi-service, event-driven design typically adds a message broker (to fan events
across services) and a lock/cache store such as Redis alongside the relational and
analytical databases. Each additional store is another stateful service to run, back up,
and keep consistent.

## Decision

Two data stores only:

- **Postgres** — users, sessions, connectors, action outcomes (decaying memory),
  River jobs, scan runs. Everything transactional.
- **ClickHouse** — assets, **graph edges**, findings, signals, audit events.
  Everything append-heavy and analytical. All tables `ReplacingMergeTree` + TTL
  (audit: plain MergeTree, 7-year TTL).

Graph nodes/edges live in ClickHouse (not Postgres recursive CTEs) because the Explore
feature compiles `GraphQuerySpec` into parameterized ClickHouse queries — one store, one
compiler, no cross-store stitching. Blast radius is bounded-depth iterative expansion.

A message broker is replaced by River jobs (durable work) and in-process pub/sub (SSE
updates). Redis is not used at all.

## Consequences

- `docker compose up` needs two containers; a Kubernetes deployment needs two stateful
  services.
- Graph traversals are bounded by spec budgets (max nodes/edges/hops) — enforced at the
  contract layer, which Explore requires anyway.
