# ADR 001 — Single Go binary, single-tenant, self-hosted

**Status:** accepted · amended 2026-10-23 (dormant tenancy scaffolding removed) · amended 2026-10-24 (the serve-to-worker RPC seam named in Consequences)

## Context

Vulngraph is a self-hosted security platform: each deployment serves the one organisation
that runs it. The goal is operational simplicity: no distributed coordination, no tenancy
machinery, no multi-tenant control plane to operate.

## Decision

One Go binary (`graph`) containing the HTTP/RPC server, background workers, migrations,
and user management as subcommands. Single-tenant: no `tenant_id` anywhere. Deployment
topology (public exposure, network policy, ingress) is left to whoever operates it — the
binary itself makes no assumption either way.

## Consequences

- No service mesh, gateway or request signing to maintain. One internal seam needs
  authentication: serve (when it has no graph replica of its own) and the scanner query
  the worker's graph engine over an HTTP RPC (`LADYBUG_INTERNAL_PORT`, default 8090),
  authenticated with a shared secret, `LADYBUG_RPC_SECRET`, that the operator generates,
  gives to each of those processes and rotates ([ADR 041](041-ladybug-serve-worker-rpc.md)).
  Without the secret the worker refuses to start the listener unless
  `LADYBUG_RPC_INSECURE=true`. The same binary runs as `serve`, `worker`, `scanner`,
  `migrate` and `node-posture`. Apart from that RPC, and the node-posture reader's
  stdout, which the worker reads through the Kubernetes API, the processes share only
  Postgres and ClickHouse.
- Vertical scaling only — acceptable for a single deployment's asset volume; an
  organisation with multiple independent estates runs multiple instances.

## Amendment (2026-10-23) — dormant tenancy scaffolding removed

`graphstore` carried dormant multi-tenant scaffolding (`tenantDBs`/`EvictLRU`) that no code
path ever populated. It is deleted; the single-tenant decision stands, and multi-tenancy, if
it is ever wanted, starts from a new ADR.
