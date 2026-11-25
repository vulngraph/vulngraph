# ADR 008 — No monitoring/error-tracking stack

**Status:** superseded by [ADR 037](037-observability.md) (2026-07-06) — a
vendor-neutral, env-gated `/metrics` endpoint and OTLP tracing were added. The
error-tracking-stack rejection (no Sentry/GlitchTip) still stands; only the
"no metrics endpoint, no tracing libraries" clause is reversed.

## Context

Multi-service platforms typically ship an error tracker, per-service metrics endpoints,
and distributed tracing infrastructure. For a single self-hosted binary much of this is
overhead: there are no service hops to trace and no fleet to aggregate.

## Decision

Structured zerolog (via `pkg/log`) to stdout, collected by whatever the cluster already
does with container logs. The audit trail lives in ClickHouse `audit_events` (7-year TTL)
as a domain feature, not an observability bolt-on. No Sentry/GlitchTip, no metrics
endpoint, no tracing libraries.

## Consequences

- Debugging = logs + the audit trail + River's job tables (which expose failures and
  retries queryably in Postgres).
- If a metrics endpoint is ever genuinely needed, it is one additive handler — the
  decision can be reversed cheaply (as ADR 037 later did).
