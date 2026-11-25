# ADR 004 — Anthropic Go SDK called directly

**Status:** accepted · amended by [ADR 084](084-provider-neutral-llm-seam.md) (provider-neutral `internal/llm` seam; Anthropic remains the default backend)

## Context

The reasoning step needs an LLM. An alternative design routes all LLM traffic through a
dedicated gateway service supporting many providers with per-tenant configuration,
failover, and budget guards. Those are multi-tenant requirements that a single-tenant,
self-hosted platform does not have.

## Decision

The reasoning step calls the Anthropic Go SDK directly from inside the relevant River job.
One provider, one API key (cluster secret), no gateway service.

All AI output that drives behaviour (action plans, graph query specs) is **structured
output validated against a schema** before use — never free text parsed optimistically.

## Alternatives considered

- **A separate multi-provider LLM gateway service** — rejected: an extra service, network
  hop, and configuration surface for flexibility a single-tenant deployment does not need.

## Consequences

- One less service and language; reasoning failures surface as ordinary job errors with
  River retry semantics.
- Provider flexibility is sacrificed deliberately; reintroducing an abstraction later is
  additive, not a rewrite (see ADR 084).
