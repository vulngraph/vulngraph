# ADR 007 — AWS + GCP + GitHub only; focused CIS check set

**Status:** accepted; amended 2026-07-15 — the connector and compliance scope
below have both been overtaken. Connectors now cover **AWS, Azure, GCP, GitHub,
Google Workspace, Kubernetes, and Okta** (`internal/collect/`), not just the
AWS + GCP + GitHub of this ADR. The "no gap-analysis reports, no framework matrix"
clause is **reversed by [ADR 029](029-multi-framework-compliance.md)**
(multi-framework compliance). The original scoping rationale below is retained as
history; treat the provider list and the single-framework compliance limit as
superseded.

## Context

Security posture platforms can cover a very wide set of providers (multiple clouds, SCM
systems, productivity suites, device management) with hundreds of posture checks and full
framework gap-analysis reporting. Each provider and framework is ongoing maintenance.
For a self-hosted, single-tenant platform, breadth should follow actual need rather than
lead it.

## Decision

- Connectors: **AWS, GCP, GitHub** — the initial provider set.
- Checks: a focused core of the highest-value CIS checks per provider, implementing
  CIS Benchmark controls (no third-party check text is reused). The check *registration pattern* is
  the deliverable; the catalogue grows incrementally.
- Compliance: a static check→CIS-control mapping (`go:embed`) and one coverage view.
  No gap-analysis reports, no framework matrix.

## Consequences

- Adding a provider later means a new connector package + checks — additive work (as the
  amendment above shows).
- Compliance answers exactly one question ("which CIS controls are passing?") and is
  allowed to stay that small (later reversed by ADR 029).
