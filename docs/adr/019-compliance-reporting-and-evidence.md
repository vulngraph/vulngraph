# ADR 019 — Compliance reporting with frozen evidence

**Status:** accepted (extends ADR 007) — **not yet implemented** (2026-07-18)

> The decision below stands as the design, but as of 2026-07-18 none of it is built: there
> is no `internal/app/report/` domain, no `compliance_reports`/`compliance_control_evidence`
> tables or migration, no `REPORT_INTERVAL` job, and no `/api/compliance/reports*` endpoints.
> Only the live `GET /api/compliance` view from ADR 007 is registered. Treat this as an
> accepted-but-unbuilt design record.

## Context

ADR 007 scoped compliance to one live question — *which CIS controls pass right now* — computed on read by `compliance.Service.Compute` (lists `source:"cspm"` findings, fails a control if any mapped `CheckID` has an open finding). That is deliberately tiny and stays useful for the dashboard.

But periodic compliance reporting for an audit needs something `Compute` cannot give: a **durable, point-in-time attestation** — "on 2026-06-13, control X passed, and here is the evidence." Two facts make a naive "store what Compute returned" wrong:

- **Findings are mutable and expiring.** The `findings` table is `ReplacingMergeTree(synced_at)` with a 365-day TTL; rows get replaced on every re-sync/re-enrich and dropped after a year. A live foreign-key to a finding is not reproducible months later — exactly when an auditor asks.
- **Report cadence ≠ scan cadence.** Enrichment/response run async and best-effort after a scan (`jobs/enrich.go`), so a report chained to a specific scan's completion would snapshot half-scored findings. River has no join/barrier; building one is complexity a weekly report doesn't need.

(`finding.repo.List` already dedups with `argMax(col, synced_at) … GROUP BY id`, so the read itself is consistent — the problem is mutability over time, not within a read.)

## Decision

A new `report` domain (`internal/app/report/`, four-file layering per ADR 010) produces **immutable, point-in-time, evidence-frozen compliance reports.**

- **Decouple cadence.** A weekly periodic job (config-gated `REPORT_INTERVAL`, mirroring `scanPeriodicJobs` in `jobs/scan.go`) generates a report from current steady-state findings — *not* chained to a scan. The pipeline re-enriches every finding every 30 min, so a weekly report reads a long-converged state. A soft guard (snooze if too many findings are un-enriched) covers the "a scan landed minutes ago" case; no River barrier.
- **Freeze evidence.** For each control, the report records its supporting/failing findings by **copying the finding fields** (id, check_id, severity, score, score_band, resource_id, detected_at, title) into the report's own rows. Evidence is a frozen copy, never a live reference — so the report is reproducible after findings mutate or TTL out. This is the load-bearing property of the feature.
- **Store append-only in ClickHouse, audit-grade retention.** Model on `audit_events` (plain `MergeTree`, `TTL ts + INTERVAL 7 YEAR`) — compliance artifacts are audit data, not the 365-day operational findings table. Two tables: `compliance_reports` (header: id, framework, generated_at, total, passing) and `compliance_control_evidence` (one row per report×control×finding, carrying the frozen fields). Report id is **deterministic per (framework, week-bucket)** so a retried job upserts instead of duplicating.
- **Framework-parameterized from day one.** `framework` is a column + a parameter on `Generate` and every endpoint, even though only `cis` is valid in v1. Adding ISO 27001 / SOC 2 is then a pure addition — an in-code `Framework{ID, Controls[]}` taxonomy entry + its control→check mapping — with no schema, endpoint, or model change. Many ISO/SOC2 controls map to the same checks via the same `CheckID` join.
- **Read surface.** Keep live `GET /api/compliance` (recomputed current view). Add `GET /api/compliance/reports` (keyset-paginated headers = the trend feed, ADR 018), `…/reports/{id}` (report + frozen evidence), `…/reports/latest?framework=`, and `…/controls/{id}/timeline` (per-control pass/fail across snapshots). OpenAPI domain file updated in the same commit (ADR 017). PDF/ZIP export is deferred and, when added, renders a stored (already-frozen) report — never recomputes.

## Consequences

- Durable, reproducible audit evidence + a posture trend fall out for free from timestamped immutable rows.
- This **expands ADR 007's "allowed to stay that small"** — stated plainly. The live view stays minimal; the historical/attestation layer is the new `report` domain beside it.
- Storage scales with *open* findings per weekly report (passing controls store check-level, not per-finding, evidence); the `MergeTree` + 7-year TTL bounds it.
- ISO 27001 / SOC 2 and export are additive later, not rework.
