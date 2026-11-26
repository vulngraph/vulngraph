# Docs

New here? [`getting-started.md`](getting-started.md) takes you from `docker compose up` to a working
install with demo data, then your own cloud, then production. [`examples.md`](examples.md) and
[`queries.md`](queries.md) show what it can do, and [`evaluating.md`](evaluating.md) is for deciding
whether to trust it with access to your cloud. [`threat-model.md`](threat-model.md) sets out the
trust boundaries and what is and is not defended.

To understand the code, start here, in this order:

1. [`architecture.md`](architecture.md) — the architecture overview: the
   stores, the collect → correlate → decide → learn pipeline, and how it is
   kept safe. Read this first.
2. [`adr/README.md`](adr/README.md) — the historical record: significant
   decisions already made, what was considered and rejected, and why. Check
   here before re-proposing something.
3. [`specs/README.md`](specs/README.md) — how a larger change can be proposed
   as a short spec before implementation; a durable decision earns an entry
   in `adr/`.
4. [`connector-sdk.md`](connector-sdk.md) — how to add a collector, check or
   scanner in-tree (a source change plus its registration, which the guide
   locates for each: a scanner registers in two pods). To feed
   findings from an external tool without code changes, use
   `POST /api/scans/import`; to feed a VM's installed packages from your
   own scanner, see [`iam/byoa-inventory.md`](iam/byoa-inventory.md).

## Reference

- [`capabilities.md`](capabilities.md) — what each part of Vulngraph does, in
  detail, with its limits (the README has the summary).
- [`examples.md`](examples.md) — what it looks like: real screenshots and recordings from the
  bundled demo account, with the queries behind them. [`demo.md`](demo.md) describes that account.
- [`connecting.md`](connecting.md) — step by step for AWS, GCP, Azure, GitHub, Okta, Google Workspace and
  Kubernetes, including workload identity.
- [`../ROADMAP.md`](../ROADMAP.md) — where the project is heading, and what it will not do.
- [`faq.md`](faq.md) — short answers on write access, LLMs, egress, freshness and what it is not.
- [`known-limitations.md`](known-limitations.md) — gaps that affect what
  Vulngraph reports, and what it does about each.
- `COVERAGE.md` — CSPM/CIEM check coverage against your own data. Not checked
  in (it reflects whatever estate you point Vulngraph at); generate your own with
  `go run ./cmd/coverage-gen`.
- [`iam/`](iam) — IAM policies and setup for cloud-side read access this
  platform's connectors need (read-only grants, not app config), and the
  minimum GitHub App, Okta and Google Workspace grants
  ([`iam/identity-and-code-connectors.md`](iam/identity-and-code-connectors.md)).
  The built-in cloud roles they name allow more reads than the collectors
  make: AWS `SecurityAudit` and `ViewOnlyAccess` (see
  [`onboarding-aws-org.md#permissions`](onboarding-aws-org.md#permissions)),
  GCP `Viewer` (see [`iam/gcp-cspm-permissions.md`](iam/gcp-cspm-permissions.md),
  which also gives a custom role with only the collector's reads) and Azure
  `Reader`, which is `*/read` on the subscription.
- [`migrations.md`](migrations.md) — migration numbering rules (strict order,
  contiguous numbers) and what enforces them.
- [`pipeline-benchmarks.md`](pipeline-benchmarks.md) — generate synthetic inventory
  and measure database work, graph refresh throughput and memory locally or in CI.

