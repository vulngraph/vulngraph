# ADR 055: Dangling-finding resolve sweep

**Status:** accepted (2026-07-13)

## Context

ADR 054 gave findings a lifecycle: `resolved_at` is stamped at sync time when an
emitting check re-runs on a still-present resource and no longer reports the
finding (fixed), or when a connector's hash-diff detects the resource was
deleted. Two gaps in that design leave findings dangling:

1. **Provider-native feeds are not diff-reconciled.** GuardDuty and SCC emission
   sets are provider-controlled (archival, pagination windows), so ADR 054
   deliberately does not diff them — a partial fetch must never mass-resolve real
   threats. They resolve only via resource deletion.
2. **The deletion path only revisits resources a connector still tracks.**
   `findDeletedAssets` works from a per-connector hash-diff of the current sync.
   A resource that was already gone before the lifecycle existed, or that a
   connector no longer enumerates, is never revisited, so its findings never
   resolve.

The result is open findings that reference a `resource_id` with no current asset
row. The typical case is a provider-native threat finding (for example GuardDuty)
on an EC2 instance that has since been terminated. Absent a sweep, these sit in
every list, tile, and rollup until the 365-day TTL evicts them — noise that buries
live risk.

## Decision

A periodic `DanglingSweepWorker` (`internal/jobs/dangling.go`) complements ADR
054's sync-time resolution. Each tick it pages open findings, asks the asset
store which of their `resource_id`s still have an asset row
(`asset.Service.ExistingIDs` → `SELECT DISTINCT id FROM assets WHERE id IN (…)`,
bloom-indexed point lookup), and calls `finding.Service.Resolve` on those with
none. It runs the whole job inline — resolution is a cheap batch ClickHouse
rewrite, so per-finding fan-out (the enrich model) would be pure overhead.

**The join key must be exact, and it is not universally so.** A finding is
resolved only when its `resource_id` is byte-identical to an asset id — so "no
asset row" means "resource gone", not "different id scheme". Only
`(source, resource_type)` pairs verified 1:1 are swept (`danglingJoinSpecs`);
every other finding is left to the TTL rather than resolved on a guess:

| source / resource_type | join key | swept? |
|---|---|---|
| `aws_guardduty` / `ec2_instance` | resource_id = EC2 instance id = asset id | **yes** (most common orphan class) |
| `aws_guardduty` / `s3_bucket` | resource_id = bucket name = asset id | **yes** |
| `aws_guardduty` / `iam_user` | resource_id = user **name**; asset id = **ARN** | no — would never match, would wrongly resolve all |
| `aws_guardduty` fallback types | resource_id = generic GuardDuty type label | no — not an asset id |
| `gcp_scc` | resource_id = `project/instance` path / raw SCC name | no — correspondence to `gce_instance` asset id unverified |
| `ghas_*` / `iac` (`github_repo`) | resource_id = repo FullName = asset id | no — GitHub collection can be rate-limited, so a missing repo asset ≠ deletion (GHAS findings on a live repo close when GitHub reports the alert closed; ADR 054) |
| `cspm` | — | no — already reconciled at sync (ADR 054) |

**Rate limiting.** Two per-tick bounds, mirroring the enrich sweep's
backpressure so a large orphan backlog drains over several ticks rather than in
one burst:

- `danglingResolveMax` (3000) — findings resolved per tick, the drain rate and
  the ClickHouse write bound. With an hourly cadence a backlog drains over
  successive ticks, after which the sweep only handles whatever the deletion path
  missed since.
- `danglingScanMax` (25000) — a per-source ceiling on findings *examined*, a
  safety valve against a source that unexpectedly balloons. When a backlog exists
  a tick is expected to reach the resolve cap before this; hitting it is logged as
  a warning.

The sweep is an always-on base periodic (like KEV/OSV), registered identically
on the worker and scanner clients so whichever pod River elects leader enqueues
it; only the worker consumes the dedicated `dangling` queue (1 worker), isolated
so the resolve sweep never blocks enrich or correlate. `RunOnStart: false` keeps
it off the deploy-time thundering herd — the TTL is the ultimate floor, so there
is no boot urgency.

## Consequences

- The orphaned-finding backlog drains over successive ticks and then trends
  toward zero; provider-native findings on deleted resources leave worklists
  without waiting for the TTL.
- Resolution is reversible by the same mechanism as ADR 054: if a resource
  reappears and the feed re-emits the finding, `RecordObserved` clears
  `resolved_at` (RMT full-row rewrite) and it reopens.
- **Accepted risk — coverage-gap false resolve.** If a resource is live but the
  platform never collected it as an asset (e.g. a region/account GuardDuty
  watches but the EC2 collector is not scoped to), the sweep sees "no asset row"
  and resolves a real finding. Mitigated by (a) restricting to `(source,
  resource_type)` pairs whose collectors share the same assumed-role/coverage as
  the feed, and (b) reversibility on re-observation. New pairs must not be added
  until their asset coverage is confirmed to match the feed's.
- Extending the sweep is a matter of verifying a new `(source, resource_type)`
  join key and adding it to `danglingJoinSpecs` — `gcp_scc` and the GHAS/IaC repo
  findings are the next candidates once their id correspondence / collection
  reliability is confirmed.
