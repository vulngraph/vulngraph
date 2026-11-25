# ADR 028 — Per-field drift change history

**Status:** accepted · amended 2026-08-12 (change-log values capped at 1 KiB)

## Context

Drift detection (ADR 022's content-hash diff + the exposure-edge deltas) could tell you
*that* an asset changed and whether it gained/lost internet exposure — but not *what*
changed. The only versioned fields were public IP and name (curr/prev, two generations, in
`connector_asset_hashes`). "What changed on this asset, and when" — the question a responder
actually asks during an investigation — was unanswerable. The useful answer is of the form
"this bucket went public at 14:32, here is the exact config delta", not "something changed."

The data to answer it already flows through the sync diff: `SyncWorker` computes
`changedAssetIDs` by comparing each freshly-collected asset's `ContentHash` to the stored
one. At that moment both the new asset and (via a cheap `ByIDs` read) the pre-write version
are available — a field-level diff is one comparison away.

## Decision

An append-only per-field change log, written at the existing sync diff chokepoint.

- **`graph.asset_change_log`** (ClickHouse): `(asset_id, field,
  old_value, new_value, connector_id, changed_at)`. Plain `MergeTree`, 7-year TTL — an
  audit log, never deduplicated (each change is a distinct historical fact), matching the
  audit-table retention standard.
- **`asset.DiffFields(old, next)`** produces field-level changes over core fields + every
  tag + every metadata key (added/removed/changed). One `FieldChange` per differing field.
- **Sync wiring:** for assets that *existed and changed* this sweep (not new assets — nothing
  to diff against), `SyncWorker` batch-fetches the pre-write versions (`ByIDs`), diffs them
  against the new ones, and appends the change rows. Best-effort and capped — the timeline is
  observability; a failure here never affects the sync itself.
- **Surfaces:** `GET /api/assets/{id}/changes` + an `AssetChangeTimeline` on the asset detail
  page (before→after per field, newest first; hidden on stable assets).
- **Companion fix:** the previously stored-but-unwired scan-profile cron scheduling is now
  live (`ProfileScheduleWorker` per-minute tick, reusing `cronexpr.Due` (`pkg/cronexpr`) from ADR 027) — profiles
  with a cron actually fire, alongside the existing manual + drift triggers.

## Consequences

- "What changed and when" is fully answerable per asset, from the data already moving through
  sync — no new collection, just a diff + append at the chokepoint.
- **Trade-off:** granularity is per-field on *collected* config (the asset's metadata/tags/
  core fields). It is not a full resource-config diff (we store what collectors surface, not
  the raw cloud API response), and it captures change at sync cadence (ADR 013), not the
  instant of the cloud mutation. Genuinely fast-moving fields between syncs collapse to a
  single curr→next delta.
- The change log is append-only and TTL-bounded; it never feeds scoring or correlation —
  purely a responder-facing timeline, so a write failure degrades gracefully.
- The snapshot-diff framework (`internal/app/scan/snapshot.go` — TLS/cert/ports/headers) that
  predates this remains unwired; posture-delta drift via active capture is not built (it needs
  the scanner to capture+persist snapshots, marginal vs the config change log).

Cites ADR 022 (content-hash diff this builds on), 013 (sync cadence — why it's near-real-time
not instant), 023 (provenance — connector_id on each change row), 027 (`cronexpr.Due` reuse for the
profile scheduler), 003 (ClickHouse audit-table conventions).

## Amendment (2026-08-12) — change-log values are capped at 1 KiB

Storage for `graph.asset_change_log` is dominated by `old_value` + `new_value`, and a few
metadata fields dominate those: expanded-permission blobs such as `meta:permissions` (and to
a lesser extent `meta:policies`) on IAM principals can be very large and may differ on every
observation, so each sync writes large, never-deduplicated rows. Retention is not the main
lever, since the cost accrues from fresh rows.

Nothing consumes those bytes. The log is "purely a responder-facing timeline" that "never
feeds scoring or correlation", and there is exactly one reader — `selectChangeLog`
(`internal/app/asset/repo.go`), surfacing `AssetChangeTimeline` on the asset detail page,
newest 100 rows. A timeline does not need to render large JSON blobs in full.

`asset.DiffFields` now caps each stored value at `changeValueCap` (1 KiB) via
`capChangeValue`, appending the true length and a sha256 prefix of the full value. The
digest is load-bearing: without it, two different oversized values sharing a 1 KiB prefix
would store identically and a capped row would read as "nothing changed". Per-field change
*detection* is unaffected — the comparison runs on uncapped values.

Two things deliberately not changed:

- **`field` keeps `LowCardinality(String)`.** The concern was that `tag:<anykey>` /
  `meta:<anykey>` make its domain unbounded. The number of distinct field names is expected to
  stay well within `LowCardinality`'s comfortable range, and removing it would grow the
  column several-fold. Worth revisiting if distinct values reach the tens of thousands — and
  treating that as a collector-churn signal (a single volatile collector field can dominate
  row counts) rather than a schema problem.
- **Retention and partitioning stay as they are.** A 7-year TTL on derived cloud-config
  observations is harder to defend than on `audit_events`, which is a compliance artifact,
  but with values capped the table is no longer expensive and the change is not urgent.
  Partitioning by `toYYYYMM(changed_at)` — which would make TTL eviction a part drop instead
  of a part rewrite — belongs with the wider partition-key work, not here.
