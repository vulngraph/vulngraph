# ADR 073 — Force a connector to resync from scratch

**Status:** proposed (sketch only — not implemented)

## Context

Two related but distinct problems sit next to the connector-purge action
(`POST /api/connectors/{id}/purge`, `internal/app/asset/purge.go`):

1. **Purge is for a target that is confirmed gone.** There is no equivalent for a target that
   is still alive but whose collected data the operator no longer trusts — for example a
   connector that has been running against a stale `SyncFingerprint`/`asset_hashes` baseline
   (Postgres, `internal/app/connector`) after an upstream schema or scope change, so most of
   what it "syncs" is a no-op hash diff against data that was itself wrong.
2. **`TriggerSync` (`POST /api/connectors/{id}/sync`) is not a full resync.** It enqueues the
   connector's normal collection job, which diffs against `asset_hashes`/`SyncFingerprint` to
   decide what changed (ADR 054). A connector with a stale baseline keeps comparing new data to
   it; `TriggerSync` alone cannot clear that.

Operators need a way to purge and resync a connector from scratch, and to re-sync specific
scopes faster.

This ADR does **not** propose an automatic sweep. The rule from the purge work carries over:
nothing in this repo infers "the data is wrong" from staleness alone (`jobs/dangling.go`'s
cloud-resource exemption, ADR 049's freshness re-stamp instead of delete). Force-resync must
stay a named, admin-invoked action on one connector at a time, like purge.

## Decision (sketch)

**`POST /api/connectors/{id}/resync`** — admin-gated, no `confirm_name` required (unlike purge,
it is non-destructive to anything but the connector's own hash cache: it forces re-collection,
never deletes assets or resolves findings directly).

1. `connector.Service.ResetSyncBaseline(ctx, id)`:
   - `repo.DeleteAssetHashes(ctx, id, nil)` — clear all rows for the connector (a nil/empty
     `ids` slice means "all": a small signature addition, not a new capability);
   - `repo.SetSyncFingerprint(ctx, id, "")` — the collector's "nothing seen yet" state, already
     the default for a newly created connector.
2. `Syncer.EnqueueSync(ctx, id)` — reuse the existing `TriggerSync` path; no new job kind. With
   the hash cache empty, the collector's first-run behaviour applies: every item hashes as new,
   `UpsertAssets` upserts all of it, and ADR 054's sync-time resolution re-evaluates every
   finding tied to the connector's assets against fresh data. No new finding-lifecycle code.
3. Response: `{"resync_enqueued": true}` — fire-and-forget like `TriggerSync`, since a full
   collection pass has provider- and size-dependent duration and no synchronous completion
   signal.

**Explicitly out of scope for `/resync`:**

- Deleting existing assets first. A stale baseline does not mean the assets are wrong, only
  that the diff may have skipped real changes. Re-collecting is enough; existing rows are
  overwritten by the fresh upsert.
- A cross-connector "resync everything" variant. That has a materially different blast radius
  (concurrent load on every provider's rate limits at once, such as GitHub API rate limits) and
  would need its own throttled fan-out design: one River job per connector using the existing
  per-queue worker counts, so periodic work never starves agent runs. Not built here.

## Consequences

- A connector stuck on a bad baseline gets one explicit, non-destructive lever, distinct from
  and never confused with purge's irreversible one.
- No new job kind and no new finding-lifecycle path — reuses `TriggerSync`'s enqueue and ADR
  054's sync-time resolution.
- `DeleteAssetHashes` would need to accept "all ids for this connector" (it currently takes an
  explicit `ids []string`) — a small repo change, not a new table or migration.
- Building it is a small follow-up: one repo signature change, one service method, one handler,
  one OpenAPI path item — the same shape as purge, smaller since there is no asset/finding
  cross-domain wiring.
