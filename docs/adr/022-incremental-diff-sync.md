# ADR 022 — Incremental, diff-based sync

**Status:** accepted — implemented (phased; the `connectors.sync_fingerprint` column,
`ContentHash`/`CurrentHashesByConnector`, the diff in `internal/jobs/sync.go`). Amended
2026-07 (check-registry identity rides the fingerprint), 2026-08-02 (the diff gates evaluation,
not observation) and 2026-08-21 (presence/content split deliberately not built).

## Context

The reconciliation sweep (ADR 013) re-writes the world every cycle. `SyncWorker.Work` calls `UpsertAssets` for every collected asset (a fresh `synced_at` row) and `enqueueEnrich` for every finding — every 30 minutes, whether or not anything changed. In steady state where nothing moved, a sweep still pays the full ClickHouse write + merge cost and re-scores every finding. There is no change detection: no content hash, no diff.

This is the sync-side twin of the problem ADR 021 solved on the reasoning side. ADR 021 stops re-*reasoning* unchanged findings (the LLM gate); this stops re-*writing* and re-*enriching* unchanged assets and findings at the source.

## Decision

**Content-hash diffing in the sync write path.**

1. **Hash each collected asset/finding over semantic fields only** — type, provider, region, account, endpoint, IPs, domain, tags, metadata, risk-relevant fields — excluding `synced_at`/`last_seen`/`discovered_at`, with canonical map/tag ordering (or nothing ever matches).
2. **Bulk-load the current `(id → hash)` snapshot for the connector in one `argMax … GROUP BY` read** (one query per sweep, not per asset) and diff in memory.
3. **Act on the diff:** new/changed → write the new version and enqueue enrich; unchanged → do not bump the version, do not enqueue enrich; gone (present before, absent now) → mark stale/deleted.
4. **Per-connector fast path:** a rolling `sync_fingerprint` over all the connector's asset hashes, stored on the connector. If it equals last sweep's, short-circuit the whole connector — skip write + enrich entirely. One comparison handles "this account didn't change."

In steady state a sweep writes almost no versions and enqueues almost no enrich jobs.

**Three traps that make this correct rather than silently broken:**

1. **Separate presence from content.** Deletion detection relies on the full re-write aging out missing rows. If unchanged writes are skipped, `last_seen` stops advancing and live assets wrongly look deleted. Track "I saw it" independently from "it changed."
2. **ClickHouse is append-only** — there is no cheap in-place `last_seen` update (an `ALTER UPDATE` is an expensive mutation; a heartbeat row insert defeats the write saving). So **presence/`last_seen` lives in Postgres** (cheap batched upserts keyed by connector + asset id), content stays in ClickHouse written only on change; deletion = PG presence older than N sweeps. This matches the existing split — operational state in PG, analytical in CH.
3. **Enrich must re-trigger on context change, not just finding change.** A finding's score can change while its bytes are identical, because enrichment depends on external inputs (KEV refresh, correlate/blast-radius, decaying-memory per ADR 005). So the blind 30-minute "re-score everything" sweep is replaced by input-driven re-enqueue: re-enqueue enrich when (a) the finding's hash changed, (b) a KEV/intel feed delta touches its CVE, or (c) correlate/blast-radius changed for its asset. ADR 021's context fingerprint is the backstop — even an imperfect trigger cannot cause a stale reasoning decision, because the fingerprint re-reasons on the actual decision inputs.

**Keep a low-frequency full reconciliation** (e.g. daily, not 30-minute) as the authoritative backstop ADR 013 calls for — it catches anything the event-driven triggers miss while the common case stays near-free. The 30-minute cadence becomes diff-only.

## Consequences

- Steady-state sweeps become near-free: deltas only. ClickHouse write/merge volume and worker CPU drop sharply, and the `enriched_at`-reset churn disappears — while KEV/context escalations still propagate.
- This composes with ADR 021: 022 stops the upstream write/enrich churn, 021 stops the downstream reasoning churn. Together the pipeline is incremental end to end.
- New surface: a `content_hash` column + `CurrentHashes(connectorID)` bulk read + `UpsertChanged` in `asset/repo.go`; diff logic in `jobs/sync.go`; a `sync_fingerprint` on the connector (PG); input-driven re-enqueue replacing the blind sweep in `jobs/enrich.go`; a Postgres presence table for `last_seen`/deletion.
- Risk to manage on rollout: the presence/deletion rework is the dangerous part — get trap 1/2 wrong and live assets look deleted or go stale. It should land as a **watched, phased deploy**. Phase order: (1) per-connector `sync_fingerprint` short-circuit (safe, big win), (2) per-asset content-hash write/enrich diff, (3) PG presence + deletion rework, (4) input-driven enrich replacing the blind sweep.

## Not built

Level 3 — skip collection itself for quiet connectors via provider change feeds (AWS Config/EventBridge, GCP Cloud Asset Inventory). It would avoid even the API calls, but is a bigger lift worth it only for the heaviest connectors; the internal hash-diff above captures most of the savings with pure internal code.

This amends ADR 013 (hybrid sync) and pairs with ADR 021 (change-driven reasoning).

## Amendment (2026-07) — check-registry identity rides the fingerprint

The diff path created a blind spot: CSPM checks run only on changed assets, so a newly
deployed check never fired on stable assets. The intended backfill trigger (an in-memory
registry count on the shared sync worker) observed a deployment only once per worker
process — the first connector synced got the backfill, and every other connector's
unchanged assets stayed unchecked, so new checks could produce no findings despite real
violations.

The stored `sync_fingerprint` is now `"<assetFP>|checks:<registry fingerprint>"` (hash over
sorted check IDs). A registry change mismatches every connector's stored value, which
(a) bypasses the phase-1 short-circuit and (b) runs the check pass over all collected assets
once, then re-stamps. Pre-amendment values have no suffix and read as a registry mismatch —
deploying this forces exactly one backfill sweep per connector.

## Amendment (2026-08-02) — the diff gates evaluation, not observation

The per-asset diff originally decided both *what gets written* and *what gets
re-evaluated*. Because `asset.ContentHash` excludes `LastSeen`, that made
`assets.last_seen` mean "last changed" and broke every liveness consumer (see the
2026-08-02 amendment to ADR 068).

Sync now always writes the full collected asset set (`restampLastSeen`), while
`changedAssetIDs` continues to gate the CSPM check run and the enrich enqueue. The
expensive half this ADR exists to skip is unchanged; only the cheap write widened.

## Amendment (2026-08-21) — presence/content split (trap 2) deliberately not built

The 2026-08-02 amendment traded the write saving away to fix liveness, leaving the
presence/content split (trap 2) as the outstanding design. It was re-evaluated and
**deliberately not built**:

- **The write amplification is real but expected to be cheap.** Re-stamping every
  collected asset writes far more rows than actually changed, but it is a bulk insert of
  large batches into a well-compressing `ReplacingMergeTree`, so its merge cost should stay
  a small share of ClickHouse merge time; the revisit triggers below say when to re-check.
- **The risk is high.** The presence/content split would rebuild the exact mechanism whose
  previous form caused live assets to drop out of the graph, wrongly auto-resolved
  findings, and exposed assets to TTL deletion (see the 2026-08-02 amendment). The saving
  does not justify that risk.

Revisit if asset merges become a significant share of total ClickHouse merge time, the
`assets` table grows large enough to matter, or the asset insert appears among the slowest
queries.

**The more significant write cost is elsewhere.** `findings`, `signals` and `beliefs` are
written one finding at a time by enrichment (`enrich/service.go` calls `finding.Record`
with a single-element slice per job; the signal and belief writes mirror it), producing
many tiny inserts and a disproportionate share of merge work for little data. Batching
those writes belongs to ADR 069/075's write path, not to this ADR's diff.

**Known related defect, not fixed here:** `assets.discovered_at` has the same problem
`findings.detected_at` had (see ADR 075's 2026-08-21 amendment) — every collector stamps
`DiscoveredAt: now` on every sweep, and the sync writes the whole collected set, so nothing
preserves first-discovery. `assetArgMaxSelect` reading `min(discovered_at)` limits the
damage only to the merge window, so long-lived assets appear newly discovered. Two
consumers are affected: `respond.ageBucket` treats the whole fleet as new, and
`asset.driftNewAssets` filters `WHERE discovered_at >= now() - INTERVAL ? SECOND` before
aggregation, so its 24-hour "new assets" feed matches nearly everything. Fixing the query's
WHERE/HAVING split alone would not fix it: `min(discovered_at)` is itself re-stamped. The
real fix is an immutable first-discovery timestamp, which needs a stored-value read the
sync path does not currently perform (it reads hashes from Postgres, never asset rows) —
i.e. it is trap-2-shaped, and it is the strongest remaining argument for building trap 2.
