# ADR 024 — Change-driven enrichment

**Status:** accepted · amended 2026-08-11 (`LoadView` cost is result transfer), 2026-08-12 (re-observation is a lost update)

## Context

The periodic enrich sweep re-processes **every finding every 30 minutes regardless of whether anything changed**, and the dominant cost is per-finding ClickHouse load. On a large estate this can saturate ClickHouse CPU.

`enrich.Service.Enrich` runs a `BlastRadius` source that calls `asset.Service.BlastRadius(resourceID, depth 2)` — a bounded BFS issuing a `GetAsset` for the seed, an `EdgesFrom` per frontier hop, and a `GetAsset` per reachable node, up to the 500-node budget. That is up to ~500 ClickHouse queries **per finding**. With `enrichSweepLimit = 200` findings per 30-minute tick, a single sweep can fire up to 200 × 500 ClickHouse queries — plus the per-finding peer reads (AttackPaths/ToxicCombo/CrossCluster) and a second, identical blast-radius walk in `respond.Decide`. The `enriched_at` column existed but was never read to skip anything. ADR 021's reasoning cache only skipped the LLM call — it runs *after* the blast-radius walk, so it saved tokens, not ClickHouse CPU.

The fix: **only re-enrich when something changed.** Because `respond.Decide` is enqueued only at the end of `EnrichWorker.Work` (`enqueueDecide`), gating enrichment also removes the downstream decision walk — one gate fixes both costs.

## Decision

`EnrichWorker.Work` gates on a cheap per-finding **input fingerprint** plus a **freshness backstop**, stored in Postgres (`enrich_cache`, mirroring ADR 021's `reasoning_cache`):

- **Fingerprint** (`enrichcache.Fingerprint`) hashes the finding's *inputs* — `ID, CheckID, Type, Severity, ResourceID, KnownExploited`. It deliberately excludes the enrichment *outputs* (`Score`/`ScoreBand` — hashing them would loop) and all timestamps. A KEV escalation flips `KnownExploited`, so it re-enriches immediately even within the backstop.
- **Gate:** before enriching, look up `enrich_cache`. If the fingerprint matches and the last enrichment is within `enrichMaxAge`, **skip** — no blast-radius walk, no decide enqueued. Otherwise enrich and record the fingerprint + time.
- **Backstop** (`enrichMaxAge`, env `ENRICH_MAX_AGE`, default 24h — raised from an original 6h because a 6h backstop re-enriches too aggressively on large finding sets; rationale on `defaultEnrichMaxAge` in `internal/jobs/enrich.go`): even an unchanged finding re-enriches once stale, so graph-context drift the fingerprint can't see (a new blast-radius asset, a new peer finding) is still picked up — bounded, not every cycle.
- Applies to **all** enqueue paths uniformly (sweep, ingest, scan, KEV). Ingest re-detecting an identical finding every 30 min is exactly the redundant work this drops; a genuinely new or changed finding has a new fingerprint (or no cache entry) and always enriches.

This is the enrich-side twin of ADR 021's reasoning gate, and the first concrete slice of ADR 022's "input-driven re-enqueue."

## Consequences

- Steady-state sweeps stop re-walking the blast radius for unchanged findings — the dominant ClickHouse load drops sharply (only changed/stale findings enrich), and the downstream `respond.Decide` walk is gated for free since it's only enqueued when enrichment runs.
- **Trade-off:** a finding whose graph neighborhood changes while its own row does not won't re-score until the backstop (`enrichMaxAge`) — KEV/severity/new-finding escalations are still immediate. The precise alternative (re-enqueue on correlate/sync deltas) builds on ADR 022's content hash (now implemented) and remains deferred.
- **Fail-open:** any `enrich_cache` read error falls through to enriching; a nil cache disables the gate (the prior always-enrich behaviour), keeping the worker unit-testable.
- A skipped enrich leaves the persisted score unchanged — correct, since the finding is unchanged.
- New PG-backed `enrichcache` domain (`domain`/`repo`/`service`/`fingerprint`), the `enrich_cache` table, sqlc queries — mirrors `reasoncache` (ADR 010 layering; `EnrichWorker` depends on a narrow interface).

## Not built

- Precise graph-change re-enqueue (correlate/sync deltas drive enrichment) on top of ADR 022's per-asset content hash (now implemented) — would replace the time backstop with true input-change detection.
- ~~Correlate's full-table `LoadView` every 30 min~~ — **partly addressed 2026-08-11** (see the amendment below). The redundant enrich-vs-respond double-walk for *changed* findings remains a separate, smaller lever (a respond/enrich blast-radius hand-off) — noted, not built here.

Cites ADR 021 (reasoning gate — same principle, one stage downstream), 022 (this is its first built slice), 014 (enrichment stage), 005 (decaying memory — why within-band score drift is excluded from the fingerprint), 010 (layering).

## Amendment (2026-08-11) — the `LoadView` cost is result transfer, not ClickHouse CPU

The deferred `LoadView` item assumed the cost was ClickHouse CPU. It is not: the aggregate
itself is fast, but the **result** is large — dominated by the `metadata` column — and
`scanAssets` runs one `json.Unmarshal` per row inline in the scan loop, all inside the read
deadline. A previously undocumented 60s read deadline, far tighter than the
`CorrelateWorker`'s own 20-minute budget, could cut off full sweeps mid-transfer (the server
side then reports a network error such as a connection reset while writing to the socket),
degrading effective full-sweep cadence well below the 30-minute schedule.

**Decision.** `loadViewTimeout` is 5 minutes; `correlationLimit` becomes a **fail-closed
circuit breaker** (`correlate.ErrViewTruncated`) derived from the ADR 071 worker budget
rather than a silent truncation point, applied on **both** paths (the partial path
previously discarded the truncation flag and could correlate a truncated view silently);
and four types (`subnet`, `vpc`, `azure_subnet`, `azure_vnet`) that no rule and no
`NewGraph` case reads were removed from the view, guarded by
`TestCorrelationTypesHasNoUnusedTypes`.

**Deliberately not done.** Chunking the view is unsafe: nearly all rules join across types,
`dedupe`'s cross-rule confidence ranking forces the five `defined_in` producers into one
group that re-collects most of the payload anyway, and per-chunk ingest breaks sweep
atomicity — which under ADR 049 converts a clean failure into silent topology *deletion*.
Extending `EphemeralLivenessCond` to `dns_record`/`ec2_instance` is forbidden by ADR 068's
"only add a type when absence genuinely means the resource is gone". `metadata` cannot be
dropped — most rules read it.

**Next lever.** Most metadata bytes come from two keys: `permissions` (on
`gcp_service_account` rows) and `policies` (on IAM principals). A server-side metadata-key
projection, guarded by an AST scan for `Metadata["…"]` accesses in
`loadview_columns_test.go`, is the right fix. It is **blocked** until `writeAnnotations`
merges instead of replacing (`service.go` does `f.Metadata = a.Metadata`, and
`k8s_manifest_ownership.go` copies the whole map), or key-projection would silently erase
unprojected metadata in ClickHouse.

## Amendment (2026-08-12) — enrichment shares a ReplacingMergeTree row with producer facts, so re-observation is a lost update

`findings` is `ReplacingMergeTree(synced_at)` and the enrichment columns (`score`,
`score_band`, `enriched_at`, `must_fix_class`, …) live in the same row as the producer
facts. `finding.Service.RecordObserved` is therefore a read-modify-write:
`carryForwardEnrichment` reads stored enrichment via `repo.ByIDs` at time R, then
`repo.Upsert` writes full rows stamped `synced_at = now()` at time W. **Any enrich
write-back landing in (R, W] is destroyed** — the sync row wins on `synced_at` carrying the
pre-enrich values read at R. `carryForwardEnrichment` is a mitigation with a race window,
not a guarantee. The design risk: a finding that reads back as never-enriched
(`enriched_at = 0`) may in fact have been enriched and then overwritten.

Two consequences:

1. **The un-enriched cohort is a self-refilling head, not a fixed set of stragglers.**
   Any recovery mechanism that orders by `enriched_at` cannot converge in principle; a
   re-enrich walk ordered that way can spend its whole budget without making progress.
2. **`detected_at` is re-stamped on every re-observation** (`carryForwardEnrichment` does
   not carry it), so a finding's age resets whenever its producer sees it again. Age is a
   documented must-fix input (ADR 044), so it is wrong for everything that gets
   re-observed. Not fixed here.

The durable pattern: **ClickHouse is the system of record for "needs enrich"** —
`open AND enriched_at < cutoff` is written atomically with the domain write because it is
the same row — and River is a latency cache of pending work. Ingest-time enqueue is
therefore best-effort by design, and the always-on reconciler is the durability guarantee.

The structural fix is one writer per column: a dedicated `finding_enrichment` table
(`ReplacingMergeTree(enriched_at) ORDER BY (id)`) written by the enrichment writers (enrich
and the KEV refresh) and LEFT JOINed on read. That touches all five readers in `finding/repo.go` plus the downstream must-fix and
safety consumers, so it is deliberately not done here.
