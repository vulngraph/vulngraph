# ADR 075 — Enrichment write ownership: one writer per column, `finding_enrichment` as its own table

**Status:** accepted (2026-08) · amended 2026-08-21 (finding age shipped as a separate column),
2026-08-24 (stage 6 shipped) — shipped except two parts of §2. The read-time severity
derivation is not implemented: KEV-listed findings keep the producer's raw severity, no writer
escalates `severity`, and exploitation shows up through the `known_exploited` flag and the
enrich KEV page floor. `known_exploited` is written by the KEV worker, not computed by enrich.
Stages 1–5 landed as separate reviewed changes;
stage 6 (the legacy-column drop) shipped, so the schema has no legacy
enrichment columns. Every reader now joins
`finding_enrichment`; the ten legacy enrichment columns no longer exist on
`findings`.

## Context

`findings` is `ReplacingMergeTree(synced_at)` and the ten enrichment columns (`score`,
`score_band`, `enriched_at`, `known_exploited`, `dependents`, `unused`, `safety_class`,
`fix_target`, `must_fix_class`, `must_fix_reason`) lived in the same row as the
producer facts. Every writer therefore rewrote every column. A producer re-observation
(`finding.Service.RecordObserved`) was a read-modify-write — `carryForwardEnrichment`
read stored enrichment via `repo.ByIDs` at time R, `repo.Upsert` wrote full rows
stamped `synced_at = now()` at time W — and **any enrich write-back landing in (R, W]
was destroyed**: the sync row won on `synced_at` carrying the pre-enrich values read
at R. `carryForwardEnrichment` was a mitigation with a race window, not a guarantee.
The same full-row shape meant enrich's own write (`Record`) could resurrect a
just-resolved finding — the known race ADR 054 accepted for slice 1.

The observable effects (ADR 024 amendment):

- Open findings that had been enriched read as never-enriched (`enriched_at = 0`)
  after a later producer write clobbered them; a single finding could complete many
  enrich jobs and still read unenriched.
- The never-enriched cohort was a self-refilling head, not a fixed backlog: the
  reenrich walk spent many rounds and enqueues against it without converging.
- After the repair pass was fixed to converge correctly, enrichment coverage per
  source still fell. The repair works; it cannot win against a write path that keeps
  undoing it. **No recovery mechanism converges while the lost update remains.**

A second defect rode the same row: **`detected_at` was re-stamped on every
re-observation** (`checks.eval` stamps `now`; `carryForwardEnrichment` did not carry
it). Finding age is a documented must-fix input (ADR 044 `FindingAge`), so
prioritisation was skewed for everything re-observed — effectively the whole
actively-synced corpus.

`lost_update_integration_test.go` reproduces both defects deterministically against
real ClickHouse as pinned-defect tests: they asserted the broken behaviour and were
flipped to their target assertions when the fix landed.

### Why the existing tests never caught it

`TestCarryForwardCoversEveryEnrichmentField` and the `carry_forward_test.go` suite (both
deleted with the carry-forward code in stage 5)
verified the carry-forward *logic* against an in-memory fake. The defect was not in
the logic; it was in the **interleaving semantics of two full-row writers on one RMT
version column**, which only real ClickHouse exhibits and only under a write landing
inside (R, W]. No test constructed that interleaving.

## Decision

**One writer per column.** Enrichment moves to its own table, written ONLY by enrich and
`LEFT JOIN`ed on read. A producer re-observation then *physically cannot* clobber
enrichment — there is no shared row to lose an update on — and enrich physically cannot
resurrect a resolved finding, closing ADR 054's known race as a side effect.

### 1. Schema

```sql
CREATE TABLE finding_enrichment (
    id              String,
    score           UInt8                  DEFAULT 0,
    score_band      LowCardinality(String) DEFAULT '',
    known_exploited UInt8                  DEFAULT 0,
    dependents      UInt16                 DEFAULT 0,
    unused          UInt8                  DEFAULT 0,
    safety_class    LowCardinality(String) DEFAULT '',
    fix_target      String                 DEFAULT '',
    must_fix_class  LowCardinality(String) DEFAULT '',
    must_fix_reason String                 DEFAULT '',
    enriched_at     DateTime64(3)
)
ENGINE = ReplacingMergeTree(enriched_at)
ORDER BY (id)
TTL toDateTime(enriched_at) + INTERVAL 365 DAY;
```

- `ORDER BY (id)`: every read of this table is by finding id (point, IN-list, or full
  scan); the primary key serves them all — no bloom index needed, unlike `findings`
  (which is `ORDER BY (source, id)` and needs its `idx_id` bloom index).
- Version column `enriched_at` as `DateTime64(3)`: `findings.synced_at`'s one-second
  granularity is a standing tie hazard (`WithClock` exists solely to work around it in
  tests); millisecond precision removes the class for the new table.
- TTL from `enriched_at`: an open finding re-enriches at least every `enrichMaxAge`
  (`jobs.defaultEnrichMaxAge`, 24h backstop), so its enrichment row is perpetually re-stamped. A resolved finding stops
  enriching and its row expires alongside the finding's own 365-day horizon.
- One narrow row per finding id: small relative to `findings`.

**The domain type does not change.** `finding.Finding` keeps its enrichment fields as the
read model; the repo composes them from the join. This is what caps the blast radius: the
Go consumer packages, the OpenAPI contract (`openapi/domains/finding.yaml` — `score`,
`score_band`, `enrichment_state`, `must_fix_class` etc. are all `required`), and the
frontend components that read these fields need **zero changes**.

### 2. Write paths

- **enrich** (`enrich.Service.Enrich`, previously `findings.Record(full row)`): calls a
  new `finding.Service.RecordEnrichment(ctx, []Enrichment)` writing ONLY
  `finding_enrichment`. Enrich never touches the `findings` table again. `finding.Enrichment`
  is a small struct (id + the ten outputs); layering per ADR 010 is unchanged — `finding`'s
  `repo.go` remains the only CH importer, enrich keeps its narrow service interface.
- **producers** (`RecordObserved`): `carryForwardEnrichment` is **deleted**, along with the
  `enrich:"output"` tag machinery and `TestCarryForwardCoversEveryEnrichmentField` — the
  structural guarantee replaces the field-list discipline. `insertFindings` drops the ten
  enrichment columns. A pin test asserts the producer insert column list never regains
  them.
- **KEV** (`KEVWorker` + `intel/kev.Enrich`): today the second full-row writer — it stamps
  `known_exploited = true` AND escalates `severity` to critical on the producer row, which
  is why `carryForwardEnrichment` needed its oscillation exception (a producer re-observing
  at the original severity would wipe the escalation until the next daily sweep). Both
  writes are removed:
  - *Proposed, implemented differently:* `known_exploited` was to become an enrich-computed
    output, with the enrich worker consulting the KEV catalog. Instead `KEVWorker`
    (`internal/jobs/kev.go`) writes the flag into `finding_enrichment` itself
    (`RecordEnrichment`, from a re-read taken immediately before the write) and enqueues
    enrich for every finding it flagged. Enrich re-reads the stored flag before its own
    write, so it carries the flag forward rather than overwriting it.
  - *Proposed, not implemented:* severity escalation becomes a **read-time derivation**: readers return
    `if(known_exploited = 1, 'critical', severity)` as the effective severity. Producers
    own the raw `severity` column outright; the carry-forward KEV exception and the
    critical↔high oscillation cease to exist. This *extends* ADR 012's "no second catalog
    lifecycle": there is now no stored-flag lifecycle at all on the producer row.
- **Resolve / lifecycle** (`Resolve`, `ResolveGoneByResourceIDs`): unchanged shape. This
  split removes the *enrich* and *KEV* writers from a finding's producer row, which is the
  race that matters here — but it does NOT make the row single-writer, and an earlier draft
  of this section claimed it did. `Resolve` is a read-modify-write of the full producer row
  reachable from three paths that are not serialized with the owning connector's sync job:
  a user-driven govern accept (`govern/service.go` → `handler.go`), the periodic
  `dangling_ephemeral` worker (`jobs/dangling_ephemeral.go`), and connector purge
  (`connector/service.go`). A sync landing concurrently with any of them can still lose
  a `resolved_at`. That residual race is **out of scope** and unchanged by this ADR: it is
  narrow (lifecycle columns only, not the ten enrichment outputs), self-healing on the next
  observation for the periodic paths, and closing it needs its own serialization decision.
  Stated explicitly so nobody reads this ADR as having fixed it.

### 3. Read strategy — the join shape

One shared building block, mirroring `selectFindingsArgMax`:

```sql
-- enrichmentCurrent: current enrichment per id, RMT versions collapsed via
-- argMax(col, enriched_at) GROUP BY id — never FINAL (project ClickHouse rule). %s is an
-- optional pre-aggregation id filter, which uses the (id) primary key.
SELECT id,
    argMax(score, enriched_at)           AS score,
    argMax(score_band, enriched_at)      AS score_band,
    argMax(known_exploited, enriched_at) AS known_exploited,
    argMax(dependents, enriched_at)      AS dependents,
    argMax(unused, enriched_at)          AS unused,
    argMax(safety_class, enriched_at)    AS safety_class,
    argMax(fix_target, enriched_at)      AS fix_target,
    argMax(must_fix_class, enriched_at)  AS must_fix_class,
    argMax(must_fix_reason, enriched_at) AS must_fix_reason,
    max(enriched_at)                     AS enriched_at
FROM finding_enrichment
%s
GROUP BY id
```

Composed as:

```sql
SELECT f.*, e.score, e.score_band, …, if(e.known_exploited = 1, 'critical', f.severity) AS severity
FROM ( <producer argMax dedup, pre-agg WHERE on source/resource_id/check_id/id> ) AS f
LEFT JOIN ( <enrichmentCurrent> ) AS e USING (id)
WHERE <enrichment + lifecycle predicates, now PLAIN — see below>
ORDER BY … LIMIT ?
```

Specifics, checked against the project's ClickHouse rules:

- **No FINAL anywhere** — both sides are argMax dedup subqueries. `ANY LEFT JOIN` directly
  against the raw table was rejected: with unmerged RMT versions present, ANY picks an
  *arbitrary* matching row, not the newest — wrong by construction.
- **Point/IN lookups** (`Get` — the hot path — and `ByIDs`): the id predicate is
  pushed into BOTH subqueries. Left side prunes via the `idx_id` bloom index as today;
  right side is a primary-key lookup on `ORDER BY (id)`. Added cost over today: a few
  granule reads and a hash join over a handful of rows — negligible.
- **Batch/aggregate reads** (`List`, `ByResourceIDs`, `Summary`, `Clusters`,
  `SignalsByResource`, risk rollups, `UnenrichedCounts`, `MustFixCoverage`,
  `OpenIDsBehindCutoff`): the right side is the whole narrow table — one extra
  small-table scan + a transient hash build per query.
  These queries already do whole-table argMax collapses over `findings`, so this is a
  bounded increment, and the client-layer concurrency semaphore bounds parallelism.
  **Gate: each rewritten query is timed with `FORMAT Null` against representative data
  before the reader flip (stage 4).**
- **The never-enriched sentinel survives for free.** With ClickHouse's default
  `join_use_nulls = 0`, a LEFT JOIN non-match fills the right side's columns with type
  defaults: `score = 0`, `enriched_at = epoch`, `'' `strings — exactly the sentinels
  `EnrichmentStateAt`, `Filter.Unenriched`, `enrich.go`'s `Score > 0` gate, and the
  frontend's `enrichment_state` already encode. No sentinel logic changes.
- **The WHERE/HAVING split gets SIMPLER.** Today every enrichment predicate must live in a
  post-aggregation HAVING against argMax aliases (the subtlety documented at length on
  `selectFindingsArgMax`). Post-join, enrichment predicates (`MinScore`, `MustFixOnly`,
  `SafeOnly`, `Unenriched`, `StaleFirst`, the score/enriched_at keyset cursors) are plain
  outer WHERE on joined columns. Only `resolved_at`/`detected_at` retain the HAVING
  treatment inside the producer subquery.

**Rejected read alternatives:**

- **`dictGet` over a hashed dictionary**: cheapest per query, but a dictionary refreshes on
  `LIFETIME` — reintroducing exactly the write→read staleness this ADR exists to kill (an
  enrich write invisible to the next read), plus permanently pinned server memory and one
  more moving part to monitor. Rejected.
- **Two-query-and-merge-in-Go everywhere**: clean for row readers, but `List` filters,
  sorts, AND keyset-paginates on enrichment columns (`SortByScore` is a primary UI
  ordering; `StaleFirst` drives the drift sweep) — pagination over a merged sort cannot be
  done in Go without reading unbounded rows. And the aggregates (`Summary`, `Clusters`,
  `SignalsByResource`) exist precisely to avoid pulling per-finding rows into Go. It would
  leave two read forms where one join form covers all sixteen queries. Rejected.

### 4. The cost, traced

Every reader of enrichment columns, from a full trace of the codebase:

**In `internal/app/finding` — 12 query shapes to rewrite:**

| Query const / method | Enrichment columns used | Post-split shape |
|---|---|---|
| `selectFindingsArgMax` → `List` | all ten (filters, sort, cursors) | join, filters go plain-WHERE |
| `selectFindingByID` → `Get` (hot path) | all ten | join, id pushed both sides |
| `ByIDs` | all ten (governor targets; carry-forward dies) | join, ids pushed both sides |
| `ByResourceIDs` | all ten (lifecycle/purge/correlate-invalidation) | join, unfiltered right side |
| `signalsByResource` (×3 subselects) | score, known_exploited | join per branch |
| `riskByResourceForIDs` / `riskiestResources` | score, score_band | join |
| `summaryOpenFindings` | score_band | join |
| `clustersByCheck` | score, score_band, known_exploited | join |
| `unenrichedOpenFindings` | enriched_at | LEFT-JOIN non-match = never enriched |
| `mustFixCoverageBySource` | must_fix_class, enriched_at | join |
| `openIDsBehindCutoffQ` | enriched_at | join |
| `insertFindings` / `Upsert` | writes all ten | drops all ten |

(`distinctCheckIDs`, `countByCheckID`, `checkQualityQ` touch no enrichment columns —
untouched.)

**Raw SQL outside the finding package — 4 queries:**

| Site | Columns | Note |
|---|---|---|
| `internal/app/belief/repo.go` `selectCrystallizationInputs` | score_band, must_fix_class | join |
| `internal/app/belief/repo.go` `selectAdjudicationBacklog` | score, must_fix_class, enriched_at (filter + order + adj-staleness compare) | the highest-coupling rewrite; documented mirror of `belief.NeedsAdjudication` — rewrite both together |
| `internal/app/coverage/repo.go` `qOpenFindingBands` | must_fix_class, score_band | join |
| `internal/app/asset/drift.go` `findingsForAssets` | score | join (drift.go is already the one freshness-cond exemption; keep its exemption comment honest) |

**Write-path code:** `enrich/service.go` (Record → RecordEnrichment),
`jobs/kev.go` + `intel/kev/kev.go` (writer removed, catalog interface added),
`jobs/enrich.go` (fingerprint input change), `finding/service.go`
(carryForwardEnrichment deleted; RecordObserved carries `detected_at`),
`enrichcache/fingerprint.go` (KnownExploited source).

**Untouched, verified by the trace:** all pure consumers of `finding.Finding` fields —
findingctx, respond (cove score gates, contextpack, webhook), govern, mcp, adjudicate,
alerts, reason, sink/webhook (since removed), reasoncache, graphstore/Ladybug node signals, obs metrics,
httpsrv/asset risk adapters — plus `openapi/domains/*.yaml` and the frontend
components. They read the domain type or the API shape, both of which are preserved.

### 5. `detected_at`

`detected_at` is a **producer-row concern** — it is "when this violation was first seen",
a fact about observation, not about scoring — so it stays in `findings` and gets carried
forward correctly:

- `RecordObserved` sets `DetectedAt = min(prev.DetectedAt, new.DetectedAt)` from the
  `ByIDs` read it already performs. Post-split this read-modify-write is **race-free**: the
  only writers of a finding's producer row are its own connector's serialized sync jobs —
  enrich and KEV no longer write `findings` at all.
- **TTL must move first**: today's `TTL detected_at + INTERVAL 365 DAY` only works
  *because* detected_at is re-stamped. Carrying a >365-day-old detected_at forward would
  make every new version row for such a finding TTL-eligible on write — the finding would
  vanish while live. The hazard is latent — it arrives once carried-forward ages cross a
  year — which is why the TTL move must not be deferred.
  `ALTER TABLE findings MODIFY TTL synced_at + INTERVAL 365 DAY` is behaviourally
  equivalent to the status quo (re-stamped detected_at ≈ last write time ≈ synced_at) and
  frees detected_at to carry true age. ADR 054's TTL note ("re-stamped on observation")
  is superseded by this. (Shipped early, in stage 1.)
- Historical age is unrecoverable — every currently-open re-observed finding's age
  restarts from its next observation. Stated so nobody expects a backfill.
- `List`'s comment that detected_at "is NOT identity-stable" (and `unenrichedOpenFindings`'
  ordering-key rationale) becomes stale doctrine: after this, detected_at is monotone
  non-increasing per id. The HAVING placement stays correct either way.
- **`qFindingSourceLiveness` must move to `synced_at` in the same change**
  (`internal/app/coverage/repo.go`). It reports `max(detected_at) AS last_detected` as
  "the last time this source produced anything" — a reading that is only true *because*
  detected_at is re-stamped on every observation. Once it carries true first-seen age,
  `max(detected_at)` freezes at whenever the source's newest finding first appeared, so a
  healthy long-running source with no new finding types reads as progressively staler and
  the dark-source signal raises false alarms. `max(synced_at)` is the actual liveness fact.
  This is the one reader outside `finding` that the §5 change breaks, and it breaks
  silently — no query error, just a wrong number in the coverage report. Its enrichment
  columns are untouched, so it needs no join rewrite; the sixteen-query count in §3 stands.

### 6. Migration order

The change landed in stages, each its own commit, so that no reader ever saw a blank
score:

1. **Create** (the `finding_enrichment` table): the table above
   plus the `findings` TTL modify.
2. **Dual-write**: enrich (and KEV, until stage 5) wrote both the legacy columns and
   `finding_enrichment`.
3. **Backfill** (idempotent):
   ```sql
   INSERT INTO finding_enrichment
   SELECT id, argMax(score, synced_at), …, argMax(enriched_at, synced_at) AS enriched_at
   FROM findings GROUP BY id
   HAVING enriched_at >= toDateTime('2000-01-01')
   ```
   RMT dedup makes overlap with dual-write harmless: a backfilled row's version
   (`enriched_at`) can never beat a newer live enrich write.
4. **Flip readers**: the sixteen queries move to the join form, checked with
   `FORMAT Null` timings of each rewritten aggregate against representative data (this
   table's read paths are CPU-sensitive, so the flip is a performance change as well as
   a correctness change).
5. **Cut writers over**: enrich stops writing legacy columns (`Record` retires in favour
   of `RecordEnrichment`), KEV writes its flag through `RecordEnrichment` (see §2),
   `carryForwardEnrichment` and the `enrich:"output"` machinery are deleted,
   `RecordObserved` gains the detected_at carry, `insertFindings` drops the ten columns,
   and the three pinned integration tests in `lost_update_integration_test.go` flip to
   their ADR 075 target assertions.
6. **Drop the legacy columns** from `findings` (see the 2026-08-24 amendment below).
   The migrations have since been squashed: `migrations/clickhouse/00001_init.sql`
   creates `findings` without them.

A fresh install never holds data in the legacy columns. The health signals for this table are `graph_findings_unenriched` (should sit at
the true-new rate) and the per-source `MustFixCoverage` ratios (should not regress).

### 7. Tests

- **Committed with this ADR** (`internal/app/finding/lost_update_integration_test.go`):
  three deterministic integration reproductions using an injected stepping clock and a
  `raceRepo` that fires an enrich write exactly inside RecordObserved's (R, W] window —
  the interleaving no existing test constructed. They are *pinned defects* (a project
  test pattern): they assert today's broken behaviour and fail the moment the race is closed,
  with the target assertions written inline. This is the test that would have caught the
  original bug, and it is the acceptance test for stage 5.
- **With the implementation**: a pin that `insertFindings`' column list contains no
  enrichment column (the structural invariant, in the spirit of
  `TestGraphEdgesReadersApplyFreshness`); a `RecordEnrichment` unit + integration test;
  detected_at carry-forward tests; re-run of the belief/coverage/drift
  integration tests against the join forms.

## Rejected alternatives

- **Merge-on-write `carryForwardEnrichment`** (read latest, merge, write): there is no
  atomic read-modify-write in ClickHouse — RMT replaces whole rows on the version column,
  full stop. Any read-then-write has the (R, W] window; making R later or W smarter
  shrinks it, but with re-observations and enrich writes both continuous, a shrunk
  window still loses updates. A smaller fix that cannot be made correct is not a
  smaller fix.
- **Enrich writes only its columns via `ALTER TABLE UPDATE`**: mutations are asynchronous
  whole-part rewrites; at enrich's write rate this is a mutation storm that would
  bury the merge pipeline, and mutations rewrite ALL versions of a row, interacting
  badly with RMT semantics. Rejected.
- **`AggregatingMergeTree` with per-column-group version states** (`argMaxState(col,
  enriched_at)` for enrichment, `argMaxState(col, synced_at)` for producer facts, in one
  table): genuinely solves last-writer-wins per column group in-table, but every reader
  must speak `-Merge` combinators, the table stops being debuggable with plain SQL, and
  the reader-rewrite cost is the SAME sixteen queries — all of the invasiveness, none of
  the simplicity. Rejected.
- **Serializing writers** (per-id locks, or routing producer writes through the enrich
  queue): cross-queue coupling River is designed to avoid, doesn't survive multi-process,
  and leaves detected_at and the resolved-resurrection race untouched. Rejected.
- **Keep repairing** (status quo + reconciler): observed non-convergent. The repair pass
  is retained — it remains the durability backstop per ADR 024's "ClickHouse is the
  system of record for needs-enrich" — but it cannot be the fix.

## Consequences

- A producer re-observation physically cannot clobber enrichment; an enrich write
  physically cannot resurrect a resolved finding (ADR 054's accepted race closes); the
  KEV critical↔high oscillation class dies; `detected_at` becomes real age for ADR 044.
- ~16 query rewrites and 3 write-path rewrites, all inside repos and workers; zero
  domain-type, API, or frontend changes. The riskiest single rewrite is
  `selectAdjudicationBacklog` (filter+order+compare across both tables).
- Every batch read pays one extra small-table scan and a transient hash build;
  point reads pay a primary-key lookup. Validated with `FORMAT Null` before the flip,
  since this table's read paths are CPU-sensitive.
- Two tables can no longer be inconsistent *by clobbering*, but a finding deleted by TTL
  leaves an enrichment row until its own TTL (harmless: nothing joins to it) and an
  enrichment row can describe a finding not yet visible to a reader (harmless: LEFT JOIN
  from findings). Neither is user-visible.
- `synced_at` on `findings` becomes purely "last producer write", which makes it a
  truthful freshness signal for the first time.
- Risk: this rewrites every read of the platform's most-read table (stage 4). A reader
  written against the old shape (e.g. a raw-SQL site outside the finding package) would
  have served frozen legacy columns. Stage 6 dropped those columns, so such a reader now
  fails with a query error instead of serving stale values, which is the correct failure
  mode.

Cites ADR 024 (the amendment that identified this defect), 054 (lifecycle columns and the
resolved-resurrection race this closes), 044 (age as a must-fix input), 012 (KEV
catalog lifecycle, extended here), 022 (why re-observation volume is structural), 010
(layering of the new write seam), 069 (the full-pass machinery that becomes able to
converge).

## Amendment notes

### 2026-08-21 — finding age shipped as a separate column, not by repurposing `detected_at`

§5 proposed making `detected_at` itself carry true age, which requires the TTL move
and breaks `qFindingSourceLiveness` in the same change. Adding a column is cheaper than
changing the meaning of one with several consumers, so the age fix shipped ahead of the
rest of this ADR as the `findings.first_detected_at` column, and §5's `detected_at` rewrite is withdrawn.

Invariants and risks behind the change:

- **The defect is structural.** Every enrichment rewrite re-inserts the finding with a fresh
  `detected_at`, so a finding id can hold two or more surviving ReplacingMergeTree versions
  with different `detected_at` values. The observable spread is bounded by merge lag; once
  versions collapse the older value is gone, so the error grows with corpus age.
- **Scoring impact grows with corpus age.** Only `ghas_code_scanning` and `ghas_secrets` stamp
  an upstream first-seen (`coalesceTime(a.CreatedAt, now)`) rather than `now`; for other
  producers a young corpus hides the bug because nothing has yet crossed the ADR 044 90-day
  age threshold. The fix must land before the corpus ages into it.
- **Per producer, exposure follows the code**: producers that re-stamp `now` on every write
  (`iac`, `iac_terraform`, `aws_guardduty`, `cspm` among them) are exposed; producers that
  stamp an upstream first-seen are not. A low surviving-version rate for a producer reflects
  merge lag, not immunity.

Why a new column rather than §5's rewrite:

- **No reader breaks.** `qFindingSourceLiveness` (`internal/app/coverage/repo.go`)
  reads `max(detected_at)` as "when did this source last produce anything", which stays
  true while `detected_at` is re-stamped.
- **`detected_at` stays the list sort key** ("newest activity first"), a defensible
  product behaviour that is not what age means.
- The TTL hazard is avoided independently: stage 1 had already moved
  the `findings` TTL to `synced_at`.

Immutability is enforced twice, deliberately:

1. **Write side** — `Service.RecordObserved` pins `FirstDetectedAt` to the oldest
   non-zero timestamp known for the id, using the `ByIDs` read it already performs. The
   pin runs before any enrichment-state gate: an unenriched finding has been present
   exactly as long as an enriched one.
2. **Read side** — the repo reads `minIf(first_detected_at, first_detected_at > 0)`
   across the id's row versions, not `argMax`. `argMax` answers "what does the newest
   row say", the property that made `detected_at` wrong; `min` cannot be moved forward
   by any writer. The non-zero filter is load-bearing: a plain `min` would let one row
   written without the column report 1970 and demote the finding permanently. Zero means
   unknown, and unknown contributes nothing (ADR 044).

**What cannot be recovered.** The migration defaults the column to each row's own
`detected_at`, so the min-across-versions read recovers the oldest `detected_at`
ClickHouse still physically holds — never an invented value. For findings whose
versions had already merged, the true first observation is gone; no backfill is
possible.

**Visibility.** `finding.AgeIntegrity` exports `graph_finding_age_preserved`,
`graph_finding_age_missing` and `graph_finding_age_oldest_seconds`.
`graph_finding_age_preserved` counts open findings whose first observation is older
than their latest `detected_at`; it is 0 by construction until the pin works, so a
deploy that leaves it at 0 shipped inert.

### 2026-08-24 — stage 6 shipped: the ten legacy columns are dropped

Stage 6 shipped as a schema change that dropped the columns, activating the
mitigation in Consequences: a reader that missed the stage-4/5 flip now fails loudly
against the schema instead of serving stale values.

Verified before writing the migration:

- **Full-repo trace**: every query site in §4, plus a grep across `internal/`,
  `openapi/`, `docs/` and the frontend for all ten column names, confirmed no raw SQL,
  integration test or OpenAPI schema reads them from `findings`. The OpenAPI contract
  and frontend read the `Finding` domain type, which is unchanged (§1).
- **No data is lost**: after stage 5 nothing writes the legacy columns, and the migrations
  run in sequence, so on any install the columns hold nothing that `finding_enrichment`
  does not.
- **A stale artifact was fixed in the same change**: an ad-hoc verification query read
  `findings.enriched_at`/`findings.must_fix_class` directly and now joins
  `finding_enrichment`. The doc comments on `insertFindings` and
  `TestInsertFindingsOmitsEnrichmentColumns` (`internal/app/finding/repo.go`,
  `repo_test.go`), which described the columns as the stage-6 rollback net, were
  updated.
