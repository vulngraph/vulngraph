# ADR 054: Finding lifecycle — sync-time auto-resolution

**Status:** accepted (2026-07-13) · amended 2026-07 (resolved filter on aggregate surfaces), 2026-07-27 (`resolution_reason`), 2026-08-21 (per-scope completeness) · amended by ADR 081 (enforce-mode tombstones for security_group/vpc) and ADR 083 (sync deletion/resolution gated on `coveredScopes`)

## Context

Findings were insert-only. When an issue was fixed (or its resource deleted) the
emitting check simply stopped re-emitting it, and the last row sat in every
list, summary tile, cluster, and risk rollup until the 365-day TTL evicted it.
A finding that has not been re-observed recently cannot be told apart as "fixed"
or "not re-checked". A platform that cannot perceive that a problem went away
cannot show remediation progress (MTTR, trends), and the belief engine (ADR 053)
loses its strongest outcome signal: resolution.

The codebase already solved this problem three times in miniature:
- `scan_findings` has new/confirmed/resolved/regressed with
  `ReconcileFindingLifecycle` diffing each scan run — but only for scan profiles.
- `findDeletedAssets` detects cloud-deleted assets at sync — but only cleaned
  the Postgres hash cache.
- ADR 049 gave graph edges liveness (re-stamp + reader-side freshness filter) so
  that disappeared edges stop being traversable.

The complication is ADR 022: checks run only on **changed** assets, so absence
of emission is meaningful only within the set of assets the checks actually ran
on that sweep. A finding on an unchanged asset is deliberately not re-recorded;
treating its stale `synced_at` as "resolved" would mass-hide live findings.

## Decision

Two new columns on `findings`, following the ADR 049 shape —
stamp liveness, filter at read, never delete:

- **`last_observed_at`** — stamped every time the emitting check/collector
  re-observes the finding. Set by `finding.Service.RecordObserved`, the write
  path for observation producers (sync). `Record` remains for score-writers
  (enrich, KEV): a score update is NOT an observation and must not touch
  lifecycle fields. Not `synced_at` — that is the ReplacingMergeTree version
  column and is bumped by every write.
- **`resolved_at`** — set by the sync-time reconcile; zero while open.

Resolution edges (both in `internal/jobs/sync.go`, best-effort, never fail a
successful sync):
1. **Fixed**: after checks run against `checkTargets` and findings are
   recorded, `reconcileResolvedFindings` diffs stored open `source="cspm"`
   findings on those resources against the just-emitted IDs (deterministic
   finding IDs make the diff exact). Not re-emitted ⇒ fixed ⇒ `resolved_at =
   now`. The diff never touches resources outside `checkTargets`, so the ADR
   022 changed-assets semantics are preserved.
2. **Resource deleted**: `findDeletedAssets` hits also resolve every open
   finding (any source) on the deleted resources. This path is gated on a
   COMPLETE collection: any best-effort family skip must set `Result.Partial`,
   which makes sync skip deletion reconciliation for that sweep (absent ≠
   deleted). Every collector with best-effort families must honor this;
   otherwise a transient IAM/storage/DNS API error would auto-resolve live
   findings. GCP and Kubernetes families flag Partial accordingly
   (`bestEffort` in `internal/collect/gcp`, per-list handling in
   `internal/collect/kubernetes`).
3. **Regression**: `RecordObserved` clears `resolved_at` — a re-observed
   resolved finding reopens automatically via the RMT full-row rewrite.

Readers exclude resolved findings by default: `Filter.IncludeResolved` (API
`?include_resolved=true`) adds/omits `resolved_at < toDateTime('2000-01-01')`,
the same sentinel idiom as `Unenriched`. Responses expose `last_observed_at` /
`resolved_at` (omitted while unset). This applies to every read surface, not
just `List()`: the dashboard summary, triage clusters, the graph signal
projection (`SignalsByResource` — `has_kev`/`max_score` on asset nodes), and
the per-resource risk rollups all carry the same filter
(`TestCHRepo_ResolvedFindingsExcludedFromAggregates` pins it).

Provider-native findings (GuardDuty, SCC, GHAS) are **not** diff-reconciled
against the check registry — their emission sets are provider-controlled
(archival, pagination windows) and a partial fetch must not mass-resolve real
threats. Each source closes on the provider's own evidence instead
(`internal/jobs/sync_provider.go`):

- **GHAS** (`ghas_secrets`, `ghas_code_scanning`): each sweep also reads the
  alerts GitHub closed — `state=closed` code-scanning and `state=resolved`
  secret-scanning listings, newest change first, back 30 days
  (`closedAlertLookback`) and only for repos and kinds whose open listing
  answered. A closed alert is positive evidence about one finding, so it needs
  no completeness claim (`collect.Result.ClosedFindings`,
  `reconcileProviderClosures`). The reason follows GitHub's state:
  code-scanning `fixed` and secret `revoked` → `fixed`; code-scanning
  `dismissed` and secret `false_positive` / `wont_fix` / `used_in_tests` →
  `manual` (a person's triage on GitHub); secret `pattern_deleted` /
  `pattern_edited` or a resolution GitHub adds later → `provider_closed`.
  GitHub's words are kept as `resolved_reason`, `resolved_by` = the source. A
  finding is closed only if it is open, of the closure's source, last emitted
  by this connector, and not returned open by the same sweep (reopened). A
  closure no sweep read inside the 30-day window (the connector did not sync
  for the whole window, or more than `GITHUB_MAX_PAGES` pages closed inside it)
  leaves its finding open until an admin resolves it.
- **GuardDuty**: a region whose ACTIVE listing was proven complete closes the
  connector's open threat findings it no longer returns (`provider_closed`).
- **SCC**: a successful fetch is the organization's whole ACTIVE THREAT
  listing, so the open SCC findings it no longer returns (gone inactive in SCC)
  close as `provider_closed`; findings carry the organization as provenance so
  only that organization's listing closes them.

All three also resolve through resource deletion (item 2) when their
resource's deletion is proven.

## Consequences

- A fixed issue leaves worklists within one sync sweep of its asset changing
  (the fix itself changes the asset, so the checks re-run on it immediately).
- Resolution events are recorded, enabling MTTR/trend analytics and feeding
  outcome ground truth to the belief engine (ADR 053 crystallization).
- Known race: an in-flight enrich (Get before resolve, Record after) can
  resurrect a just-resolved finding with a newer RMT version. The window is
  seconds; a resurrected finding re-resolves the next time its asset changes
  or the check registry grows (full-run reconcile). Accepted for slice 1.
- The findings TTL stays at 365d from `detected_at` (re-stamped on
  observation). Cutting TTL by `last_observed_at` was rejected: findings on
  unchanged assets are never re-stamped (ADR 022), so a liveness-based TTL
  would evict live findings.

## Amendment 2026-07 — resolved filter on aggregate surfaces

Initially only the list endpoint filtered resolved findings, so aggregates kept
counting them (for example, a fixed KEV finding kept `has_kev=true` on its graph
node and inflated dashboard counts). The filter was extended to every aggregate
read surface listed above and pinned by
`TestCHRepo_ResolvedFindingsExcludedFromAggregates`.

## Amendment 2026-07-27 — `resolution_reason`: outcome, not just timestamp

### Context

The original consequence "resolution events are recorded, enabling MTTR/trend
analytics and feeding outcome ground truth" was only half true: only the
timestamp was recorded, and the two outcomes that carry all the signal are
indistinguishable in it:

- someone corrected the control → the finding was worth showing a human
- the resource disappeared on its own → nobody needed to see it

Without that distinction nothing in the platform tracked whether a check
produced work worth doing. Judgements about finding quality relied on manual
sampling and ended up encoded in hand-maintained Go lists
(`contextIndependentCriticals`, `hygieneOptimizationChecks`, `staleStateSpecs`,
…) rather than in the system, so noisy checks could stay
registered long after being identified as noisy.

### Decision

`findings.resolution_reason` (`LowCardinality(String)`) records a
closed enum, `finding.ResolutionReason`:

| reason | meaning | counts as |
|---|---|---|
| `fixed` | the emitting check/feed ran again against a live resource and no longer reports it | acted on |
| `resource_gone` | the resource no longer exists (deleted, terminated, or `last_seen` behind its provider's high-water mark) | **junk signal** |
| `manual` | a human resolved it explicitly, with their own free text kept separately | acted on |

`Service.Resolve` takes the reason as a **required parameter** rather than reading a
field off `Finding`. That is deliberate: the compiler then rejects an unexplained
resolution and a new call site cannot forget one. An invalid or empty reason is an
error, not a defaulted blank — silently accepting `""` would reintroduce the gap one
call site at a time. A resolved row with an empty reason is reported as `unknown`,
never guessed.

`manual` is kept separate from `fixed` so human triage cannot inflate a check's
apparent effectiveness.

### Consequences

- `graph_check_junk_rate{check_id,source}` = `resource_gone / (fixed + resource_gone
  + manual)`, with `graph_check_resolutions{check_id,source,outcome}` as the
  auditable breakdown and `graph_check_quality_measurable` distinguishing "genuinely
  clean" from "not enough evidence yet" — without which a brand-new check and a
  perfect one both report 0.0.
- Check quality becomes a standing, ranked list to burn down instead of a periodic
  manual audit. It is deliberately keyed on the check rather than on individual
  findings: cheap, complete coverage, and no LLM needed. Judging a single finding
  by language model is far more expensive and gated to a small fraction of
  critical/high findings.
- The scoreboard is capped at `finding.CheckQualityLimit` series (GuardDuty finding
  types arrive as unbounded check_ids) and logs a warning naming how many checks were
  dropped. A silent truncation here would recreate the blindness.
- `resolution_reason` is exposed on the finding API response so a responder can see
  why something closed rather than only that it did.

Supersedes nothing; extends ADR 054 slice 1. ADR 055's sweeps and ADR 053's
crystallization inputs both become interpretable as a result; wiring
crystallization into enrich remains the next step.

## Amendment 2026-08-21 — per-scope completeness, observed only

### Context

Slice 1 gates deletion reconciliation on `!res.Partial`. That gate is correct
and must stay, but its granularity makes it fire rarely: `Partial` is one
boolean per connector, and an AWS connector runs many best-effort families per
region across every enabled region. One permission gap anywhere sets it for the
whole sweep, every sweep. `connectors.partial_streak` records the consequence at connector
level (how long since a connector completed a phase) but cannot say which phase.

The result is that stale compute instances (`ec2_instance`, `gce_instance`) can
accumulate in inventory, with attack paths computed over them.
`asset.EphemeralLivenessCond` (ADR 068) cannot help: it deliberately excludes
cloud instance types, because a stale `gce_instance` row is still tagged
`status=RUNNING` at last observation and is more often a victim of broken
collection than of deletion. That caution is justified: a collection outage can
leave most assets un-recollected for an extended period, and liveness-based
expiry would then discard live inventory.

### Decision

Make completeness a per-scope claim rather than a per-connector boolean, and
observe it before anything acts on it.

- `collect.Result` gains `CompletedEnumerations []ScopeEnumeration` —
  `{Scope, Types, Count}` — where `Scope` is a stable per-collector key
  (`<region>/ec2:instances`, `global/compute.instances`). `Partial` stays,
  unchanged, as the aggregate that still gates reconciliation.
- `Result.MarkComplete` is the ONLY writer, so every claim is validated in one
  place, and `TestCompletedEnumerationsHaveASingleWriter` (mutation-verified)
  keeps it that way. An unvalidated claim is the single input on which a future
  enforce mode would delete real inventory.
- A scope may be declared complete only next to the error handling that makes
  the claim true: `complete` beside `skip` in `internal/collect/aws/aws.go`,
  `noteComplete` beside `bestEffort` in `internal/collect/gcp/gcp.go`.
- Declared where completeness is genuinely knowable and nowhere else. AWS EC2
  instances/security-groups/subnets/VPCs paginate on `NextToken` and return
  `(nil, err)` on any page error, so a nil error IS a guarantee;
  `DescribeAddresses` is unpaginated. GCP's compute enumeration needed a fix
  first: `instances.aggregatedList` reports unreachable zones INSIDE a
  successful response (`Unreachables`, plus a per-zone `Warning`), so a nil
  error alone was never a completeness guarantee — those now flag `Partial` and
  declare nothing. GitHub (`listRepos` pages out early by design), Kubernetes
  (RBAC `Forbidden` on some lists is expected and deliberately not `Partial`)
  and every unaudited family declare nothing rather than a guess.
- Three observe-only gauges (`internal/obs/metrics_deletion.go`):
  `graph_sync_scope_last_complete_timestamp_seconds{connector,scope}` — the
  watermark whose age says how long a scope has been untrustworthy;
  `graph_sync_scope_enumerated_assets{connector,scope}` — the denominator a
  relative threshold needs; and `graph_sync_deletion_candidates{connector,completeness}`
  — stored asset hashes absent from the sweep, split by whether reconciliation
  was allowed to act. No alert rule: while most connectors report `partial`,
  that series carries most of the volume, so any threshold set now would fire
  permanently and mean nothing. These gauges are what a threshold has to be
  calibrated against.

At the time of this amendment nothing was deleted, tombstoned or resolved on the back of
this; ADR 081 (tombstones), ADR 083 (sync reconciliation, `internal/jobs/sync.go`
`coveredScopes`) and GuardDuty reconciliation (`reconcileGuardDutyFindings`) have since
started consuming it. The refusal
thresholds a future enforce mode must apply — relative and absolute caps,
consecutive-sweep confirmation, per-scope suppression on truncation, per-edge-type
suppression against `graph_ladybug_edge_cap_hit` (ADR 049) — are written down on
`Result.MarkComplete` so they are part of the signal's design rather than an
afterthought at the point of first deletion.

### Consequences

- The candidate count is per `(connector, completeness)`, NOT per
  `(connector, type)`. `connector_asset_hashes` stores no asset type, and the
  change-gated hash upsert could never backfill one onto the rows that matter (a
  stable asset's hash row is not rewritten; an already-absent asset's never is
  again). A type label would have to be guessed from the id's shape, so it is
  omitted rather than faked.
- A sweep that took the ADR 022 short-circuit never loads the stored hashes, so
  it publishes no candidate count at all rather than a zero. The gauge holds its
  last real reading, which is the correct answer for a sweep whose collected set
  fingerprinted identically.
- `computeAPI.ListInstances` now returns the unreachable-zone list. That is a
  real behaviour change, not only a signal: a GCP project with an unreachable
  zone is now correctly `Partial`, where before it was silently treated as a
  complete enumeration.
