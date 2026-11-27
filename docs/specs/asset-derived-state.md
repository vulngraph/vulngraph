# Derived asset state without observation rewrites

The concurrent pipeline fixture found a lost update: correlation read an asset,
sync committed a newer name and metadata, and correlation reinserted the old row
with its new risk score and a later version. The newer observation disappeared.

Inventory remains owned by collectors. CIEM scores computed from a collected
observation join that observation before its single write and content fingerprint.
Finding risk and correlation annotations have separate storage and producer
versions; neither can write names, tags, observation times or inventory metadata.

Finding risk publishes a complete generation. It computes the existing raw
severity contribution (critical 80, high 60), writes bounded batches, and publishes
a reserved empty-ID commit row in the same risk table only after every batch
succeeds. Readers select the greatest committed generation and exclude commit
rows from risk data and completeness counts. Empty resource IDs are rejected. Failures before commit and partial refreshes cannot clear prior risk; a complete snapshot may finish within the bounded write-drain budget. Empty
complete generations clear contributions, and older late publications cannot
replace newer ones. Collector/CIEM risk combines with finding risk using max.

The two-table publication prototype failed a deterministic snapshot-acquisition
barrier: both point and list readers selected a newer marker against an older
data snapshot and returned only base risk. Ordinary concurrent repeats missed it.
Every application `CH.Select` now enforces
`enable_shared_storage_snapshot_in_query=1`, including over caller or DSN defaults.
Both risk data and commit-marker references use the same underlying table and
query snapshot. A visible commit row therefore has its already-committed data in
that snapshot. The separate publication ledger is only for cleanup; it cannot
select visible risk. This relies on the deployed engine's per-storage snapshot
cache, not cross-table atomicity ([pinned implementation](https://github.com/ClickHouse/ClickHouse/blob/v26.8.34.13-lts/src/Storages/MergeTree/MergeTreeData.cpp#L11663)).
The delayed-snapshot replay and explicit disabled-setting override are regression
gates; unsupported settings fail the read rather than silently weakening it.

The current annotation producer owns only K8s manifest drift. Each record binds
to its manifest key and live type, so an old interpretation cannot annotate a
changed declaration. Empty drift writes an explicit JSON deletion. Producer time
comes from ClickHouse before evaluation; independently ordered annotation rows
cannot overwrite risk. Finding risk belongs to the canonical resource ID: an unresolved contribution
remains conservative across a same-ID reappearance until a newer complete
finding evaluation clears it. Derived records cannot recreate an absent inventory
row. `first_discovered_at` is historical observation time, not an incarnation
fence. Matching an annotation's declaration input does not prove its external
liveness conclusion is current; successful re-evaluation supplies freshness.
This is not a claim of one committed source generation across inventory, findings
and correlation queries.

Shared asset read views apply the overlay before filters, ordering, pagination,
export and graph loading. Point reads retain raw-version argMax and id pruning;
full reads retain FINAL. Correlation's projected metadata reads use the same
overlay without expanding their metadata key list. These extra joins require
measured cost evidence on the existing fixtures.

Acceptance requires independent service interleavings, complete and interrupted
publications, reverse completion order, score clearing, declaration changes,
deletion/reappearance, repeated reads before and after merges, and integrated
sync/correlate/enrich/graph/HTTP output parity. Preserve failing baseline evidence.

The initial age-only TTL was rejected. The candidate pins completed risk rows
before publishing; only unpublished rows and retired markers can expire. GC
retains the newest two complete generations and a one-hour reader grace,
then deletes older data and every version of its publication marker. Marker TTL
alone is insufficient: it can remove a newer retired version before older versions
merge away. Abandoned unselected generations have a one-day age threshold.
The pin copy and cleanup add work that must be included in measurements. Pre-upgrade base scores have no reliable producer provenance. They remain
conservative until a fresh collector observation replaces them; migration cannot
subtract an inferred finding contribution without risking removal of CIEM risk.
Tests must cover this transition, deletion/reappearance, and merges. Production
acceptance still requires query/write-cost evidence and full required gates.

The actual unchanged-fingerprint sync path writes the fresh collected rows as
well: the fingerprint skips redundant checks/enrichment, not observation writes.
Its worker regression test starts with a legacy whole-row score, confirms the
fingerprint and quiet-sync streak, and requires the next successful observation
to replace that base score. A failed collection cannot supply that replacement.

## Inventory page costs

Joining derivations before limiting a wide inventory page exceeded the existing
query-memory guard. List now selects `(type,id,synced_at)` page keys, then
hydrates only those observation versions and attaches current finding risk.
Derived score filters still precede the page limit. The whole statement uses
the enforced shared storage snapshots. Inventory excludes declaration types,
which are the only types eligible for the annotation metadata overlay.

Matched local runs used ClickHouse 26.8.47.5, two CPUs, a 3 GiB container, 16 KiB
metadata values and three retained observation versions. Populated fixtures also
contain two complete risk generations, one newer unpublished generation and an
annotation row per asset. Each filter/page has three measured repetitions.

| Assets | Joined first page, median / peak query memory | Version-key page, median / peak query memory |
| --- | --- | --- |
| 10,000 | 96.9 ms / 585.5 MB | 41.4 ms / 27.3 MB |
| 100,000 | 1,509.7 ms / 2,532.5 MB | 102.0 ms / 69.9 MB |

All 48 candidate reads per populated run preserved exact independently expected
pages, fields and scores. Five baseline reads in the 100,000-asset run exhausted
the server memory limit; their errors are retained, not treated as successful
timings. Candidate reads remained within the original byte and memory ceilings.
The empty-derived-state control is a tradeoff: at 10,000 assets its first page
changed from 36.4 ms / 24.8 MB to 42.1 ms / 26.2 MB. This is not a universal
latency improvement or a whole-system capacity result.

Selective reads retain a scan tradeoff: the empty second account-filtered page
at 1,000 assets reads 5,002 rows versus 2,002 for the joined baseline, while its
median latency changes from 12.6 to 7.0 ms and peak memory from 37.5 to 1.47 MB.
That extra derived-state scan remains PERF-03 work; the broad-page regression
guard does not cover it. Its absolute byte and memory budgets still apply.

The original empty-fixture budgets remain unchanged. The populated fixture
separately reports physical rows in all input tables and permits at most five
times that input population to be read. It is not a pass of the old asset-only
row ceiling. An additional matched guard rejects broad, unfiltered page selection
that reads more than its baseline plus one asset-key pass. The same fixed byte
and memory budgets apply to both fixtures. The Go oracle determines membership
and risk independently; a bounded raw-observation read checks the remaining
fields even when the historical joined query cannot complete.

## Local measured envelope

The fixture uses one worker process, 500 synthetic AWS-shaped connector scopes
and 100,000 assets. Ten percent of scopes hold ninety percent of the assets;
one percent of payloads are 16 KiB. It generates 1,350 provider findings and holds
each allocated collection result for a disclosed 500 ms. Queue limits remain
20 sync and 10 enrichment workers. This models allocation and downstream work;
it does not measure cloud SDKs, API latency or a mixed-provider estate.

The deployed ClickHouse image/configuration is 26.8.34.13, two CPUs, a 3 GiB
server limit and 4 GiB container limit. The worker has one CPU and 4 GiB, including
a 1,280 MiB native graph budget; Postgres has one CPU and 1 GiB. Aligned sampled
cgroup totals include caches and the benchmark observer, not just resident heaps.

| Replay | Lifecycle/read correctness | Inventory p95 / p99 | Largest aligned active sample |
| --- | --- | --- | --- |
| Same-table publication, early broad-work start | 6 waves, 712 reads, no errors | 309 / 615 ms | 3.585 GB, graph active |
| Broad work after a quarter of scopes, with active enrichment | 6 waves, 740 reads, no errors | 299 / 480 ms | 4.127 GB, graph active |

These 100,000-asset envelope runs precede the inventory-page rewrite above.
A fresh 5,000-asset six-wave replay passes with the revised reader; the older
whole-system peaks are not measurements of that rewrite.

Each wave independently verifies asset values, persisted enrichment scores,
deletion/reappearance and native graph counts. The second replay also checks
native workload risk values. Three samples show sync, enrichment, full correlation
and graph work together; one includes eight held collection results. The largest
of those three totals 3.393 GB. No sample shows all four during native COPY/BFS.
The fixtures use different scheduling, so this table is not a matched speedup
comparison or a capacity recommendation. Required repeated/profile/native/aged
assurance remains incomplete.

The second replay recorded twelve risk publications: 14,836 staged scores and
14,836 pinned copies, twelve same-table commit rows, twelve cleanup-ledger rows,
and 48 cleanup statements. Sampled database maxima were 39 active parts and one
pending mutation affecting one part. Two-second sampling can miss short-lived
mutation/merge peaks. Whole-process CPU and raw query/IO counters are retained
alongside these counts; read-only timings do not cover publication cost.

`scripts/benchmark-connector-envelope.sh` retains the exact uncommitted source
patch and file hashes, rendered deployment configuration, image identities,
effective settings, query costs, resource timelines and failure logs.
`scripts/summarize-connector-envelope.py` aligns samples instead of adding
independent peaks. The small publication/lifecycle replay runs in native CI;
large envelopes remain explicit local/manual work. Failed historical whole-row
and two-table publication replays are retained as baseline evidence.
