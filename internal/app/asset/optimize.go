package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// Query strings are package consts named for what they fetch (CLAUDE.md).
const (
	// liveAssetIDs returns the subset of the given ids that are LIVE — present in
	// the assets table AND passing the ephemeral-liveness gate. EphemeralLivenessCond
	// is embedded verbatim so there is exactly ONE definition of "this pod still
	// exists" in the codebase, matching what the Ladybug load and the correlate
	// LoadView apply (asset/liveness_test.go pins that).
	//
	// The inner GROUP BY collapses ReplacingMergeTree versions and aliases the two
	// columns the condition reads to NON-shadowing names, then re-projects them:
	// aliasing them directly as `type`/`last_seen` would put those names in scope
	// for EphemeralLivenessCond's own correlated subquery, causing it to resolve
	// against the outer row instead of the assets table it names. The correlated
	// max(last_seen) inside the condition names `assets` explicitly so it resolves
	// against the type's own high-water mark, never wall-clock.
	//
	// A non-ephemeral type short-circuits the condition to true, so this is a
	// straight existence check for everything except the ephemeral types.
	liveAssetIDs = `SELECT id FROM (
		SELECT id, asset_type AS type, latest_seen AS last_seen FROM (
			SELECT id, argMax(type, synced_at) AS asset_type, max(last_seen) AS latest_seen
			FROM assets WHERE id IN (%s) GROUP BY id
		)
	) WHERE ` + EphemeralLivenessCond

	// typeHighWater returns the most recent last_seen across one asset TYPE — when
	// that type was last collected. Zero means the type has no assets at all, which
	// a caller must treat as "nothing to reason about" rather than "everything is
	// gone": the ephemeral-liveness cutoff is only meaningful relative to a real
	// high-water mark.
	typeHighWater = `SELECT max(last_seen) FROM assets WHERE type = ?`

	// verifiedExpiredEphemeralIDs is liveAssetIDs' negation: the subset of the
	// given ids that DO have an asset row but fail EphemeralLivenessCond — a real,
	// resolved corpse, not a fabricated or never-seen id. A non-ephemeral type's
	// row can never appear here since EphemeralLivenessCond short-circuits true for
	// it. This lets a caller upgrade "declared ephemeral type" (producer-asserted,
	// unverifiable in isolation) to "verified expired" (checked against the asset
	// table this process itself maintains), in the same one-query, whole-batch
	// shape as liveAssetIDs.
	verifiedExpiredEphemeralIDs = `SELECT id FROM (
		SELECT id, asset_type AS type, latest_seen AS last_seen FROM (
			SELECT id, argMax(type, synced_at) AS asset_type, max(last_seen) AS latest_seen
			FROM assets WHERE id IN (%s) GROUP BY id
		)
	) WHERE NOT (` + EphemeralLivenessCond + `)`

	// optimizeTable merges a ReplacingMergeTree's active parts so its duplicate
	// versions actually collapse. Table names are never user input — the %s is
	// filled only from OptimizableTables below.
	//
	// FINAL, and deliberately NOT DEDUPLICATE. `OPTIMIZE … FINAL` collapses rows
	// per the table's ReplacingMergeTree version column (synced_at), keeping the
	// newest — the semantics every reader here already assumes. `DEDUPLICATE`
	// means something else entirely: drop rows that are byte-identical across the
	// listed columns, ignoring the version column. On these tables that would
	// discard legitimately distinct history and is never what is wanted.
	//
	// optimize_throw_if_noop is left at its default (0): a table that is already
	// fully merged must be a silent success, not an error that fails the job.
	optimizeTable = `OPTIMIZE TABLE %s FINAL`

	// tableBaseStats sizes a table's BASE data — the parts' own columns, excluding
	// any projection stored inside them. bytes_on_disk is the wrong column here:
	// it includes projections that `OPTIMIZE … FINAL` does not rewrite in place,
	// so a guard reading it either skips a table that is actually tiny, or starts
	// optimizing a table its projection makes far more expensive than it looks.
	//
	// BOTH byte columns are read, and the GUARD is on the uncompressed one. A merge
	// decompresses every source part, sorts, and recompresses, so its cost is
	// proportional to UNCOMPRESSED bytes; these tables compress 5-10x, so a ceiling
	// on compressed bytes would silently permit a merge an order of magnitude
	// larger than the number it checked. data_compressed_bytes is kept only
	// because it's what an operator sees in system.parts, for the log line.
	//
	// active_parts is returned alongside so the caller can FAIL CLOSED: a sum with
	// no rows behind it is 0, indistinguishable from a genuinely empty table.
	// Zero active parts means "nothing to merge, or this is not the table you
	// think it is" — never "safe to optimize".
	tableBaseStats = `SELECT sum(data_compressed_bytes), sum(data_uncompressed_bytes), count()
		FROM system.parts
		WHERE active AND database = currentDatabase() AND table = ?`

	// tableProjectionParts counts a table's active PROJECTION parts.
	//
	// A projection changes what OPTIMIZE costs by a large factor: with
	// deduplicate_merge_projection_mode = 'rebuild', a deduplicating merge does
	// not skip or drop the projection, it REBUILDS it — so the guard is on the
	// projection itself, not on a byte count that can't see that cost.
	tableProjectionParts = `SELECT count() FROM system.projection_parts
		WHERE active AND database = currentDatabase() AND table = ?`
)

// EphemeralTypes are the asset types whose absence from recent collection means
// the resource is GONE rather than merely uncollected — the types
// EphemeralLivenessCond filters on. Declared here so callers (the finding
// lifecycle sweep) can name them without re-deriving the list by parsing SQL;
// optimize_test.go pins the two to each other.
var EphemeralTypes = []string{"k8s_pod", "container", "k8s_job"}

// OptimizableTables are the ReplacingMergeTree tables whose duplicate versions
// only collapse when a merge runs. Every entry is read somewhere with FINAL or
// with argMax over versions, so uncollapsed duplicates cost every reader.
//
// The ORDER here carries no priority: a pass starts at a rotating offset (see
// Optimize) precisely so that position in this list stops deciding which tables
// get compacted and which are starved.
//
// No table here is excluded for carrying a projection: the projection guard
// (tableProjectionParts) skips any table that has one, so this list doesn't
// need to hardcode an exclusion.
var OptimizableTables = []string{"graph_edges", "signals", "beliefs", "findings", "assets"}

// OptimizeMaxUncompressedBytes is the ceiling on a table's BASE UNCOMPRESSED
// bytes above which the optimize job skips it.
//
// Uncompressed, not compressed, because that is what a merge actually processes:
// it decompresses every source part, merge-sorts, and recompresses. These tables
// compress 5-10x, so a ceiling on compressed bytes would authorise merges many
// times larger than the number it checked.
//
// 8 GiB is comfortably inside OptimizeTableTimeout (4 min) at typical merge
// throughput. A table that grows past it wants a partition key or a smaller
// sort key, not a periodic full-table rewrite. A skip is logged at WARN, never
// silent.
const OptimizeMaxUncompressedBytes = 8 << 30

// OptimizeTableTimeout bounds ONE table's merge, client-side and (via
// max_execution_time) server-side.
//
// None of these tables has a PARTITION BY, so `OPTIMIZE … FINAL` has no
// incremental unit — it merges the whole table into a single part in one
// statement, with no partial mode to fall back to. An explicit per-statement
// bound is the only thing standing between one pathological table and the
// entire pass budget. jobs/optimize_test.go pins that the per-table timeout
// times the table count fits inside the job's pass budget.
const OptimizeTableTimeout = 4 * time.Minute

// OptimizeRotationPeriod is the cadence the rotation offset advances on, and MUST
// equal the job's tick interval (jobs.optimizeInterval; optimize_test.go over in
// internal/jobs pins the two together).
//
// Rotation exists because the pass walks a FIXED list under a SHARED budget: if
// the early tables use it up, the late ones are never reached — identically, on
// every pass, forever. Deriving the offset from wall-clock rather than a counter
// keeps it stateless, so it survives pod restarts instead of resetting to zero
// every time.
const OptimizeRotationPeriod = 24 * time.Hour

// Skip reasons recorded on an OptimizeResult, and logged. Stable strings — they
// are what an operator greps for when a table stops being compacted.
const (
	// SkipProjection: merging would rebuild the table's projection.
	SkipProjection = "active projection: a deduplicating merge would rebuild it"
	// SkipTooLarge: base data above OptimizeMaxUncompressedBytes.
	SkipTooLarge = "base data above the size guard"
	// SkipNoParts: no active parts at all. Fail-closed — an empty result is not
	// evidence that a merge is safe, it is evidence the question was not answered.
	SkipNoParts = "no active parts (empty, unknown, or wrong database)"
)

// LiveIDs returns which of the given asset ids are live: present in the store and,
// for an ephemeral type, collected recently enough relative to that type's own
// high-water mark. Ids not returned are gone — either the row never existed or
// the resource stopped being collected long enough ago that absence means deletion.
func (r *CHRepo) LiveIDs(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	placeholders, args := dbutil.CHIn(ids)
	query := fmt.Sprintf(liveAssetIDs, placeholders)

	var out []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, id)
		}
		return rows.Err()
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("LiveIDs: %w", err)
	}
	return out, nil
}

// verifyExpiredEphemeralChunk caps how many ids go into one
// VerifyExpiredEphemeral query's IN list. ClickHouse's ?-placeholder binding
// substitutes values into the query TEXT client-side, so the SIZE of the ids
// matters as much as the count — and these are full k8s pod/container paths,
// not short opaque ids. An unchunked batch can exceed max_query_size and fail
// every call outright. purgeEdgeChunk's larger size is not reused here
// because that chunk holds short asset ids, not long path strings.
const verifyExpiredEphemeralChunk = 1000

// VerifyExpiredEphemeral checks a batch of candidate ids against the asset
// table and returns which of them are verified corpses: a real row exists but
// it fails EphemeralLivenessCond. Ids that never had a row at all — a
// genuinely dangling reference — are simply absent from the result, same
// convention as LiveIDs/ExistingIDs. Empty input returns an empty, non-nil map
// so a caller can index it unconditionally.
func (r *CHRepo) VerifyExpiredEphemeral(ctx context.Context, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	for start := 0; start < len(ids); start += verifyExpiredEphemeralChunk {
		end := min(start+verifyExpiredEphemeralChunk, len(ids))
		chunk := ids[start:end]

		qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		placeholders, args := dbutil.CHIn(chunk)
		query := fmt.Sprintf(verifiedExpiredEphemeralIDs, placeholders)

		err := r.ch.Select(qCtx, func(rows driver.Rows) error {
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return fmt.Errorf("scan: %w", err)
				}
				out[id] = true
			}
			return rows.Err()
		}, query, args...)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("VerifyExpiredEphemeral: %w", err)
		}
	}
	return out, nil
}

// TypeHighWater returns the most recent last_seen across one asset type. Zero
// means the type has no assets at all.
func (r *CHRepo) TypeHighWater(ctx context.Context, assetType string) (time.Time, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out time.Time
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			if err := rows.Scan(&out); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
		}
		return rows.Err()
	}, typeHighWater, assetType)
	if err != nil {
		return time.Time{}, fmt.Errorf("TypeHighWater: %w", err)
	}
	return out, nil
}

// TableStats are the facts the optimize guard needs about one table.
type TableStats struct {
	// BaseBytes is compressed on-disk size of the parts' own columns, excluding
	// projections. Reported, never guarded on — see OptimizeMaxUncompressedBytes.
	BaseBytes uint64
	// BaseUncompressedBytes is what a merge actually reads, sorts and rewrites.
	// This is the quantity the size guard applies to.
	BaseUncompressedBytes uint64
	ActiveParts           uint64
	ProjectionParts       uint64
}

// TableStats reports a table's base size, active part count and projection part
// count. It deliberately returns all three from the storage layer rather than a
// single "is it safe" bool: the policy belongs in the service, the measurements
// here.
func (r *CHRepo) TableStats(ctx context.Context, table string) (TableStats, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var out TableStats
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			if err := rows.Scan(&out.BaseBytes, &out.BaseUncompressedBytes, &out.ActiveParts); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
		}
		return rows.Err()
	}, tableBaseStats, table)
	if err != nil {
		return TableStats{}, fmt.Errorf("TableStats: %w", err)
	}

	err = r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			if err := rows.Scan(&out.ProjectionParts); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
		}
		return rows.Err()
	}, tableProjectionParts, table)
	if err != nil {
		return TableStats{}, fmt.Errorf("TableStats: projections: %w", err)
	}
	return out, nil
}

// OptimizeTable merges one ReplacingMergeTree's parts so its duplicate versions
// collapse. The statement blocks until the merge completes; it is fully
// idempotent, so a timeout costs only the unfinished work, never correctness.
//
// Bounded twice, deliberately. The Go deadline frees this pod's ClickHouse
// semaphore slot; max_execution_time makes the SERVER abandon the merge, which a
// client-side cancel of a long-running OPTIMIZE cannot be relied on to do. Without
// the server-side bound a wedged merge keeps burning CPU on a possibly already
// CPU-constrained instance long after the job gave up.
func (r *CHRepo) OptimizeTable(ctx context.Context, table string) error {
	qCtx, cancel := context.WithTimeout(ctx, OptimizeTableTimeout)
	defer cancel()
	qCtx = r.ch.WithQuerySettings(qCtx, map[string]any{
		"max_execution_time": int(OptimizeTableTimeout.Seconds()),
	})

	if err := r.ch.Exec(qCtx, fmt.Sprintf(optimizeTable, table)); err != nil {
		return fmt.Errorf("OptimizeTable %s: %w", table, err)
	}
	return nil
}

// LiveIDs returns the subset of ids whose asset is still live (see the repo
// method). The finding lifecycle sweep uses it to tell a finding on a resource
// that still exists from one on a corpse.
func (s *Service) LiveIDs(ctx context.Context, ids []string) ([]string, error) {
	out, err := s.repo.LiveIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("LiveIDs: %w", err)
	}
	return out, nil
}

// VerifyExpiredEphemeral checks a batch of ids against the asset table (see
// the repo method). The Ladybug rebuild uses it so "endpoint_expired" reflects a
// row this process itself confirmed is a corpse, rather than trusting the
// edge's own declared endpoint type.
func (s *Service) VerifyExpiredEphemeral(ctx context.Context, ids []string) (map[string]bool, error) {
	out, err := s.repo.VerifyExpiredEphemeral(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("VerifyExpiredEphemeral: %w", err)
	}
	return out, nil
}

// TypeHighWater reports when an asset type was last collected. Zero time means
// the type has no assets at all — callers must treat that as "no basis to judge
// anything gone", never as "everything is gone".
func (s *Service) TypeHighWater(ctx context.Context, assetType string) (time.Time, error) {
	t, err := s.repo.TypeHighWater(ctx, assetType)
	if err != nil {
		return time.Time{}, fmt.Errorf("TypeHighWater: %w", err)
	}
	return t, nil
}

// OptimizeResult records what one optimize pass did to one table, so the caller
// can log an outcome per table instead of one opaque success.
type OptimizeResult struct {
	Table                 string
	BaseBytes             uint64
	BaseUncompressedBytes uint64
	Skipped               bool
	SkipReason            string        // one of the Skip* consts; empty when not skipped
	Elapsed               time.Duration // merge wall-clock; zero when skipped
	// Err is this table's failure. The pass CONTINUES past it — one unmergeable
	// table must not silence the five behind it — so the error is recorded per
	// table rather than only returned once for the whole pass.
	Err error
}

// skipReasonFor applies the optimize policy to one table's measurements. Empty
// means "optimize it". Pure, so the policy is table-testable without a database.
//
// Fail-closed by construction: every path that does not have positive evidence
// the merge is cheap returns a skip. The default branch is "optimize" only after
// three affirmative checks — parts exist, no projection would be rebuilt, and the
// base data is under the ceiling.
func skipReasonFor(st TableStats) string {
	switch {
	case st.ActiveParts == 0:
		return SkipNoParts
	case st.ProjectionParts > 0:
		return SkipProjection
	case st.BaseUncompressedBytes > OptimizeMaxUncompressedBytes:
		return SkipTooLarge
	default:
		return ""
	}
}

// rotationOffset picks which index of an n-entry list a pass starts at, from
// wall-clock alone. Stateless on purpose: a counter field would reset on every
// pod restart, and on spot nodes that means it resets constantly and the rotation
// never actually rotates.
//
// Pure and total: n <= 0 returns 0, and the result is always in [0, n).
func rotationOffset(now time.Time, n int) int {
	if n <= 0 {
		return 0
	}
	periods := now.UTC().Unix() / int64(OptimizeRotationPeriod/time.Second)
	return int(((periods % int64(n)) + int64(n)) % int64(n))
}

// rotate returns tables starting at offset and wrapping around, without mutating
// the input. Every entry appears exactly once.
func rotate(tables []string, offset int) []string {
	if len(tables) == 0 {
		return nil
	}
	offset %= len(tables)
	out := make([]string, 0, len(tables))
	out = append(out, tables[offset:]...)
	out = append(out, tables[:offset]...)
	return out
}

// Optimize merges every OptimizableTables entry that passes the guard (see
// skipReasonFor), collapsing ReplacingMergeTree duplicates. It returns one result
// per table, skips and failures included — a skipped table is a fact the operator
// needs, not an absence.
//
// Two properties matter beyond the merging itself:
//
// STARVATION. The pass shares one budget across the whole list. Walking a fixed
// order means that whenever the budget runs short the SAME tail is skipped every
// pass, forever. The start point therefore rotates (rotationOffset), so over a
// full rotation every table gets the first, cheapest slot.
//
// CONTINUATION. A single failing table must not abort the pass and silence every
// table behind it — each table's error is recorded on its own result, the walk
// continues, and the errors are joined into one return value so the job still
// fails loudly.
//
// Tables are optimized one at a time, never concurrently: each holds one of a
// limited number of per-pod ClickHouse query slots for the duration of its
// merge, and the point of this job is to reduce load, not to burst it.
func (s *Service) Optimize(ctx context.Context) ([]OptimizeResult, error) {
	order := rotate(OptimizableTables, rotationOffset(time.Now(), len(OptimizableTables)))

	results := make([]OptimizeResult, 0, len(order))
	var errs []error
	for _, table := range order {
		if err := ctx.Err(); err != nil {
			// The pass budget is spent. Stop rather than issue merges against a dead
			// context, and say so — a truncated pass must never look like a clean one.
			errs = append(errs, fmt.Errorf("Optimize: budget spent before %s: %w", table, err))
			break
		}

		st, err := s.repo.TableStats(ctx, table)
		if err != nil {
			err = fmt.Errorf("Optimize: %s: %w", table, err)
			results = append(results, OptimizeResult{Table: table, Err: err})
			errs = append(errs, err)
			continue
		}
		if reason := skipReasonFor(st); reason != "" {
			results = append(results, OptimizeResult{
				Table: table, BaseBytes: st.BaseBytes, BaseUncompressedBytes: st.BaseUncompressedBytes,
				Skipped: true, SkipReason: reason,
			})
			continue
		}
		start := time.Now()
		if err := s.repo.OptimizeTable(ctx, table); err != nil {
			err = fmt.Errorf("Optimize: %s: %w", table, err)
			results = append(results, OptimizeResult{
				Table: table, BaseBytes: st.BaseBytes, BaseUncompressedBytes: st.BaseUncompressedBytes,
				Elapsed: time.Since(start), Err: err,
			})
			errs = append(errs, err)
			continue
		}
		results = append(results, OptimizeResult{
			Table: table, BaseBytes: st.BaseBytes, BaseUncompressedBytes: st.BaseUncompressedBytes,
			Elapsed: time.Since(start),
		})
	}
	return results, errors.Join(errs...)
}
