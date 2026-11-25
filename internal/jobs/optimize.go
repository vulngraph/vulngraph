package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// The ClickHouse compaction job. Every ReplacingMergeTree table accumulates
// duplicate rows between merges, which every FINAL read and every argMax
// GROUP BY pays for, so this runs a periodic `OPTIMIZE TABLE ... FINAL` over
// each table in asset.OptimizableTables.
//
// `assets` needs a special case: while it still carries a projection with
// deduplicate_merge_projection_mode = 'rebuild', an OPTIMIZE FINAL rebuilds the
// whole projection on top of the base merge every pass. asset.skipReasonFor
// refuses that case by inspecting system.projection_parts directly, since a
// plain byte count can't tell the projection's bytes from the table's. Once the
// projection is dropped, the skip clears on its own.
//
// The cadence is per-pass over all tables, not per-table. Each table is bounded
// individually by asset.OptimizeTableTimeout and the whole pass by
// optimizeTimeout, sized so the former always fires first — see the consts.

const (
	// queueMaintain is the dedicated lane for ClickHouse compaction. A merge can
	// run for minutes; sharing the dangling lane would stall the resolve sweep, and
	// sharing correlate or graph would stall the pipeline itself.
	queueMaintain = "maintain"
	// maintainWorkers: one compaction at a time. Concurrent merges compete for the
	// same disk and the same ClickHouse query slots, which is the load this job
	// exists to reduce.
	maintainWorkers = 1

	// optimizeInterval: compaction cadence, and the single most important number
	// here. It MUST equal asset.OptimizeRotationPeriod (pinned by a test) — the
	// rotation offset is derived from wall-clock on that period, so a mismatch
	// makes consecutive passes reuse the same start table.
	//
	// Daily, not more frequent. None of the optimizable tables has a PARTITION BY,
	// so `OPTIMIZE ... FINAL` has no incremental unit — it merges the entire table
	// into a single part every time. A tighter interval means more full-table
	// rewrites, each leaving a mega-part that defeats ClickHouse's own leveled
	// merge selector. Once a day bounds accumulated duplication to a day of
	// writes for one rewrite. If duplication ever needs bounding tighter than
	// this, the answer is a partition key, not a faster treadmill.
	optimizeInterval = 24 * time.Hour

	// optimizeTimeout bounds one whole pass. It is deliberately larger than
	// len(OptimizableTables) * asset.OptimizeTableTimeout (5 x 4 min = 20 min), so
	// the per-table bound — not this one — is what stops a slow table, and every
	// table in the list is reached on every pass. optimize_test.go pins that
	// inequality: without it, a per-table timeout raise would silently reintroduce
	// tail starvation.
	optimizeTimeout = 30 * time.Minute
)

// OptimizeAssetsArgs is the periodic ClickHouse compaction tick.
type OptimizeAssetsArgs struct{}

func (OptimizeAssetsArgs) Kind() string { return "optimize_assets" }

func (OptimizeAssetsArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueMaintain,
		// MaxAttempts 1: a compaction pass either ran or it did not. Retrying a
		// merge that just timed out or lost to memory pressure only re-applies the
		// same load to the same overloaded server; the next scheduled tick is the
		// retry, a day later (optimizeInterval), with the situation changed.
		MaxAttempts: 1,
		// Unique while queued or running: merges are long, the cadence is short
		// relative to the worst case, and two passes racing over the same tables
		// would double the very load this reduces.
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// assetOptimizer compacts the ReplacingMergeTree tables. *asset.Service implements it.
type assetOptimizer interface {
	Optimize(ctx context.Context) ([]asset.OptimizeResult, error)
}

// OptimizeAssetsWorker runs one compaction pass.
type OptimizeAssetsWorker struct {
	river.WorkerDefaults[OptimizeAssetsArgs]
	assets assetOptimizer
}

// Timeout overrides River's 1-minute default — see optimizeTimeout.
func (OptimizeAssetsWorker) Timeout(_ *river.Job[OptimizeAssetsArgs]) time.Duration {
	return optimizeTimeout
}

func (w *OptimizeAssetsWorker) Work(ctx context.Context, _ *river.Job[OptimizeAssetsArgs]) error {
	results, err := w.assets.Optimize(ctx)
	// Results are logged even on failure: the pass continues past a failing table
	// and joins the errors, so knowing WHICH tables failed is the difference
	// between "the job is broken" and "one table is too big or too busy".
	logOptimizeResults(ctx, results)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}
	return nil
}

// logOptimizeResults reports one line per table. A skip is a WARNING, not an info
// line: every skip reason means a table is silently accumulating duplicates, and a
// guard that quietly stops doing its job is the failure mode this job exists to
// prevent.
func logOptimizeResults(ctx context.Context, results []asset.OptimizeResult) {
	logger := log.FromContext(ctx)
	for _, r := range results {
		switch {
		case r.Err != nil:
			logger.Error().Err(r.Err).
				Str("table", r.Table).Uint64("base_bytes", r.BaseBytes).
				Uint64("base_uncompressed_bytes", r.BaseUncompressedBytes).
				Msg("optimize failed for this table — the pass continued with the rest")
		case r.Skipped:
			logger.Warn().
				Str("table", r.Table).Uint64("base_bytes", r.BaseBytes).
				Uint64("base_uncompressed_bytes", r.BaseUncompressedBytes).
				Str("reason", r.SkipReason).
				Msg("optimize skipped — duplicates will not collapse for this table until the reason clears")
		default:
			logger.Info().
				Str("table", r.Table).Uint64("base_bytes", r.BaseBytes).
				Uint64("base_uncompressed_bytes", r.BaseUncompressedBytes).
				Dur("elapsed", r.Elapsed).
				Msg("optimize complete")
		}
	}
}
