package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeOptimizer struct {
	results []asset.OptimizeResult
	err     error
	calls   int
}

func (f *fakeOptimizer) Optimize(context.Context) ([]asset.OptimizeResult, error) {
	f.calls++
	return f.results, f.err
}

func TestOptimizeAssetsWorker_RunsAPass(t *testing.T) {
	opt := &fakeOptimizer{results: []asset.OptimizeResult{
		{Table: "findings", BaseBytes: 211 << 20},
		{Table: "assets", BaseBytes: 547 << 20, Skipped: true, SkipReason: asset.SkipProjection},
	}}
	w := &OptimizeAssetsWorker{assets: opt}

	require.NoError(t, w.Work(context.Background(), &river.Job[OptimizeAssetsArgs]{Args: OptimizeAssetsArgs{}}))
	require.Equal(t, 1, opt.calls)
}

func TestOptimizeAssetsWorker_WrapsFailure(t *testing.T) {
	w := &OptimizeAssetsWorker{assets: &fakeOptimizer{err: errors.New("code 241")}}

	err := w.Work(context.Background(), &river.Job[OptimizeAssetsArgs]{Args: OptimizeAssetsArgs{}})

	require.ErrorContains(t, err, "Work:")
	require.ErrorContains(t, err, "code 241")
}

// `OPTIMIZE … FINAL` blocks until the merge completes and the pass walks several
// tables — River's 1-minute default would cancel a normal run mid-merge.
func TestOptimizeAssetsWorker_TimeoutBeatsRiverDefault(t *testing.T) {
	require.Equal(t, optimizeTimeout, OptimizeAssetsWorker{}.Timeout(nil))
	require.Less(t, optimizeTimeout, optimizeInterval,
		"a pass must be bounded well inside its own cadence, or ticks overlap")
}

// The pass budget must exceed the sum of the per-table budgets, or the LAST
// tables in the walk are structurally unreachable — every pass, identically.
// Nothing else in the tree pins the two numbers to each other.
func TestOptimizePassBudgetCoversEveryTable(t *testing.T) {
	worst := time.Duration(len(asset.OptimizableTables)) * asset.OptimizeTableTimeout

	require.GreaterOrEqual(t, optimizeTimeout, worst,
		"%d tables x %s = %s of per-table budget must fit inside the %s pass budget",
		len(asset.OptimizableTables), asset.OptimizeTableTimeout, worst, optimizeTimeout)
}

// The rotation offset is derived from wall-clock on asset.OptimizeRotationPeriod.
// If the tick interval differs from that period, consecutive passes land in the
// same period and reuse the same start table — the rotation silently stops
// rotating and the starvation it prevents comes back.
func TestOptimizeIntervalMatchesTheRotationPeriod(t *testing.T) {
	require.Equal(t, asset.OptimizeRotationPeriod, optimizeInterval,
		"the wall-clock rotation only advances once per tick if these are equal")
}

// At most twice a day. None of the optimizable tables has a PARTITION BY, so
// each pass is a FULL-TABLE rewrite with no incremental unit; a 2h cadence would
// mean twelve whole-table rewrites a day per table, each leaving a mega-part
// that defeats ClickHouse's leveled merge selector for every later insert.
func TestOptimizeIntervalIsNotAFullTableRewriteTreadmill(t *testing.T) {
	require.GreaterOrEqual(t, optimizeInterval, 12*time.Hour,
		"an unpartitioned OPTIMIZE ... FINAL rewrites the whole table; more than twice a day is a treadmill")
}

// A failing table must not silence the ones behind it: the worker logs every
// result it got, including the failures, and still returns an error.
func TestOptimizeAssetsWorker_LogsPartialResultsOnFailure(t *testing.T) {
	opt := &fakeOptimizer{
		results: []asset.OptimizeResult{
			{Table: "nodes", BaseBytes: 30 << 20},
			{Table: "graph_edges", Err: errors.New("code 241")},
			{Table: "assets", BaseBytes: 547 << 20, Skipped: true, SkipReason: asset.SkipProjection},
		},
		err: errors.New("code 241"),
	}
	w := &OptimizeAssetsWorker{assets: opt}

	err := w.Work(context.Background(), &river.Job[OptimizeAssetsArgs]{Args: OptimizeAssetsArgs{}})

	require.Error(t, err)
	// logOptimizeResults must handle all three result shapes without panicking —
	// the failure branch is exactly the one that runs during an incident.
	logOptimizeResults(context.Background(), opt.results)
}

// Compaction is expensive and idempotent: it must never overlap itself, and a
// failed pass must not be retried immediately against an already-loaded server —
// the next scheduled tick is the retry.
func TestOptimizeAssetsArgs_InsertOpts(t *testing.T) {
	opts := OptimizeAssetsArgs{}.InsertOpts()

	require.Equal(t, queueMaintain, opts.Queue,
		"compaction needs its own lane: a multi-minute merge on the dangling or graph queue stalls that queue's real work")
	require.Equal(t, 1, opts.MaxAttempts,
		"a merge that failed under load must not be retried straight back into that load")
	require.True(t, opts.UniqueOpts.ByArgs)
	require.Equal(t, uniqueStates, opts.UniqueOpts.ByState,
		"two overlapping passes would double the load this job exists to reduce")
}
