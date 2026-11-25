package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// LadybugRebuildArgs triggers an immediate Ladybug graph rebuild from ClickHouse.
// CorrelateWorker enqueues it after every completed full correlation sweep.
// Apart from the syncs the worker runs at boot (the initial load, its retry
// loop and the refresh after a snapshot warm start), that enqueue is what
// rebuilds the worker's graph: the worker has no periodic Ladybug sync (the
// optional serve replica re-syncs on its own 30-minute loop).
type LadybugRebuildArgs struct{}

func (LadybugRebuildArgs) Kind() string { return "ladybug_rebuild" }

// InsertOpts runs on the dedicated graph queue and deduplicates: if a rebuild
// is already pending/running, skip the insert so a burst of correlate
// completions never stacks up multiple identical rebuilds.
//
// It does not run on the correlate queue, which has one worker and sits near
// saturation — there the rebuild that makes topology changes visible to every
// graph query would wait behind whatever correlate backlog had piled up. See
// queueGraph.
//
// MaxAttempts is 2 because uniqueStates includes retryable: under River's default
// 25 a failing rebuild would sit retryable for days, and every rebuild request in
// that time would be dropped as its duplicate. The next correlate re-requests it.
func (LadybugRebuildArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue:       queueGraph,
		MaxAttempts: 2,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: uniqueStates,
		},
	}
}

// LadybugRebuildWorker executes a Ladybug graph rebuild synchronously. It delegates
// to the LadybugSyncer closure (same path used by CorrelateWorker), so the rebuild
// logic lives in one place.
type LadybugRebuildWorker struct {
	river.WorkerDefaults[LadybugRebuildArgs]
	ladybug LadybugSyncer // nil disables the worker (guard in Work)
}

// Timeout matches the correlate worker's ladybug sync budget.
// The full rebuild (ClickHouse read + Ladybug insert + BFS) typically takes 2-4 min.
func (w *LadybugRebuildWorker) Timeout(_ *river.Job[LadybugRebuildArgs]) time.Duration {
	return 10 * time.Minute
}

func (w *LadybugRebuildWorker) Work(ctx context.Context, _ *river.Job[LadybugRebuildArgs]) error {
	if w.ladybug == nil {
		return nil // Ladybug not configured in this deployment
	}
	start := time.Now()
	logger := log.FromContext(ctx)
	if err := w.ladybug.Sync(ctx); err != nil {
		return fmt.Errorf("LadybugRebuildWorker: %w", err)
	}
	logger.Info().Dur("elapsed", time.Since(start)).Msg("ladybug graph rebuilt (event-driven post-correlate)")
	return nil
}
