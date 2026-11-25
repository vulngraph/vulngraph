package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/vulngraph/vulngraph/pkg/cronexpr"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// SavedQueryScheduler runs the saved Cypher queries that are due this tick.
// *savedquery.Service satisfies it. dueFn decides whether a cron schedule fires
// at the given time — injected so cron evaluation lives here, in the jobs layer.
type SavedQueryScheduler interface {
	RunScheduled(ctx context.Context, dueFn func(schedule string) bool) (int, error)
}

// RunSavedQueriesArgs is the per-minute tick that evaluates scheduled saved
// queries and runs the ones whose cron matches the current minute.
type RunSavedQueriesArgs struct{}

func (RunSavedQueriesArgs) Kind() string { return "run_saved_queries" }

func (RunSavedQueriesArgs) InsertOpts() river.InsertOpts {
	// The work is light (a handful of read-only Cypher queries). It runs on the
	// graph queue rather than the single-worker correlate queue: a per-minute
	// schedule cannot live behind a correlate backlog and still mean "every
	// minute" (see queueGraph). Dedupe like LadybugRebuildArgs so ticks never stack
	// up regardless.
	return river.InsertOpts{
		Queue:      queueGraph,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// tickStaleAfter is how old a per-minute cron tick may be and still run. A
// tick evaluated against wall-clock "now" (the profile worker) would re-fire the
// CURRENT minute when stale, so a backlog of stacked ticks would trigger the
// same scheduled scans repeatedly. Stale ticks are skipped; the next minute's
// tick covers the present.
const tickStaleAfter = 2 * time.Minute

// SavedQueryWorker executes scheduled saved queries via the savedquery service.
type SavedQueryWorker struct {
	river.WorkerDefaults[RunSavedQueriesArgs]
	queries SavedQueryScheduler
	now     func() time.Time
}

// Timeout overrides River's 1-minute default: a tick runs every due query in
// turn, each bounded by the graph user pool's own per-query timeout, so a
// handful of slow queries would otherwise be cut off mid-run.
func (w *SavedQueryWorker) Timeout(_ *river.Job[RunSavedQueriesArgs]) time.Duration {
	return 10 * time.Minute
}

func (w *SavedQueryWorker) Work(ctx context.Context, job *river.Job[RunSavedQueriesArgs]) error {
	nowFn := w.now
	if nowFn == nil {
		nowFn = time.Now
	}
	t := tickMinute(job.JobRow)
	if nowFn().UTC().Sub(t) > tickStaleAfter {
		log.FromContext(ctx).Info().Time("tick_minute", t).
			Msg("saved-query tick stale — skipped (its minute passed)")
		return nil
	}
	ran, err := w.queries.RunScheduled(ctx, func(schedule string) bool {
		return cronexpr.Due(schedule, t)
	})
	if err != nil {
		return fmt.Errorf("Work: run scheduled: %w", err)
	}
	if ran > 0 {
		log.FromContext(ctx).Info().Int("queries", ran).Msg("saved-query schedule: ran due queries")
	}
	return nil
}

// tickMinute is the minute a tick stands for: the periodic job's scheduled
// time, truncated to the minute. Evaluating the cron against it rather than
// the wall clock means a tick that starts late still fires the queries due in
// ITS minute (not skipping them for the next one) and never fires the next
// minute's queries twice. A retry reschedules the job, so a retried tick falls
// back to its creation time, which retries do not move.
func tickMinute(job *rivertype.JobRow) time.Time {
	t := job.ScheduledAt
	if job.Attempt > 1 || t.IsZero() {
		t = job.CreatedAt
	}
	return t.UTC().Truncate(time.Minute)
}
