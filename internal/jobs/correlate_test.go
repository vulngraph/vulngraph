package jobs

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/obs"
)

type fakeCorrelator struct {
	fullCalls    int
	partialCalls int
	partialIDs   []string
	err          error // when set, Correlate/PartialCorrelate return this instead of a clean run
}

func (f *fakeCorrelator) Correlate(context.Context) (int, error) {
	f.fullCalls++
	return 0, f.err
}
func (f *fakeCorrelator) PartialCorrelate(_ context.Context, ids []string) (int, error) {
	f.partialCalls++
	f.partialIDs = ids
	return 0, f.err
}

func correlateJob(createdAt time.Time, changedIDs []string) *river.Job[CorrelateArgs] {
	return &river.Job[CorrelateArgs]{
		JobRow: &rivertype.JobRow{CreatedAt: createdAt},
		Args:   CorrelateArgs{ChangedIDs: changedIDs},
	}
}

// A failed full sweep is not coverage for an old partial job.
func TestCorrelateWorker_OldPartialRunsAfterFailedFull(t *testing.T) {
	c := &fakeCorrelator{err: errors.New("full view refused")}
	w := &CorrelateWorker{correlate: c}
	require.Error(t, w.Work(t.Context(), correlateJob(time.Now(), nil)))
	c.err = nil
	require.NoError(t, w.Work(t.Context(), correlateJob(time.Now().Add(-24*time.Hour), []string{"i-123"})))
	require.Equal(t, 1, c.fullCalls)
	require.Equal(t, 1, c.partialCalls)
	require.Equal(t, []string{"i-123"}, c.partialIDs)
}

func TestCorrelateWorker_FreshPartialRuns(t *testing.T) {
	c := &fakeCorrelator{}
	w := &CorrelateWorker{correlate: c}

	err := w.Work(context.Background(), correlateJob(time.Now(), []string{"i-123"}))
	require.NoError(t, err)
	require.Equal(t, 1, c.partialCalls)
	require.Equal(t, []string{"i-123"}, c.partialIDs)
}

// Full sweeps are never stale-skipped — an old queued full sweep still does the
// authoritative whole-graph work.
func TestCorrelateWorker_FullSweepNeverSkipped(t *testing.T) {
	c := &fakeCorrelator{}
	w := &CorrelateWorker{correlate: c}

	old := time.Now().Add(-24 * time.Hour)
	err := w.Work(context.Background(), correlateJob(old, nil))
	require.NoError(t, err)
	require.Equal(t, 1, c.fullCalls, "full sweep runs regardless of age")
}

// The sync-side backpressure: at/over correlateQueueMax pending jobs, the depth
// check reports capacity reached (enqueuePartialCorrelate then skips).
func TestCorrelateQueueDepth(t *testing.T) {
	depth, err := correlateQueueDepth(context.Background(), fakeJobLister{jobs: correlateQueueMax + 1})
	require.NoError(t, err)
	require.Equal(t, correlateQueueMax+1, depth)

	depth, err = correlateQueueDepth(context.Background(), fakeJobLister{jobs: 3})
	require.NoError(t, err)
	require.Equal(t, 3, depth)
}

// TestCorrelateInsertOptsCapsRetries pins MaxAttempts against River's library
// default of 25, which this InsertOpts silently inherited by setting only Queue.
// A full sweep is idempotent and self-superseding, so the periodic tick is the
// retry; 25 attempts with River's growing backoff mean one deterministically
// failing sweep keeps re-reading a large materialized view for days.
func TestCorrelateInsertOptsCapsRetries(t *testing.T) {
	opts := CorrelateArgs{}.InsertOpts()
	require.Equal(t, 2, opts.MaxAttempts,
		"a failing full sweep must surface after one retry, not grind for ~25h")
	require.Equal(t, queueCorrelate, opts.Queue,
		"correlation must stay on its own queue so a whole-graph join cannot starve sync/respond")
}

// TestCorrelateWorker_SweepErrorClassification guards the fix for
// GraphCorrelateSweepsFailing: main.go passes the SAME context to
// river.Client.Start that signal.NotifyContext cancels on SIGINT/SIGTERM. This
// binary DOES set river.Config.SoftStopTimeout (workerSoftStopTimeout,
// client.go), which detaches an in-flight job's work context
// for a 20s grace period rather than cancelling it immediately — but a full
// correlate sweep runs for minutes, so it is still in flight when that grace
// period expires and River cancels it then. A full sweep interrupted by a
// routine pod termination (rolling deploy, node preemption, scale-down)
// therefore still fails with context.Canceled, which must land as "cancelled" in
// graph_correlate_sweeps_total, not "error": otherwise a burst of worker
// redeploys pages as a sustained sweep failure even though nothing on the
// ClickHouse side (view size, truncation) went wrong. A genuine failure (anything that is not context.Canceled, including
// this worker's own 20-minute Timeout expiring under real ClickHouse
// contention) must still land as "error" — the alert needs to keep seeing
// that.
func TestCorrelateWorker_SweepErrorClassification(t *testing.T) {
	cases := []struct {
		name       string
		changedIDs []string // nil → full sweep; non-nil → partial
		mode       string
		err        error
		wantStatus string
	}{
		{
			name: "full shutdown cancellation", changedIDs: nil, mode: "full",
			err: fmt.Errorf("Correlate: %w", context.Canceled), wantStatus: "cancelled",
		},
		{
			name: "full genuine failure", changedIDs: nil, mode: "full",
			err: errors.New("clickhouse: connection reset"), wantStatus: "error",
		},
		{
			name: "partial shutdown cancellation", changedIDs: []string{"i-123"}, mode: "partial",
			err: fmt.Errorf("PartialCorrelate: %w", context.Canceled), wantStatus: "cancelled",
		},
		{
			name: "partial genuine failure", changedIDs: []string{"i-123"}, mode: "partial",
			err: errors.New("clickhouse: connection reset"), wantStatus: "error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := obs.New()
			c := &fakeCorrelator{err: tc.err}
			w := &CorrelateWorker{correlate: c, metrics: m}

			err := w.Work(context.Background(), correlateJob(time.Now(), tc.changedIDs))
			require.Error(t, err)
			require.ErrorIs(t, err, tc.err)

			var gotStatuses []string
			for _, s := range gatherMetric(t, m.Registry(), "graph_correlate_sweeps_total") {
				if labelValue(s, "mode") != tc.mode {
					continue
				}
				status := labelValue(s, "status")
				gotStatuses = append(gotStatuses, status)
				if status == tc.wantStatus {
					require.Equal(t, float64(1), s.GetCounter().GetValue())
				}
			}
			require.Len(t, gotStatuses, 1, "exactly one status must be recorded per sweep attempt, got %v", gotStatuses)
			require.Equal(t, tc.wantStatus, gotStatuses[0])
		})
	}
}
