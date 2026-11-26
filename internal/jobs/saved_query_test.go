package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
)

type fakeSavedQueryScheduler struct {
	calls int
	due   func(string) bool
}

func (f *fakeSavedQueryScheduler) RunScheduled(_ context.Context, due func(string) bool) (int, error) {
	f.calls++
	f.due = due
	return 0, nil
}

func tickJob(createdAt time.Time) *rivertype.JobRow {
	return &rivertype.JobRow{CreatedAt: createdAt}
}

// A backlog of stacked stale ticks must not fire scheduled work repeatedly:
// stale ticks are skipped and the next minute's tick covers the present.
func TestSavedQueryWorker_StaleTickSkipped(t *testing.T) {
	s := &fakeSavedQueryScheduler{}
	w := &SavedQueryWorker{queries: s}

	stale := time.Now().UTC().Add(-tickStaleAfter - time.Minute)
	err := w.Work(context.Background(), &river.Job[RunSavedQueriesArgs]{JobRow: tickJob(stale)})
	require.NoError(t, err)
	require.Equal(t, 0, s.calls, "stale tick is skipped — the next minute's tick covers now")
}

func TestSavedQueryWorker_FreshTickRuns(t *testing.T) {
	s := &fakeSavedQueryScheduler{}
	w := &SavedQueryWorker{queries: s}

	err := w.Work(context.Background(), &river.Job[RunSavedQueriesArgs]{JobRow: tickJob(time.Now().UTC())})
	require.NoError(t, err)
	require.Equal(t, 1, s.calls)
}

// The cron is evaluated against the tick's scheduled minute, not the wall
// clock: a tick for 10:00 that starts at 10:01:30 still fires the 10:00
// schedule and does not fire the 10:01 one (that minute's own tick will).
func TestSavedQueryWorker_EvaluatesScheduledMinute(t *testing.T) {
	scheduled := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	s := &fakeSavedQueryScheduler{}
	w := &SavedQueryWorker{queries: s, now: func() time.Time { return scheduled.Add(90 * time.Second) }}

	job := &rivertype.JobRow{CreatedAt: scheduled, ScheduledAt: scheduled.Add(2 * time.Second), Attempt: 1}
	require.NoError(t, w.Work(context.Background(), &river.Job[RunSavedQueriesArgs]{JobRow: job}))
	require.Equal(t, 1, s.calls)
	require.True(t, s.due("0 10 * * *"), "the tick's own minute fires")
	require.False(t, s.due("1 10 * * *"), "the wall-clock minute is not fired by this tick")
}

// A retried tick has been rescheduled by its backoff; it still stands for the
// minute it was created for.
func TestTickMinute_RetryUsesCreatedAt(t *testing.T) {
	created := time.Date(2026, 1, 5, 10, 0, 1, 0, time.UTC)
	job := &rivertype.JobRow{CreatedAt: created, ScheduledAt: created.Add(3 * time.Minute), Attempt: 2}
	require.Equal(t, created.Truncate(time.Minute), tickMinute(job))

	job.Attempt = 1
	require.Equal(t, created.Add(3*time.Minute).Truncate(time.Minute), tickMinute(job))
}

// The per-minute tick runs on the dedicated graph lane, NOT the single-worker
// correlate queue whose standing backlog made "every minute" mean "whenever
// correlate drains", and dedupes so it can never stack up either way.
func TestRunSavedQueriesArgs_UniqueOpts(t *testing.T) {
	opts := RunSavedQueriesArgs{}.InsertOpts()
	require.Equal(t, queueGraph, opts.Queue)
	require.True(t, opts.UniqueOpts.ByArgs)
	require.Equal(t, uniqueStates, opts.UniqueOpts.ByState)
}
