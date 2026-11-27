package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type backfillOnlyLister struct {
	filters []finding.Filter
	pending bool
}

func (l *backfillOnlyLister) List(_ context.Context, f finding.Filter) ([]finding.Finding, error) {
	l.filters = append(l.filters, f)
	if l.pending && f.Severity == finding.SeverityCritical {
		return []finding.Finding{{ID: "pending", Severity: finding.SeverityCritical}}, nil
	}
	return nil, nil
}

type backfillPruner struct{ calls int }

func (p *backfillPruner) PruneAlertStates(context.Context, time.Time) (int64, error) {
	p.calls++
	return 0, nil
}

func TestDemandBackfillSnoozesUntilMeasuredAndSkipsDrift(t *testing.T) {
	list := &backfillOnlyLister{pending: true}
	prune := &backfillPruner{}
	worker := &EnrichSweepWorker{findings: list, alerts: prune}
	job := &river.Job[EnrichSweepArgs]{Args: EnrichSweepArgs{BackfillOnly: true}}
	err := worker.Work(t.Context(), job)
	var snooze *river.JobSnoozeError
	require.ErrorAs(t, err, &snooze)
	require.Equal(t, enrichBackfillDelay, snooze.Duration)
	require.Zero(t, prune.calls)
	require.Len(t, list.filters, len(backfillSeverities))
	for i, f := range list.filters {
		require.True(t, f.Unenriched)
		require.False(t, f.StaleFirst)
		require.Equal(t, backfillSeverities[i], f.Severity)
	}
	list.pending = false
	require.NoError(t, worker.Work(t.Context(), job), "a measured backlog completes its durable wake-up")
}

func TestDemandBackfillHasSeparateDurableUniqueness(t *testing.T) {
	periodic := EnrichSweepArgs{}.InsertOpts()
	demand := (EnrichSweepArgs{BackfillOnly: true}).InsertOpts()
	require.False(t, periodic.UniqueOpts.ByArgs, "retain the existing periodic uniqueness key")
	require.True(t, demand.UniqueOpts.ByArgs, "a future periodic must not suppress an immediate backfill")
	require.Equal(t, uniqueStates, demand.UniqueOpts.ByState, "snoozed and running work remains one singleton")
	require.Equal(t, queueEnrich, demand.Queue)
	require.Equal(t, enrichSweepMaxAttempts, demand.MaxAttempts)
}
