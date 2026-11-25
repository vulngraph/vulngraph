package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/scan"
)

func TestScanPeriodicJobs_Gating(t *testing.T) {
	require.Empty(t, scanPeriodicJobs(0), "no interval → active scanning stays off")
	require.Empty(t, scanPeriodicJobs(-time.Minute), "negative interval → off")
	require.Len(t, scanPeriodicJobs(6*time.Hour), 1, "a positive interval schedules one periodic scan")
}

type fakeScanner struct {
	run   scan.Run
	found []finding.Finding
	err   error
	calls int
}

func (f *fakeScanner) RunScan(context.Context) (scan.Run, []finding.Finding, error) {
	f.calls++
	return f.run, f.found, f.err
}

// Happy path: runs the scan and enqueues enrich for the findings (client-safe,
// so no live client is needed in the test).
func TestScanWorker_RunsAndEnqueues(t *testing.T) {
	s := &fakeScanner{
		run:   scan.Run{ID: "run-1", TargetCount: 2, FindingCount: 1},
		found: []finding.Finding{{ID: "f1"}},
	}
	w := &ScanWorker{scans: s}

	err := w.Work(context.Background(), &river.Job[ScanArgs]{})
	require.NoError(t, err)
	require.Equal(t, 1, s.calls)
}

func TestScanWorker_ScanError(t *testing.T) {
	w := &ScanWorker{scans: &fakeScanner{err: errors.New("nuclei exploded")}}
	err := w.Work(context.Background(), &river.Job[ScanArgs]{})
	require.ErrorContains(t, err, "Work")
}
