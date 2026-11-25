package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/scan"
)

type fakeScheduledProfiles struct {
	profiles  []scan.ScanProfile
	listCalls int
	triggered []string
}

func (f *fakeScheduledProfiles) ListProfiles(context.Context) ([]scan.ScanProfile, error) {
	f.listCalls++
	return f.profiles, nil
}

func (f *fakeScheduledProfiles) TriggerProfileScan(_ context.Context, id string) (string, error) {
	f.triggered = append(f.triggered, id)
	return "run-1", nil
}

// A stale tick evaluates wall-clock "now" — running a pile of stacked ticks
// would trigger the same due profiles once per stacked job. Skip stale ticks.
func TestProfileScheduleWorker_StaleTickSkipped(t *testing.T) {
	p := &fakeScheduledProfiles{}
	w := &ProfileScheduleWorker{profiles: p}

	stale := time.Now().UTC().Add(-tickStaleAfter - time.Minute)
	err := w.Work(context.Background(), &river.Job[RunScheduledProfilesArgs]{JobRow: tickJob(stale)})
	require.NoError(t, err)
	require.Equal(t, 0, p.listCalls, "stale tick skipped before any work")
}

func TestProfileScheduleWorker_FreshTickTriggersDue(t *testing.T) {
	fixed := time.Date(2026, 6, 14, 12, 30, 0, 0, time.UTC)
	p := &fakeScheduledProfiles{profiles: []scan.ScanProfile{
		{ID: "due", Enabled: true, Schedule: "30 12 * * *"},
		{ID: "not-due", Enabled: true, Schedule: "0 3 * * *"},
		{ID: "disabled", Enabled: false, Schedule: "30 12 * * *"},
	}}
	w := &ProfileScheduleWorker{profiles: p, now: func() time.Time { return fixed }}

	err := w.Work(context.Background(), &river.Job[RunScheduledProfilesArgs]{JobRow: tickJob(fixed)})
	require.NoError(t, err)
	require.Equal(t, []string{"due"}, p.triggered)
}

// An invalid stored schedule never fires (the API flags it via
// schedule_error); it must not be half-parsed into firing on its valid parts.
func TestProfileScheduleWorker_InvalidScheduleNeverFires(t *testing.T) {
	fixed := time.Date(2026, 6, 14, 12, 30, 0, 0, time.UTC)
	p := &fakeScheduledProfiles{profiles: []scan.ScanProfile{
		{ID: "bad-list", Enabled: true, Schedule: "30 12,x * * *"},
		{ID: "four-fields", Enabled: true, Schedule: "30 12 * *"},
		{ID: "due", Enabled: true, Schedule: "30 12 * * *"},
	}}
	w := &ProfileScheduleWorker{profiles: p, now: func() time.Time { return fixed }}

	err := w.Work(context.Background(), &river.Job[RunScheduledProfilesArgs]{JobRow: tickJob(fixed)})
	require.NoError(t, err)
	require.Equal(t, []string{"due"}, p.triggered)
}
