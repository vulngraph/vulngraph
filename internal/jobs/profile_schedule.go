package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/pkg/cronexpr"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ScheduledProfiles is the slice of the scan profile service the schedule worker
// needs: list profiles and trigger one. *scan.ProfileService satisfies it.
// This worker is what fires ScanProfile.Schedule.
type ScheduledProfiles interface {
	ListProfiles(ctx context.Context) ([]scan.ScanProfile, error)
	TriggerProfileScan(ctx context.Context, profileID string) (string, error)
}

// RunScheduledProfilesArgs is the per-minute tick that fires scan profiles whose
// cron schedule matches the current minute.
type RunScheduledProfilesArgs struct{}

func (RunScheduledProfilesArgs) Kind() string { return "run_scheduled_profiles" }

func (RunScheduledProfilesArgs) InsertOpts() river.InsertOpts {
	// Runs on the graph queue, not the single-worker correlate queue: a
	// per-minute schedule behind a correlate backlog is not a per-minute
	// schedule (see queueGraph). Dedupe like LadybugRebuildArgs so ticks
	// never stack up regardless (see tickStaleAfter).
	return river.InsertOpts{
		Queue:      queueGraph,
		UniqueOpts: river.UniqueOpts{ByArgs: true, ByState: uniqueStates},
	}
}

// ProfileScheduleWorker triggers scheduled scan profiles on their cron cadence.
type ProfileScheduleWorker struct {
	river.WorkerDefaults[RunScheduledProfilesArgs]
	profiles ScheduledProfiles
	now      func() time.Time
}

// Timeout is explicit: the tick only lists profiles and enqueues scans, so a
// run that outlives tickStaleAfter is stuck, not slow.
func (w *ProfileScheduleWorker) Timeout(_ *river.Job[RunScheduledProfilesArgs]) time.Duration {
	return tickStaleAfter
}

func (w *ProfileScheduleWorker) Work(ctx context.Context, job *river.Job[RunScheduledProfilesArgs]) error {
	nowFn := w.now
	if nowFn == nil {
		nowFn = time.Now
	}
	t := nowFn().UTC()
	if t.Sub(job.CreatedAt) > tickStaleAfter {
		log.FromContext(ctx).Info().Time("created_at", job.CreatedAt).
			Msg("profile-schedule tick stale — skipped (its minute passed)")
		return nil
	}
	profiles, err := w.profiles.ListProfiles(ctx)
	if err != nil {
		return fmt.Errorf("Work: list profiles: %w", err)
	}
	logger := log.FromContext(ctx)
	ran := 0
	for _, p := range profiles {
		if !p.Enabled || p.Schedule == "" {
			continue
		}
		if err := scan.ScheduleError(p.Schedule); err != nil {
			logger.Warn().Err(err).Str("profile_id", p.ID).Str("name", p.Name).
				Msg("scheduled scan profile never runs: invalid schedule")
			continue
		}
		if !cronexpr.Due(p.Schedule, t) {
			continue
		}
		if _, err := w.profiles.TriggerProfileScan(ctx, p.ID); err != nil {
			logger.Warn().Err(err).Str("profile_id", p.ID).Msg("scheduled profile trigger failed")
			continue
		}
		ran++
	}
	if ran > 0 {
		logger.Info().Int("profiles", ran).Msg("profile schedule: triggered due scans")
	}
	return nil
}
