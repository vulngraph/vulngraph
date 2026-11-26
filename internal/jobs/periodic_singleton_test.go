package jobs

import (
	"reflect"
	"testing"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
)

// periodicWithoutSingleton names periodic kinds that still lack the
// periodicSingletonOpts shape, each with the reason. Shrink it, never grow it.
var periodicWithoutSingleton = map[string]string{
	"run_saved_queries": "unique by args already; a per-minute tick is skipped once older than " +
		"tickStaleAfter, so River's default attempts only ever hold the slot for minutes",
}

// TestEveryPeriodicIsASingleton guards against duplicate periodic jobs: every
// leader election re-runs RunOnStart, so without uniqueness each election
// stacks another copy of the sweep (river_job showed refresh_osv 5x in ~2h).
// And because uniqueStates includes retryable, River's default 25 attempts
// would hold the slot through days of backoff — so attempts must be explicit
// and small.
func TestEveryPeriodicIsASingleton(t *testing.T) {
	periodics := buildPeriodicJobs(fullConfig())
	for _, kind := range allJobArgs() {
		args, opts, _ := periodicByKind(t, periodics, kind.Kind())
		if args == nil {
			continue
		}
		if _, ok := periodicWithoutSingleton[kind.Kind()]; ok {
			continue
		}
		t.Run(kind.Kind(), func(t *testing.T) {
			withOpts, ok := args.(river.JobArgsWithInsertOpts)
			require.True(t, ok, "periodic %q must declare InsertOpts", kind.Kind())
			eff := withOpts.InsertOpts()
			// River's merge: per-insert UniqueOpts replace the args' only when
			// non-empty; MaxAttempts likewise.
			if opts != nil && !reflect.ValueOf(opts.UniqueOpts).IsZero() {
				eff.UniqueOpts = opts.UniqueOpts
			}
			if opts != nil && opts.MaxAttempts != 0 {
				eff.MaxAttempts = opts.MaxAttempts
			}
			require.Contains(t, eff.UniqueOpts.ByState, rivertype.JobStateRunning,
				"periodic %q must be unique while queued/running/retryable", kind.Kind())
			require.Positive(t, eff.MaxAttempts, "periodic %q must set MaxAttempts, not inherit River's 25", kind.Kind())
			require.LessOrEqual(t, eff.MaxAttempts, 3, "periodic %q holds its unique slot while retryable", kind.Kind())
		})
	}
}

func TestPeriodicSingletonInsertOpts(t *testing.T) {
	for _, tc := range []struct {
		args interface {
			river.JobArgs
			river.JobArgsWithInsertOpts
		}
		queue       string
		maxAttempts int
	}{
		{RefreshOSVArgs{}, queueEnrich, 3},
		{RefreshMalFeedArgs{}, queueEnrich, 3},
		{RefreshDistroAdvisoriesArgs{}, queueEnrich, 3},
		{RefreshSCCArgs{}, queueEnrich, 3},
		{RefreshEPSSArgs{}, queueFeeds, 3},
		{AdjudicateArgs{}, queueAdjudicate, 2},
		{DriftSweepArgs{}, queueDrift, 2},
		{RefreshKEVArgs{}, queueFeeds, 2},
		{EnrichSweepArgs{}, queueEnrich, enrichSweepMaxAttempts},
		{EnqueueSyncsArgs{}, queueSync, 3},
		{DiscoverAWSOrgsArgs{}, queueSync, 2},
		{DanglingSweepArgs{}, queueDangling, 2},
		{DomainMonitorArgs{}, queueFeeds, 2},
		{RefreshImageVulnArgs{}, queueContentScan, 2},
		{SuppressionExpiryArgs{}, queueFeeds, 2},
	} {
		opts := tc.args.InsertOpts()
		require.Equal(t, tc.queue, opts.Queue, tc.args.Kind())
		require.Equal(t, tc.maxAttempts, opts.MaxAttempts, tc.args.Kind())
		require.Equal(t, uniqueStates, opts.UniqueOpts.ByState, tc.args.Kind())
	}
}

// TestImageVulnHopIsNotItsOwnDuplicate pins ByArgs on the image-vuln sweep: a
// hop chains its continuation while still running, so kind-only uniqueness
// would drop the chain.
func TestImageVulnHopIsNotItsOwnDuplicate(t *testing.T) {
	require.True(t, RefreshImageVulnArgs{}.InsertOpts().UniqueOpts.ByArgs)
}
