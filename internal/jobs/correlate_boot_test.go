package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
)

type recordingInserter struct {
	args []river.JobArgs
	opts []*river.InsertOpts
}

func (r *recordingInserter) Insert(_ context.Context, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	r.args = append(r.args, args)
	r.opts = append(r.opts, opts)
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}}, nil
}

// The boot sweep used to be a raw INSERT with no unique_key and max_attempts 3
// (bypassing CorrelateArgs.InsertOpts' 2), so every worker boot added a full
// sweep on top of the periodic's RunOnStart one. It must go through River's
// uniqueness, scoped by args so pending partial sweeps don't suppress it.
func TestEnqueueBootCorrelate_IsAUniqueDelayedFullSweep(t *testing.T) {
	ins := &recordingInserter{}
	before := time.Now()
	require.NoError(t, EnqueueBootCorrelate(context.Background(), ins))

	require.Len(t, ins.args, 1)
	require.Equal(t, CorrelateArgs{}, ins.args[0], "boot sweep is the full sweep (no ChangedIDs)")
	opts := ins.opts[0]
	require.True(t, opts.UniqueOpts.ByArgs, "partials share the kind; uniqueness must be by args")
	require.Equal(t, uniqueStates, opts.UniqueOpts.ByState)
	require.WithinDuration(t, before.Add(correlateBootDelay), opts.ScheduledAt, 5*time.Second)
	require.Empty(t, opts.Queue, "queue falls through to CorrelateArgs.InsertOpts")
	require.Zero(t, opts.MaxAttempts, "attempts fall through to CorrelateArgs.InsertOpts")
}

// The periodic must not add a second boot sweep (RunOnStart) and must share the
// boot insert's uniqueness so the two dedupe against each other.
func TestBuildPeriodicJobs_CorrelateSharesBootUniqueness(t *testing.T) {
	args, opts, runOnStart := periodicByKind(t, buildPeriodicJobs(PeriodicConfig{}), CorrelateArgs{}.Kind())
	require.Equal(t, CorrelateArgs{}, args)
	require.False(t, runOnStart, "the boot sweep is EnqueueBootCorrelate; RunOnStart would make it two")
	require.Equal(t, fullCorrelateOpts().UniqueOpts, opts.UniqueOpts)
}
