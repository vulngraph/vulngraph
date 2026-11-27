//go:build integration

package jobs

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// isolatedRiverClient migrates River into a throwaway schema and returns an
// insert-only client over it, so the test never touches the dev stack's
// river_job (a running local worker would pick the jobs up).
func isolatedRiverClient(t *testing.T) (*river.Client[pgx.Tx], func(kind string) map[string]int) {
	t.Helper()
	return isolatedRiverClientWithWorkers(t, nil)
}

func isolatedRiverClientWithWorkers(t *testing.T, workers *river.Workers) (*river.Client[pgx.Tx], func(string) map[string]int) {
	t.Helper()
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	schema := "it_river_" + time.Now().Format("150405000000")
	_, err = pool.Exec(ctx, "CREATE SCHEMA "+schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })

	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: schema})
	require.NoError(t, err)
	_, err = migrator.Migrate(ctx, rivermigrate.DirectionUp, nil)
	require.NoError(t, err)

	config := &river.Config{Schema: schema, Workers: workers}
	if workers != nil {
		config.Queues = map[string]river.QueueConfig{queueCorrelate: {MaxWorkers: 1}}
	}
	client, err := river.NewClient(riverpgxv5.New(pool), config)
	require.NoError(t, err)

	countByArgs := func(kind string) map[string]int {
		rows, err := pool.Query(ctx, "SELECT args::text, count(*) FROM "+schema+".river_job WHERE kind = $1 GROUP BY 1", kind)
		require.NoError(t, err)
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var args string
			var n int
			require.NoError(t, rows.Scan(&args, &n))
			out[args] = n
		}
		require.NoError(t, rows.Err())
		return out
	}
	return client, countByArgs
}

// Two worker replicas booting, plus a periodic tick, must yield ONE full
// sweep — while a pending partial sweep neither blocks it nor is blocked.
func TestEnqueueBootCorrelate_OneFullSweepPerBoot(t *testing.T) {
	ctx := context.Background()
	client, countByArgs := isolatedRiverClient(t)

	_, err := client.Insert(ctx, CorrelateArgs{ChangedIDs: []string{"a1"}}, nil)
	require.NoError(t, err)
	require.NoError(t, EnqueueBootCorrelate(ctx, client))
	require.NoError(t, EnqueueBootCorrelate(ctx, client))
	_, opts, _ := periodicByKind(t, buildPeriodicJobs(PeriodicConfig{}), CorrelateArgs{}.Kind())
	res, err := client.Insert(ctx, CorrelateArgs{}, opts)
	require.NoError(t, err)
	require.True(t, res.UniqueSkippedAsDuplicate, "the periodic tick must dedupe against the boot sweep")

	require.Equal(t, map[string]int{`{}`: 1, `{"changed_ids": ["a1"]}`: 1}, countByArgs(CorrelateArgs{}.Kind()))
}

// A leader election re-running RunOnStart must not stack a second feed refresh.
func TestPeriodicSingleton_DedupesAcrossElections(t *testing.T) {
	ctx := context.Background()
	client, countByArgs := isolatedRiverClient(t)

	for range 3 {
		_, err := client.Insert(ctx, RefreshOSVArgs{}, scheduledOn(RefreshOSVArgs{}, 16*time.Minute))
		require.NoError(t, err)
	}
	require.Equal(t, map[string]int{`{}`: 1}, countByArgs(RefreshOSVArgs{}.Kind()))
}

// The first sweep captures revision zero, then pauses. A committed revision
// one must be read by a queued follow-up even while the first sweep is running.
func TestCorrelateFollowup_RunningSnapshotCannotAbsorbLateChange(t *testing.T) {
	barrier := &snapshotBarrierCorrelator{captured: make(chan int32, 4), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(barrier.release) })
	workers := river.NewWorkers()
	river.AddWorker(workers, &CorrelateWorker{correlate: barrier})
	client, count := isolatedRiverClientWithWorkers(t, workers)
	require.NoError(t, client.Start(t.Context()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, client.StopAndCancel(ctx))
	}()
	_, err := client.Insert(t.Context(), CorrelateArgs{}, fullCorrelateOpts())
	require.NoError(t, err)
	select {
	case revision := <-barrier.captured:
		require.Zero(t, revision)
	case <-time.After(10 * time.Second):
		t.Fatal("first source not captured")
	}
	barrier.revision.Store(1)
	require.NoError(t, enqueueCorrelateFollowup(t.Context(), client, client))
	require.NoError(t, enqueueCorrelateFollowup(t.Context(), client, client))
	require.Equal(t, 2, count(CorrelateArgs{}.Kind())["{}"], "one running plus one pending follow-up")
	release.Do(func() { close(barrier.release) })
	select {
	case revision := <-barrier.captured:
		require.Equal(t, int32(1), revision)
	case <-time.After(10 * time.Second):
		t.Fatal("late revision never captured")
	}
}

type snapshotBarrierCorrelator struct {
	revision atomic.Int32
	calls    atomic.Int32
	captured chan int32
	release  chan struct{}
}

func (c *snapshotBarrierCorrelator) Correlate(ctx context.Context) (int, error) {
	revision := c.revision.Load()
	call := c.calls.Add(1)
	c.captured <- revision
	if call == 1 {
		select {
		case <-c.release:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return 0, nil
}
func (*snapshotBarrierCorrelator) PartialCorrelate(context.Context, []string) (int, error) {
	return 0, nil
}
