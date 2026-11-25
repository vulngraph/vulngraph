package jobs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"
)

// A failing connector must not retry River's default 25 times and hog the
// shared sync workers — the cap keeps it to a couple of tries per sweep.
func TestSyncConnectorInsertOpts_CapsRetries(t *testing.T) {
	require.Equal(t, 3, SyncConnectorArgs{}.InsertOpts().MaxAttempts)
}

// River requires UniqueOpts.ByState to contain all of its required job states.
// pending is one of them: dropping it makes every unique sync_connector insert
// fail at runtime ("must contain all required states, missing: pending"), which
// silently stalls the whole sync sweep and leaves every connector pending.
func TestUniqueStates_IncludePending(t *testing.T) {
	require.Contains(t, uniqueStates, rivertype.JobStatePending,
		"uniqueStates must include pending or River rejects every unique insert")
}

// River's reindexer must never run. `REINDEX CONCURRENTLY` on river_job leaves an
// INVALID `_ccnew` index behind whenever it is interrupted — and Postgres keeps
// MAINTAINING an invalid index on every write while never reading it. On a
// high-throughput table that leaves a meaningful amount of dead index bloat behind.
// See reindexerSchedule for the full reasoning.
func TestReindexerScheduleNeverRuns(t *testing.T) {
	require.NotNil(t, reindexerSchedule, "a nil ReindexerSchedule means River's DEFAULT — daily at midnight UTC")

	now := time.Now()
	next := reindexerSchedule.Next(now)
	require.True(t, next.After(now.AddDate(100, 0, 0)),
		"reindexer must be scheduled beyond any pod's lifetime, got %s", next)
}

// Both electable clients must disable it. River runs maintenance services on
// whichever client wins the leader election, so setting it on the worker alone
// would leave the reindexer live every time the scanner won.
func TestEveryQueueConsumingClientDisablesTheReindexer(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(moduleRoot(t), "internal", "jobs", "client.go"))
	require.NoError(t, err)

	chunks := strings.Split(string(src), "river.NewClient(")
	require.Greater(t, len(chunks), 1, "no river.NewClient call found")

	electable := 0
	for _, chunk := range chunks[1:] {
		// The config literal ends at the first "})" after the call.
		end := strings.Index(chunk, "})")
		require.NotEqual(t, -1, end)
		cfg := chunk[:end]
		if !strings.Contains(cfg, "Queues:") {
			continue // insert-only client: never elected, runs no maintenance
		}
		electable++
		require.Contains(t, cfg, "ReindexerSchedule: reindexerSchedule",
			"a queue-consuming client is electable and must disable River's reindexer")
	}
	require.Equal(t, 2, electable, "expected the worker and scanner clients")
}

// Both electable clients must configure SoftStopTimeout. Without it,
// river.Config's default applies: the work context inherits the start
// context directly, so cancelling it on SIGTERM (every deploy, not just a
// crash) hard-cancels every in-flight job immediately, no matter how close to
// finishing, which is one way GraphCorrelateFullSweepStale fires. Same
// technique as
// TestEveryQueueConsumingClientDisablesTheReindexer above, for the same
// reason: a plain string match on the source is the deliberately cheap
// exception here, not a regex on formatted output.
func TestEveryElectableClientConfiguresSoftStopTimeout(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(moduleRoot(t), "internal", "jobs", "client.go"))
	require.NoError(t, err)

	chunks := strings.Split(string(src), "river.NewClient(")
	require.Greater(t, len(chunks), 1, "no river.NewClient call found")

	electable := 0
	for _, chunk := range chunks[1:] {
		end := strings.Index(chunk, "})")
		require.NotEqual(t, -1, end)
		cfg := chunk[:end]
		if !strings.Contains(cfg, "Queues:") {
			continue // insert-only client: never elected, runs no jobs at all
		}
		electable++
		require.Contains(t, cfg, "SoftStopTimeout:",
			"a queue-consuming client runs real jobs and must configure SoftStopTimeout, "+
				"or every in-flight job is hard-cancelled on every deploy's SIGTERM")
	}
	require.Equal(t, 2, electable, "expected the worker and scanner clients")
}
