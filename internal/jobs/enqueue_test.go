package jobs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// TestBackoffInterval_Schedule pins the exact backoff shape: 3 consecutive
// clean syncs required before backing off at all (streak 0-2 stay at base),
// then doubling, capped at backoffCeiling. Table-tested at every bucket
// boundary rather than trusted by inspection — this schedule silently
// under- or over-throttling the sync sweep is exactly the kind of bug that
// wouldn't show up until a connector went stale or an account kept getting
// hammered.
func TestBackoffInterval_Schedule(t *testing.T) {
	base := 2 * time.Hour
	tests := []struct {
		streak int
		want   time.Duration
	}{
		{0, base},
		{1, base},
		{2, base},
		{3, 2 * base},
		{5, 2 * base},
		{6, 4 * base},
		{11, 4 * base},
		{12, 6 * base}, // 6*2h = 12h, exactly the ceiling
		{50, backoffCeiling},
	}
	for _, tc := range tests {
		got := backoffInterval(tc.streak, base)
		require.Equal(t, tc.want, got, "streak %d", tc.streak)
	}
}

// TestBackoffInterval_NeverExceedsCeilingRegardlessOfBase is the correctness
// backstop the ceiling exists for: whatever SYNC_INTERVAL an operator sets,
// no streak should ever be able to push a connector's actual wait past
// backoffCeiling.
func TestBackoffInterval_NeverExceedsCeilingRegardlessOfBase(t *testing.T) {
	for _, base := range []time.Duration{2 * time.Hour, 6 * time.Hour, 24 * time.Hour} {
		for _, streak := range []int{0, 3, 6, 12, 100} {
			got := backoffInterval(streak, base)
			require.LessOrEqual(t, got, backoffCeiling, "base=%s streak=%d", base, streak)
		}
	}
}

// TestBackoffCeilingLeavesMarginUnderStaleAfter guards the reasoning behind
// choosing 12h over the more obvious 24h: a maximally-backed-off HEALTHY
// connector must sit comfortably under the Stale() alert threshold, not at
// its edge where ordinary scheduling jitter turns success into a false
// alert. If either constant is ever edited independently, this fails instead
// of silently reintroducing that risk.
func TestBackoffCeilingLeavesMarginUnderStaleAfter(t *testing.T) {
	require.Less(t, backoffCeiling, connector.DefaultStaleAfter)
	require.GreaterOrEqual(t, connector.DefaultStaleAfter, 2*backoffCeiling,
		"the ceiling should leave a comfortable margin, not just any margin, under the staleness threshold")
}

// TestIsDueForSync_NeverSyncedIsAlwaysDue: a brand-new connector must get its
// first sync immediately, regardless of what SyncStreak happens to hold
// (always 0 by the migration's column default, but this must not depend on
// that — LastSyncedAt==nil is the actual signal).
func TestIsDueForSync_NeverSyncedIsAlwaysDue(t *testing.T) {
	c := connector.Connector{SyncStreak: 50, LastSyncedAt: nil}
	require.True(t, isDueForSync(c, 2*time.Hour, time.Now()))
}

// TestIsDueForSync_WithinBackoffWindowIsNotDue / JustPastWindowIsDue pin the
// boundary condition exactly: due at >=, not due at <.
func TestIsDueForSync_WithinBackoffWindowIsNotDue(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	last := now.Add(-90 * time.Minute) // streak 0 → base 2h window; 90m < 2h
	c := connector.Connector{SyncStreak: 0, LastSyncedAt: &last}
	require.False(t, isDueForSync(c, 2*time.Hour, now))
}

func TestIsDueForSync_JustPastWindowIsDue(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	last := now.Add(-2 * time.Hour) // exactly at the streak-0 base window
	c := connector.Connector{SyncStreak: 0, LastSyncedAt: &last}
	require.True(t, isDueForSync(c, 2*time.Hour, now))
}

// TestIsDueForSync_BackedOffStreakExtendsTheWindow confirms the streak
// actually changes the outcome, not just backoffInterval in isolation: the
// SAME elapsed time (3h) is not due for a streak-6 connector (needs 8h) but
// IS due for a streak-0 connector (needs only 2h).
func TestIsDueForSync_BackedOffStreakExtendsTheWindow(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	last := now.Add(-3 * time.Hour)
	base := 2 * time.Hour

	quiet := connector.Connector{SyncStreak: 6, LastSyncedAt: &last}
	require.False(t, isDueForSync(quiet, base, now), "streak 6 needs 8h, only 3h elapsed")

	fresh := connector.Connector{SyncStreak: 0, LastSyncedAt: &last}
	require.True(t, isDueForSync(fresh, base, now), "streak 0 needs only 2h, 3h elapsed")
}

// TestEnqueueCheckInterval_MuchShorterThanBackoffGranularity is the guard
// rail for the fix to a real scheduling bug: LastSyncedAt
// is stamped when a sync COMPLETES, not when the periodic tick that enqueued
// it fired. If the tick checking isDueForSync ran at the SAME period as the
// backoff's own base interval, every connector's observed elapsed time at
// the next tick would undershoot the target by however long that sync (plus
// its queue wait) took — silently doubling every connector's effective
// interval starting from streak 0 (intended 2h, actual 4h; verified by
// simulation below). enqueueCheckInterval must stay a small fraction of
// defaultSyncInterval for that timing slop to stay negligible instead of a
// whole extra multiple of the target interval.
func TestEnqueueCheckInterval_MuchShorterThanBackoffGranularity(t *testing.T) {
	require.LessOrEqual(t, enqueueCheckInterval, defaultSyncInterval/4,
		"the check tick must be a small fraction of the backoff base, or the timing-slop bug this guards against comes back")
}

// ceilToTick rounds d up to the next multiple of tick — the closed-form
// worst-case slop TestIsDueForSync_TickSimulationMatchesIntendedInterval
// asserts against: because LastSyncedAt is stamped at completion, not at the
// tick that triggered the sync, a sync taking syncDuration always adds
// exactly ceilToTick(syncDuration, enqueueCheckInterval) on top of the
// intended interval — never more, never less. A flat one-tick bound is wrong:
// it only holds for syncDuration <= enqueueCheckInterval.
func ceilToTick(d, tick time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	n := (d + tick - 1) / tick
	return n * tick
}

// TestIsDueForSync_TickSimulationMatchesIntendedInterval simulates the real
// timing model directly (not backoffInterval in isolation): a
// periodic tick fires every enqueueCheckInterval; each time isDueForSync
// says yes, the connector's LastSyncedAt is stamped syncDuration AFTER that
// tick (modeling real Collect+Ingest latency, not an instantaneous stamp).
// Table-driven over several plausible sync durations — including one longer
// than enqueueCheckInterval itself (queue wait on a congested sync queue) —
// asserting the ACHIEVED gap between consecutive real syncs matches the
// exact closed-form bound (intended + ceilToTick(syncDuration)), not a
// looser approximation. This is the exact invariant the shipped bug
// violated (achieved gap was double the intended interval) and the fixed
// constant (enqueueCheckInterval, far below base) restores.
func TestIsDueForSync_TickSimulationMatchesIntendedInterval(t *testing.T) {
	const base = 2 * time.Hour
	for _, tc := range []struct {
		name         string
		syncDuration time.Duration
		streak       int
	}{
		{"fast sync, streak 0 (day-one default)", 8 * time.Minute, 0},
		{"slow sync, streak 0", 25 * time.Minute, 0}, // longer than enqueueCheckInterval
		{"congested queue wait, streak 0", 45 * time.Minute, 0},
		{"fast sync, backed-off streak", 8 * time.Minute, 3}, // intended 4h
	} {
		t.Run(tc.name, func(t *testing.T) {
			intended := backoffInterval(tc.streak, base)
			wantGap := intended + ceilToTick(tc.syncDuration, enqueueCheckInterval)

			now := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
			var lastSynced *time.Time
			var gaps []time.Duration
			var prevSync time.Time

			for i := 0; i < 40; i++ {
				now = now.Add(enqueueCheckInterval)
				c := connector.Connector{SyncStreak: int32(tc.streak), LastSyncedAt: lastSynced}
				if isDueForSync(c, base, now) {
					finishedAt := now.Add(tc.syncDuration)
					if !prevSync.IsZero() {
						gaps = append(gaps, finishedAt.Sub(prevSync))
					}
					prevSync = finishedAt
					lastSynced = &finishedAt
				}
			}

			require.NotEmpty(t, gaps, "the simulation must have observed at least 2 syncs")
			for _, gap := range gaps {
				require.Equal(t, wantGap, gap,
					"achieved gap must match the exact closed form, not just some loose bound")
				require.Less(t, gap, 2*intended,
					"regression guard for the shipped bug: the achieved gap must never double the intended interval")
			}
		})
	}
}
