//go:build integration

package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// TestDeleteOrphanedScannedPackages_PrunesOnlyStaleAndAbsent exercises the
// real query: a row must be deleted only when it is BOTH past the rescan
// cutoff AND absent from the live set — either condition alone must spare it.
// This keeps GraphOSVScanCoverageStale from firing on packages an image
// rebuild removed from inventory, whose osv_scanned_packages row would
// otherwise never be re-queried and never age out on its own.
func TestDeleteOrphanedScannedPackages_PrunesOnlyStaleAndAbsent(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	eco := "it-osv-prune-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM osv_scanned_packages WHERE ecosystem = $1", eco)
	})

	q := sqlcgen.New(pool)
	require.NoError(t, q.MarkPackagesScanned(ctx, sqlcgen.MarkPackagesScannedParams{
		Ecosystems: []string{eco, eco, eco},
		Names:      []string{"orphan-old", "orphan-recent", "live-old"},
		Versions:   []string{"1.0.0", "1.0.0", "1.0.0"},
	}))

	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	old := time.Now().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	recent := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	for name, ts := range map[string]time.Time{
		"orphan-old":    old,    // stale AND absent from live set -> pruned
		"orphan-recent": recent, // absent from live set but still within cutoff -> spared
		"live-old":      old,    // stale but present in live set -> spared
	} {
		_, err = pool.Exec(ctx, "UPDATE osv_scanned_packages SET scanned_at = $1 WHERE ecosystem = $2 AND name = $3", ts, eco, name)
		require.NoError(t, err)
	}

	pruned, err := q.DeleteOrphanedScannedPackages(ctx, sqlcgen.DeleteOrphanedScannedPackagesParams{
		Cutoff:     cutoff,
		Ecosystems: []string{eco},
		Names:      []string{"live-old"},
		Versions:   []string{"1.0.0"},
	})
	require.NoError(t, err)
	require.Equal(t, int64(1), pruned, "only the stale-and-absent row is deleted")

	rows, err := q.GetScannedPackagesSince(ctx, time.Time{})
	require.NoError(t, err)
	remaining := map[string]bool{}
	for _, r := range rows {
		if r.Ecosystem == eco {
			remaining[r.Name] = true
		}
	}
	require.False(t, remaining["orphan-old"], "stale and absent from live set must be pruned")
	require.True(t, remaining["orphan-recent"], "absent from live set but within the rescan window must be spared")
	require.True(t, remaining["live-old"], "stale but still present in the live set must be spared")
}
