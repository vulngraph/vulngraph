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

// TestOSVScanStaleness_ComputesOldestAndCount exercises the real query against
// Postgres: inserts rows at known scanned_at values and asserts the helper
// returns the correct MIN and COUNT — the Postgres half of the OSV
// scan-staleness gauge (internal/obs/metrics.go).
func TestOSVScanStaleness_ComputesOldestAndCount(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// Namespace this run's rows so concurrent/repeat runs don't collide.
	eco := "it-osv-staleness-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM osv_scanned_packages WHERE ecosystem = $1", eco)
	})

	q := sqlcgen.New(pool)
	older := time.Now().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	newer := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	require.NoError(t, q.MarkPackagesScanned(ctx, sqlcgen.MarkPackagesScannedParams{
		Ecosystems: []string{eco, eco},
		Names:      []string{"pkg-a", "pkg-b"},
		Versions:   []string{"1.0.0", "2.0.0"},
	}))
	// Backdate pkg-a's row directly — MarkPackagesScanned always stamps now().
	_, err = pool.Exec(ctx, "UPDATE osv_scanned_packages SET scanned_at = $1 WHERE ecosystem = $2 AND name = 'pkg-a'", older, eco)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, "UPDATE osv_scanned_packages SET scanned_at = $1 WHERE ecosystem = $2 AND name = 'pkg-b'", newer, eco)
	require.NoError(t, err)

	// OSVScanStaleness reads across the WHOLE table (no ecosystem filter — it
	// answers "how stale is our worst-covered package" fleet-wide), so assert
	// on bounds relative to what THIS run inserted rather than an exact count,
	// since other tests/rows may coexist in the same database.
	scanned, oldest, err := OSVScanStaleness(ctx, pool)
	require.NoError(t, err)
	require.GreaterOrEqual(t, scanned, int64(2))
	require.False(t, oldest.After(older), "the fleet-wide MIN(scanned_at) can never be newer than this run's own 10-day-old row")
	require.True(t, oldest.Before(newer), "the fleet-wide oldest scan must be at or before this run's oldest inserted row")
}
