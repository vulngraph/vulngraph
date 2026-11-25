//go:build integration

package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestPruneOrphanedImageScans_PrunesOnlyStaleAndAbsent exercises the real
// query: a row must be deleted only when it is BOTH past the rescan cutoff
// AND absent from the live digest set — either condition alone must spare it.
// A digest that has NEVER scanned cleanly (scanned_at IS NULL, only failed
// attempts) must survive regardless of cutoff or liveness: that is
// graph_image_scan_never_scanned's own already-accepted floor, not this
// query's problem.
//
// This keeps GraphImageScanCoverageStale from firing on a digest an image
// rebuild/decommission removed from inventory, whose image_scan_state row
// would otherwise never be re-attempted (selectTargets only ever looks at the
// current container_image listing) and never age out on its own: a single
// such digest sits past the rescan window while the rest of the corpus is
// healthy. Mirrors OSV's DeleteOrphanedScannedPackages for the identical shape.
func TestPruneOrphanedImageScans_PrunesOnlyStaleAndAbsent(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	prefix := "it-imgprune-" + time.Now().Format("150405.000000") + "-"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM image_scan_state WHERE digest LIKE $1", prefix+"%")
	})

	cursor := newImageScanCursor(pool)
	require.NoError(t, cursor.MarkScanned(ctx, []string{
		prefix + "orphan-old", prefix + "orphan-recent", prefix + "live-old",
	}))
	require.NoError(t, cursor.MarkFailed(ctx, []imageFailure{
		{digest: prefix + "never-scanned", reason: "pull denied"},
	}))

	old := time.Now().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	recent := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	for digest, ts := range map[string]time.Time{
		prefix + "orphan-old":    old,    // stale AND absent from live set -> pruned
		prefix + "orphan-recent": recent, // absent from live set but within cutoff -> spared
		prefix + "live-old":      old,    // stale but present in live set -> spared
	} {
		_, err := pool.Exec(ctx, "UPDATE image_scan_state SET scanned_at = $1, attempted_at = $1 WHERE digest = $2", ts, digest)
		require.NoError(t, err)
	}
	// The never-scanned digest's failed attempt is old too, so what must
	// spare it is scanned_at being NULL, not recency.
	_, err = pool.Exec(ctx, "UPDATE image_scan_state SET attempted_at = $1 WHERE digest = $2", old, prefix+"never-scanned")
	require.NoError(t, err)

	cutoff := time.Now().Add(-imageRescanAfter)
	pruned, err := cursor.PruneOrphaned(ctx, []string{prefix + "live-old"}, cutoff)
	require.NoError(t, err)
	require.EqualValues(t, 1, pruned, "only the stale-and-absent row is deleted")

	states, err := cursor.States(ctx)
	require.NoError(t, err)
	require.NotContains(t, states, prefix+"orphan-old",
		"stale and absent from the live set must be pruned")
	require.Contains(t, states, prefix+"orphan-recent",
		"absent from the live set but within the rescan window must be spared")
	require.Contains(t, states, prefix+"live-old",
		"stale but still present in the live set must be spared")
	require.Contains(t, states, prefix+"never-scanned",
		"never successfully scanned must never be pruned by this query")
}
