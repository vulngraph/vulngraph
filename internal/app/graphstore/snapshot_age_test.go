package graphstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A snapshot load reports the graph as old as the build that wrote it and
// replays its recorded fetch completeness; a snapshot past snapshotMaxAge (or
// with no build time) is refused so the caller rebuilds from ClickHouse.
func TestLoadFromSnapshot_ReplaysBuildTimeAndCompleteness(t *testing.T) {
	ctx := context.Background()
	assets, edges, sigs := digestFixture()
	write := func(t *testing.T, builtAt time.Time, complete bool) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "ladybug.snap")
		require.NoError(t, WriteSnapshot(path, GraphSnapshot{
			SchemaVersion: SchemaVersion, BuiltAt: builtAt,
			Assets: assets, Edges: edges, ReachComplete: true,
			EdgeFetchComplete: complete, AssetFetchComplete: complete,
		}))
		return path
	}

	for _, complete := range []bool{true, false} {
		builtAt := time.Now().Add(-3 * time.Hour).UTC()
		svc, err := Open("", 64, 0, 0, write(t, builtAt, complete))
		require.NoError(t, err)
		require.NoError(t, svc.LoadFromSnapshot(ctx, stubSignals{sigs}))
		require.True(t, svc.LastBuiltAt().Equal(builtAt), "LastBuiltAt must be the snapshot's build time, got %s", svc.LastBuiltAt())
		require.Equal(t, complete, svc.edgeFetchComplete.Load())
		require.Equal(t, complete, svc.assetFetchComplete.Load())
		svc.Close()
	}

	for name, builtAt := range map[string]time.Time{
		"older than snapshotMaxAge": time.Now().Add(-snapshotMaxAge - time.Hour),
		"no build time":             {},
	} {
		t.Run(name, func(t *testing.T) {
			svc, err := Open("", 64, 0, 0, write(t, builtAt, true))
			require.NoError(t, err)
			defer svc.Close()
			require.ErrorIs(t, svc.LoadFromSnapshot(ctx, stubSignals{sigs}), ErrSnapshotStale)
			require.False(t, svc.Ready())
		})
	}
}
