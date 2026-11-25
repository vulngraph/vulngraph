package graphstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestSnapshot_RoundTripsTopoDigest: the digest baseline must survive the
// gob+gzip round trip, and a schema mismatch must still reject the snapshot.
func TestSnapshot_RoundTripsTopoDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ladybug.snap")
	assets, edges, _ := digestFixture()
	snap := GraphSnapshot{
		SchemaVersion: SchemaVersion,
		BuiltAt:       time.Now(),
		TopoDigest:    0xDEADBEEFCAFE,
		Assets:        assets,
		Edges:         edges,
		ReachComplete: true,
	}
	require.NoError(t, WriteSnapshot(path, snap))

	got, err := ReadSnapshot(path, SchemaVersion)
	require.NoError(t, err)
	require.Equal(t, uint64(0xDEADBEEFCAFE), got.TopoDigest,
		"TopoDigest must survive the snapshot round trip — it is the gate baseline across restarts")
	require.True(t, got.ReachComplete)

	_, err = ReadSnapshot(path, "v0-other")
	require.ErrorIs(t, err, ErrSnapshotStale)
}

// TestLoadFromSnapshot_WarmStartSkipsRebuild is the restart half of the
// load-digest fix: workers restart (deploys, memory-limit kills), and because the digest
// baseline lived only in memory, every restart forced a full rebuild even
// when ClickHouse held exactly what the snapshot held. A warm-started service
// must seed the gate from the snapshot so its follow-up sync can no-op.
func TestLoadFromSnapshot_WarmStartSkipsRebuild(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ladybug.snap")
	assets, edges, sigs := digestFixture()

	// First life: full sync writes the snapshot with the digest header.
	first, err := Open("", 64, 0, 0, path)
	require.NoError(t, err)
	require.NoError(t, first.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathFull, first.LastSyncPath())
	first.Close()

	// Second life: warm start, then the follow-up sync every warm start schedules.
	second, err := Open("", 64, 0, 0, path)
	require.NoError(t, err)
	defer second.Close()
	require.NoError(t, second.LoadFromSnapshot(ctx, stubSignals{sigs}))
	require.True(t, second.Ready())

	require.NoError(t, second.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathNoop, second.LastSyncPath(),
		"a restart with unchanged sources must not pay the full rebuild — that is the whole point of persisting the digest")

	// A signal change after warm start still takes the cheap path, and topology
	// growth still rebuilds — the seeded baseline must behave exactly like one
	// latched by a full sync.
	moved := map[string]NodeSignals{"lb-1": {HasKEV: true, MaxScore: 99}, "pod-1": sigs["pod-1"]}
	require.NoError(t, second.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{moved}))
	require.Equal(t, syncPathSignals, second.LastSyncPath())

	grown := append(append([]asset.Asset(nil), assets...),
		asset.Asset{ID: "bucket-9", Name: "logs", Type: "s3_bucket", Provider: "aws"})
	require.NoError(t, second.SyncFromSources(ctx, 0, stubAssets{grown}, stubEdges{edges}, stubSignals{moved}))
	require.Equal(t, syncPathFull, second.LastSyncPath())
}

// TestLoadFromSnapshot_NoDigestHeaderFailsOpen: a snapshot without a digest (an
// old-format file, or one whose writer's digest computation failed) must still
// warm-start the graph but seed NO baseline, so the follow-up sync does the full
// rebuild rather than trusting a baseline that was never computed.
func TestLoadFromSnapshot_NoDigestHeaderFailsOpen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ladybug.snap")
	assets, edges, sigs := digestFixture()
	require.NoError(t, WriteSnapshot(path, GraphSnapshot{
		SchemaVersion: SchemaVersion,
		BuiltAt:       time.Now(),
		TopoDigest:    0, // old snapshot: no baseline
		Assets:        assets,
		Edges:         edges,
		ReachComplete: true,
	}))

	svc, err := Open("", 64, 0, 0, path)
	require.NoError(t, err)
	defer svc.Close()
	require.NoError(t, svc.LoadFromSnapshot(ctx, stubSignals{sigs}))
	require.True(t, svc.Ready())

	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathFull, svc.LastSyncPath(),
		"no header digest means no baseline — the gate must fail open into a rebuild")
}

// TestLoadFromSnapshot_HeaderDigestMismatchSeedsNothing: a header digest that does
// not match a recompute over the snapshot's own content (digest algorithm changed
// between binaries, or the header lies) must not seed the gate — skipping a
// rebuild against a wrong baseline would serve stale topology indefinitely.
func TestLoadFromSnapshot_HeaderDigestMismatchSeedsNothing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ladybug.snap")
	assets, edges, sigs := digestFixture()
	require.NoError(t, WriteSnapshot(path, GraphSnapshot{
		SchemaVersion: SchemaVersion,
		BuiltAt:       time.Now(),
		TopoDigest:    12345, // not what this binary computes over this content
		Assets:        assets,
		Edges:         edges,
		ReachComplete: true,
	}))

	svc, err := Open("", 64, 0, 0, path)
	require.NoError(t, err)
	defer svc.Close()
	require.NoError(t, svc.LoadFromSnapshot(ctx, stubSignals{sigs}))
	require.Nil(t, svc.lastDigest.Load(), "a mismatched header digest must seed nothing")

	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathFull, svc.LastSyncPath())
}
