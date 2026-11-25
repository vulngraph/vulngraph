//go:build integration

package diskscan

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

// Needs a Postgres with the migrations applied: the compose one, or any other
// named by DISKSCAN_TEST_PG_DSN.
func integrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DISKSCAN_TEST_PG_DSN")
	if dsn == "" {
		dsn = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"
	}
	pool, err := db.NewPool(context.Background(), dsn, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func newConnectorRow(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO connectors (type, name, config_enc) VALUES ('aws', $1, '\x00') RETURNING id`,
		"it-"+time.Now().Format("150405.000000")).Scan(&id)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), "DELETE FROM connectors WHERE id = $1", id) })
	return id
}

func TestPGRepo_RunsVolumesAndLatest(t *testing.T) {
	ctx := context.Background()
	pool := integrationPool(t)
	connID := newConnectorRow(t, pool)
	conns := &fakeConns{byID: map[string]ConnectorSettings{connID: {ConnectorID: connID, Mode: DiskScanModeExistingSnapshots}}}
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := NewService(NewPGRepo(pool), conns).WithClock(func() time.Time { return now })

	run, err := svc.StartRun(ctx, connID)
	require.NoError(t, err)
	require.Equal(t, StatusRunning, run.Status)
	require.NotEmpty(t, run.ID)

	boot := DiskScanTarget{AssetID: "it-i-1", VolumeRef: "vol-boot", Boot: true}
	data := DiskScanTarget{AssetID: "it-i-1", VolumeRef: "vol-data"}
	require.NoError(t, svc.RecordResult(ctx, run.ID, boot, VolumeResult{InventoryKnown: true, CVEMatchableKnown: true, PackageCount: 321, SnapshotSource: SourceReused, SnapshotID: "snap-b"}))
	require.NoError(t, svc.RecordResult(ctx, run.ID, data, VolumeResult{Gap: GapEncryptedNoKey, Encrypted: true}))
	require.NoError(t, svc.RecordResult(ctx, run.ID, boot, VolumeResult{InventoryKnown: true, PackageCount: 322}), "an upsert, not a duplicate")
	other := DiskScanTarget{AssetID: "it-i-2", VolumeRef: "vol-x", Boot: true}
	require.NoError(t, svc.RecordResult(ctx, run.ID, other, VolumeResult{Gap: GapUnsupportedFS}))

	// The table itself refuses a result that reads as clean for an unread disk.
	_, err = pool.Exec(ctx, `INSERT INTO disk_scan_volumes (run_id, asset_id, volume_ref, observed_at) VALUES ($1, 'bad', 'v', now())`, run.ID)
	require.Error(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO disk_scan_volumes (run_id, asset_id, volume_ref, inventory_known, observed_at) VALUES ($1, 'bad', 'v', true, now())`, run.ID)
	require.NoError(t, err, "known with no gap is the one clean shape")
	_, err = pool.Exec(ctx, `INSERT INTO disk_scan_volumes (run_id, asset_id, volume_ref, gap, cve_matchable_known, observed_at) VALUES ($1, 'bad2', 'v', 'read_error', true, now())`, run.ID)
	require.Error(t, err)
	_, err = pool.Exec(ctx, `DELETE FROM disk_scan_volumes WHERE asset_id = 'bad'`)
	require.NoError(t, err)

	latest, err := svc.Latest(ctx, []string{"it-i-1", "it-i-2", "it-i-3"})
	require.NoError(t, err)
	require.Len(t, latest, 2)
	assert.True(t, latest["it-i-1"].InventoryKnown)
	assert.Equal(t, 322, latest["it-i-1"].PackageCount)
	assert.Equal(t, "vol-boot", latest["it-i-1"].VolumeRef)
	assert.Equal(t, GapUnsupportedFS, latest["it-i-2"].Gap)
	assert.False(t, latest["it-i-2"].InventoryKnown)

	finished, err := svc.FinishRun(ctx, run.ID, 3, nil)
	require.NoError(t, err)
	assert.Equal(t, StatusPartial, finished.Status)
	assert.Equal(t, RunCounts{Volumes: 3, Scanned: 1, Gaps: 2}, finished.Counts)

	got, err := svc.GetRun(ctx, run.ID)
	require.NoError(t, err)
	assert.Equal(t, finished.Status, got.Status)
	assert.False(t, got.FinishedAt.IsZero())
	_, err = svc.GetRun(ctx, "not-a-uuid")
	require.ErrorIs(t, err, ErrNotFound)

	runs, err := svc.ListRuns(ctx, connID, 10)
	require.NoError(t, err)
	require.Len(t, runs, 1)
	vols, err := svc.ListVolumes(ctx, run.ID)
	require.NoError(t, err)
	require.Len(t, vols, 3)

	// Deleting the connector removes its runs and their volumes.
	_, err = pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", connID)
	require.NoError(t, err)
	latest, err = svc.Latest(ctx, []string{"it-i-1"})
	require.NoError(t, err)
	assert.Empty(t, latest)
}

func TestPGRepo_NotEnabledRun(t *testing.T) {
	ctx := context.Background()
	pool := integrationPool(t)
	connID := newConnectorRow(t, pool)
	conns := &fakeConns{byID: map[string]ConnectorSettings{connID: {ConnectorID: connID}}}
	svc := NewService(NewPGRepo(pool), conns)
	run, err := svc.StartRun(ctx, connID)
	require.NoError(t, err)
	assert.Equal(t, StatusNotEnabled, run.Status)
	assert.False(t, run.FinishedAt.IsZero())
}

func TestPGRepo_SnapshotRegistry(t *testing.T) {
	ctx := context.Background()
	pool := integrationPool(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := NewService(NewPGRepo(pool), &fakeConns{}).WithClock(func() time.Time { return now }).WithSnapshotTTL(time.Hour)
	run := "it-run-" + now.Format("150405.000000")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM disk_scan_snapshots WHERE run_id = $1", run) })

	in := SnapshotIntent{RunID: run, ConnectorID: "c", Provider: "aws", Region: "eu-west-1", VolumeRef: "vol-1"}
	first, err := svc.RegisterSnapshotIntent(ctx, in)
	require.NoError(t, err)
	assert.Empty(t, first.SnapshotID)
	retry, err := svc.RegisterSnapshotIntent(ctx, in)
	require.NoError(t, err)
	assert.Equal(t, first.ID, retry.ID)

	require.NoError(t, svc.AttachSnapshot(ctx, first.ID, "snap-it-1"))
	require.ErrorIs(t, svc.AttachSnapshot(ctx, "00000000-0000-0000-0000-000000000000", "snap-x"), ErrNotFound)

	hasRun := func(list []SnapshotIntent) bool {
		for _, o := range list {
			if o.RunID == run {
				return true
			}
		}
		return false
	}
	orphans, err := svc.ListOrphans(ctx)
	require.NoError(t, err)
	assert.False(t, hasRun(orphans))

	later := now.Add(2 * time.Hour)
	svc.WithClock(func() time.Time { return later })
	orphans, err = svc.ListOrphans(ctx)
	require.NoError(t, err)
	assert.True(t, hasRun(orphans))

	require.NoError(t, svc.MarkDeletedBySnapshot(ctx, "aws", "snap-it-1"))
	require.NoError(t, svc.MarkDeleted(ctx, first.ID), "idempotent")
	orphans, err = svc.ListOrphans(ctx)
	require.NoError(t, err)
	assert.False(t, hasRun(orphans))
}

func TestPGRepo_Cache(t *testing.T) {
	ctx := context.Background()
	pool := integrationPool(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := NewService(NewPGRepo(pool), &fakeConns{}).WithClock(func() time.Time { return now })
	snap := "it-snap-" + now.Format("150405.000000")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM disk_scan_cache WHERE snapshot_id LIKE 'it-%'") })

	_, ok, err := svc.CacheGet(ctx, "aws", snap)
	require.NoError(t, err)
	assert.False(t, ok)

	e := CacheEntry{Provider: "aws", SnapshotID: snap, Digest: "abc", Extents: []engine.Extent{{Offset: 4096, Length: 8192}},
		Result: VolumeResult{InventoryKnown: true, CVEMatchableKnown: true, PackageCount: 7}}
	require.NoError(t, svc.CachePut(ctx, e))
	got, ok, err := svc.CacheGet(ctx, "aws", snap)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, e.Extents, got.Extents)
	assert.Equal(t, 7, got.Result.PackageCount)
	assert.True(t, got.Result.CVEMatchableKnown)

	neg := CacheEntry{Provider: "aws", SnapshotID: "it-denied-" + snap, Result: VolumeResult{Gap: GapPermissionDenied}, ExpiresAt: now.Add(24 * time.Hour)}
	require.NoError(t, svc.CachePut(ctx, neg))
	got, ok, err = svc.CacheGet(ctx, "aws", neg.SnapshotID)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, GapPermissionDenied, got.Result.Gap)
	assert.False(t, got.Result.InventoryKnown)
	svc.WithClock(func() time.Time { return now.Add(25 * time.Hour) })
	_, ok, err = svc.CacheGet(ctx, "aws", neg.SnapshotID)
	require.NoError(t, err)
	assert.False(t, ok)
}
