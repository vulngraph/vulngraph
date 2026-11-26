//go:build integration

package jobs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/db"
)

func retirementTestDSN(key, fallback string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return fallback
}

func TestInventoryRetirement_CompleteRetryOwnershipAndResurrection(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, retirementTestDSN("TEST_DATABASE_URL", pgDSN), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	ch, err := db.NewCH(ctx, retirementTestDSN("TEST_CLICKHOUSE_URL", chDSN), 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	cipher, err := connector.NewCipher(testKey(t))
	require.NoError(t, err)
	conns := connector.NewService(connector.NewPGRepo(pool), cipher)
	assets := asset.NewService(asset.NewCHRepo(ch))
	findings := finding.NewService(finding.NewCHRepo(ch))
	suffix := time.Now().Format("150405.000000000")
	create := func(name string) connector.Connector {
		c, err := conns.Create(ctx, connector.TypeGitHub, name+suffix, map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "k"}, "")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, "DELETE FROM asset_deletions WHERE connector_id=$1", c.ID)
			_, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id=$1", c.ID)
		})
		return c
	}
	c := create("retire-")
	other := create("other-")
	keep, gone, shared, returned := "keep-"+suffix, "gone-"+suffix, "shared-"+suffix, "returned-"+suffix
	ids := []string{keep, gone, shared, returned}
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id IN (?, ?, ?, ?) SETTINGS mutations_sync=1", keep, gone, shared, returned)
		_ = ch.Exec(ctx, "ALTER TABLE graph_edges DELETE WHERE src_id IN (?, ?, ?, ?) SETTINGS mutations_sync=1", keep, gone, shared, returned)
	})
	n := 0
	reg := collect.NewRegistry()
	reg.Register(connector.TypeGitHub, scriptedCollector{n: &n, sweeps: []scriptedSweep{
		{ids: ids, complete: true}, {ids: []string{keep}, complete: true, partial: true}, {ids: []string{keep}, complete: true},
	}})
	w := &SyncWorker{connectors: conns, registry: reg, assets: assets, findings: findings, checks: checks.Default()}
	job := &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: c.ID}}
	require.NoError(t, w.Work(ctx, job))
	require.NoError(t, conns.UpsertAssetHashEntries(ctx, other.ID, []connector.AssetHashEntry{{AssetID: shared, Hash: "other", AssetType: "ec2_instance", Region: "eu-west-1"}}))
	require.NoError(t, w.Work(ctx, job))
	before, err := conns.AssetDeletions(ctx, ids)
	require.NoError(t, err)
	require.Empty(t, before)
	require.NoError(t, w.Work(ctx, job))
	proofs, err := conns.AssetDeletions(ctx, ids)
	require.NoError(t, err)
	require.Contains(t, proofs, gone, "complete unchanged fingerprint must retry reconciliation")
	require.Contains(t, proofs, returned)
	require.NotContains(t, proofs, shared, "another connector still owns this resource")
	hashes, err := conns.GetAssetHashes(ctx, c.ID)
	require.NoError(t, err)
	require.NotContains(t, hashes, shared)

	// Older versions retire; a newer observation survives the same proof.
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, assets.Ingest(ctx, []asset.Asset{
		{ID: gone, Type: "ec2_instance", Provider: asset.ProviderAWS, LastSeen: old},
		{ID: returned, Type: "ec2_instance", Provider: asset.ProviderAWS, LastSeen: time.Now().Add(time.Minute)},
	}, nil))
	// Keep the test independent of second-precision timing in the three sweeps.
	_, err = pool.Exec(ctx, "UPDATE asset_deletions SET deleted_at=now()+interval '2 seconds' WHERE asset_id=ANY($1)", []string{gone, returned})
	require.NoError(t, err)
	worker := &InventoryRetirementWorker{proofs: conns, assets: assets, findings: findings}
	require.NoError(t, worker.Work(ctx, &river.Job[InventoryRetirementArgs]{}))
	live, err := assets.LiveIDs(ctx, ids)
	require.NoError(t, err)
	require.NotContains(t, live, gone)
	require.Contains(t, live, keep)
	require.Contains(t, live, shared)
	require.Contains(t, live, returned)
	pending, err := conns.PendingAssetRetirements(ctx, 200)
	require.NoError(t, err)
	require.NotContains(t, pending, gone)
	loaded, err := assets.ListAll(ctx, asset.SyncProjection{})
	require.NoError(t, err)
	for _, a := range loaded.Assets {
		require.NotEqual(t, gone, a.ID)
	}
	// Re-observation restores inventory even after the deletion was applied.
	require.NoError(t, assets.Ingest(ctx, []asset.Asset{{ID: gone, Type: "ec2_instance", Provider: asset.ProviderAWS, LastSeen: time.Now().Add(time.Minute)}}, nil))
	require.NoError(t, worker.Work(ctx, &river.Job[InventoryRetirementArgs]{}))
	live, err = assets.LiveIDs(ctx, []string{gone})
	require.NoError(t, err)
	require.Contains(t, live, gone)
}
