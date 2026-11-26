//go:build integration

package jobs

import (
	"context"
	"fmt"
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

func TestDeletionBacklogRequiresConfirmationAndDrains(t *testing.T) {
	pgDSN, chDSN := os.Getenv("TEST_DATABASE_URL"), os.Getenv("TEST_CLICKHOUSE_URL")
	if pgDSN == "" || chDSN == "" {
		t.Skip("requires isolated migrated test databases")
	}
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	ch, err := db.NewCH(ctx, chDSN, 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	cipher, err := connector.NewCipher(testKey(t))
	require.NoError(t, err)
	conns := connector.NewService(connector.NewPGRepo(pool), cipher)
	inv := asset.NewService(asset.NewCHRepo(ch))
	// The confirmed absence below represents hours passing. Seed the finding
	// before that window as well: synced_at has second precision, so immediate
	// seed/resolve writes can tie and make argMax choose either version.
	findingWriteAt := time.Now().Add(-3 * time.Hour)
	findings := finding.NewService(finding.NewCHRepo(ch, finding.WithClock(func() time.Time { return findingWriteAt })))
	prefix := "backlog-" + time.Now().Format("150405.000000000") + "-"
	create := func(name string) connector.Connector {
		c, err := conns.Create(ctx, connector.TypeGitHub, name+prefix, map[string]string{"app_id": "1", "installation_id": "2", "private_key_pem": "k"}, "")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = pool.Exec(ctx, "DELETE FROM asset_deletions WHERE connector_id=$1", c.ID)
			_, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id=$1", c.ID)
		})
		return c
	}
	c, other := create("owner-"), create("other-")
	const total = 1106
	ids := make([]string, total)
	assets := make([]asset.Asset, total)
	hashes := make([]connector.AssetHashEntry, total)
	for i := range ids {
		ids[i] = fmt.Sprintf("%s%04d", prefix, i)
		assets[i] = asset.Asset{ID: ids[i], Type: "ec2_instance", Provider: asset.ProviderAWS, Region: "eu-west-1", LastSeen: time.Now()}
		hashes[i] = connector.AssetHashEntry{AssetID: ids[i], Hash: "seed", AssetType: "ec2_instance", Region: "eu-west-1"}
	}
	require.NoError(t, inv.Ingest(ctx, assets, nil))
	require.NoError(t, conns.UpsertAssetHashEntries(ctx, c.ID, hashes))
	require.NoError(t, conns.UpsertAssetHashEntries(ctx, other.ID, hashes[2:3]))
	f := finding.Finding{ID: prefix + "finding", Source: "synthetic", ResourceID: ids[3], ResourceType: "ec2_instance", DetectedAt: findingWriteAt}
	require.NoError(t, findings.Record(ctx, []finding.Finding{f}))
	findingWriteAt = time.Now()
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix)
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE startsWith(id,?) SETTINGS mutations_sync=1", prefix)
	})
	n := 0
	reg := collect.NewRegistry()
	reg.Register(connector.TypeGitHub, scriptedCollector{n: &n, sweeps: []scriptedSweep{
		{ids: ids[:1], complete: true}, {ids: ids[:1], complete: true},
		{ids: ids[:2], complete: true, partial: true}, {ids: ids[:2], complete: true}, {ids: ids[:2], complete: true},
	}})
	w := &SyncWorker{connectors: conns, registry: reg, assets: inv, findings: findings, checks: checks.Default()}
	job := &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: c.ID}}
	assertNoProofs := func() {
		proofs, err := conns.AssetDeletions(ctx, ids)
		require.NoError(t, err)
		require.Empty(t, proofs)
	}
	age := func() {
		_, err := pool.Exec(ctx, "UPDATE connector_deletion_candidates SET first_missing_at=first_missing_at-interval '3 hours' WHERE connector_id=$1", c.ID)
		require.NoError(t, err)
	}
	require.NoError(t, w.Work(ctx, job))
	assertNoProofs()
	require.NoError(t, w.Work(ctx, job))
	assertNoProofs() // two close-together observations are still unconfirmed
	age()
	require.NoError(t, w.Work(ctx, job)) // partial collection resets the pending set
	assertNoProofs()
	var pending int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM connector_deletion_candidates WHERE connector_id=$1", c.ID).Scan(&pending))
	require.Zero(t, pending)
	require.NoError(t, w.Work(ctx, job))
	assertNoProofs() // complete collection must establish new confirmation
	age()
	require.NoError(t, w.Work(ctx, job))
	proofs, err := conns.AssetDeletions(ctx, ids)
	require.NoError(t, err)
	require.Len(t, proofs, total-3)
	for _, id := range ids[:3] {
		require.NotContains(t, proofs, id, "present, returned or other-owned assets must survive")
	}
	stored, err := conns.GetAssetHashes(ctx, c.ID)
	require.NoError(t, err)
	require.Len(t, stored, 2)
	got, err := findings.Get(ctx, f.ID)
	require.NoError(t, err)
	require.True(t, got.Resolved())
	// Move only these test proofs past second-precision storage timestamps.
	_, err = pool.Exec(ctx, "UPDATE asset_deletions SET deleted_at=now()+interval '2 seconds' WHERE connector_id=$1", c.ID)
	require.NoError(t, err)
	retire := &InventoryRetirementWorker{proofs: conns, assets: inv, findings: findings}
	require.NoError(t, retire.Work(ctx, &river.Job[InventoryRetirementArgs]{}))
	live, err := inv.LiveIDs(ctx, ids)
	require.NoError(t, err)
	require.Len(t, live, 3)
	for _, id := range ids[:3] {
		require.Contains(t, live, id)
	}
}
