//go:build integration

package finding_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

func TestPackageSignalsFollowInventoryProducer(t *testing.T) {
	dsn := os.Getenv("TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("TEST_CLICKHOUSE_URL must name an isolated migrated database")
	}
	ctx := context.Background()
	ch, err := db.NewCH(ctx, dsn, 4)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	now := time.Now().Truncate(time.Second)
	suffix := now.Format("150405") + time.Now().Format(".000000000")
	clock := now
	repo := finding.NewCHRepo(ch, finding.WithClock(func() time.Time { return clock }))
	inv := asset.NewService(asset.NewCHRepo(ch))
	pkgs := []pkginventory.InstalledPackage{{Ecosystem: "Debian:12", Name: "test-package-" + suffix, Version: "1.0"}}
	var packageID string
	for _, runner := range []struct{ id, typ string }{
		{"vm-a-" + suffix, "ec2_instance"}, {"vm-b-" + suffix, "gce_instance"}, {"image-" + suffix, "container_image"},
	} {
		assets, edges := pkginventory.InventoryGraph(runner.id, runner.typ, pkgs, now)
		packageID = assets[0].ID
		require.NoError(t, inv.Ingest(ctx, assets, edges))
		// Re-observation must not multiply the propagated signal.
		require.NoError(t, inv.IngestEdges(ctx, edges))
	}
	stale := "stale-" + suffix
	require.NoError(t, ch.Exec(ctx, `INSERT INTO graph_edges (src_id,src_type,dst_id,dst_type,edge_type,synced_at)
 VALUES (?,'ec2_instance',?,'package','runs_package',now()-INTERVAL 3 DAY)`, stale, packageID))
	f := finding.Finding{ID: "pkg-kev-" + suffix, Source: "supply_chain", Type: "vulnerability", Severity: finding.SeverityHigh,
		ResourceID: packageID, ResourceType: "package", CheckID: "CVE-2026-12345", DetectedAt: now}
	require.NoError(t, repo.Upsert(ctx, []finding.Finding{f}))
	e := finding.Enrichment{ID: f.ID, Score: 92, KnownExploited: true, EnrichedAt: now}
	require.NoError(t, repo.UpsertEnrichment(ctx, []finding.Enrichment{e}))
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE id=? SETTINGS mutations_sync=1", f.ID)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id=? SETTINGS mutations_sync=1", f.ID)
		_ = ch.Exec(ctx, "ALTER TABLE graph_edges DELETE WHERE dst_id=? SETTINGS mutations_sync=1", packageID)
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id=? SETTINGS mutations_sync=1", packageID)
	})
	signals, err := repo.SignalsByResource(ctx)
	require.NoError(t, err)
	for _, id := range []string{"vm-a-" + suffix, "vm-b-" + suffix, "image-" + suffix} {
		require.True(t, signals[id].HasKEV, "package KEV missing on %s", id)
		require.EqualValues(t, 92, signals[id].MaxScore)
	}
	require.NotContains(t, signals, stale, "expired membership must not propagate risk")
	clock = now.Add(time.Second)
	f.ResolvedAt = clock
	require.NoError(t, repo.Upsert(ctx, []finding.Finding{f}))
	signals, err = repo.SignalsByResource(ctx)
	require.NoError(t, err)
	for _, id := range []string{packageID, "vm-a-" + suffix, "vm-b-" + suffix, "image-" + suffix} {
		require.NotContains(t, signals, id, "resolved package finding must clear")
	}
}
