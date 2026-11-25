//go:build integration

package asset

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestScanLivePackages_OnlyLivePackages: a package is listed while a fresh
// edge points at it. One whose every edge has aged past the freshness window,
// and one no edge ever pointed at, are not inventory — no
// producer writes a package node without its edge, so an edgeless package is
// one nothing has re-observed either.
func TestScanLivePackages_OnlyLivePackages(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	p := "pkg:npm/it-pkglive-" + time.Now().Format("150405.000000") + "-"
	fresh, stale, staleAndFresh, edgeless := p+"fresh@1.0.0", p+"stale@1.0.0", p+"both@1.0.0", p+"edgeless@1.0.0"
	now := time.Now().Truncate(time.Second)
	pkgs := make([]Asset, 0, 4)
	for _, id := range []string{fresh, stale, staleAndFresh, edgeless} {
		pkgs = append(pkgs, Asset{ID: id, Name: id, Type: "package", Provider: ProviderGitHub,
			Metadata:     map[string]string{"ecosystem": "npm", "package": id, "version": "1.0.0"},
			DiscoveredAt: now, LastSeen: now})
	}
	require.NoError(t, svc.Ingest(ctx, pkgs, []Edge{
		{SrcID: p + "image", SrcType: "container_image", DstID: fresh, DstType: "package", EdgeType: "runs_package"},
		{SrcID: p + "repo", SrcType: "github_repo", DstID: staleAndFresh, DstType: "package", EdgeType: "depends_on"},
	}))
	// Edges older than the 48h freshness window: re-stamping stopped, so the
	// image/repo that shipped them no longer does.
	old := now.Add(-72 * time.Hour)
	require.NoError(t, ch.Batch(ctx,
		`INSERT INTO graph_edges (src_id, src_type, dst_id, dst_type, edge_type, properties, synced_at)`,
		func(b driver.Batch) error {
			if err := b.Append(p+"old-image", "container_image", stale, "package", "runs_package", "{}", old); err != nil {
				return err
			}
			return b.Append(p+"old-image", "container_image", staleAndFresh, "package", "runs_package", "{}", old)
		}))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
		_ = ch.Exec(context.Background(), "ALTER TABLE graph_edges DELETE WHERE dst_id LIKE ?", p+"%")
	})

	var listed []string
	_, err = svc.ScanLivePackages(ctx, func(page []PackageCoord) error {
		for _, c := range page {
			if strings.HasPrefix(c.ID, p) {
				listed = append(listed, c.ID)
				require.Equal(t, "npm", c.Metadata["ecosystem"], "metadata is hydrated for a live package")
				require.False(t, c.FirstSeen.IsZero(), "first-seen is hydrated — the OSV refresh rescans a source when a new binary appears under it")
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{fresh, staleAndFresh}, listed,
		"only packages with a fresh edge are live; stale-only and edgeless packages must not be listed")
}
