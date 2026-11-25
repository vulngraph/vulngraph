//go:build integration

package asset

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestCountPackages asserts the count matches ScanLivePackages' own paged
// total on a small fixture, not just that it returns some number: the gauge's
// denominator must be the same live set the OSV refresh scans.
func TestCountPackages(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	before, err := repo.CountPackages(ctx)
	require.NoError(t, err)

	p := "it-countpkg-" + time.Now().Format("150405.000000") + "-"
	now := time.Now().Truncate(time.Second)
	pkgs := []Asset{
		{ID: p + "a", Name: "a", Type: "package", Provider: ProviderGitHub,
			Metadata:     map[string]string{"ecosystem": "npm", "package": "a", "version": "1.0.0"},
			DiscoveredAt: now, LastSeen: now},
		{ID: p + "b", Name: "b", Type: "package", Provider: ProviderGitHub,
			Metadata:     map[string]string{"ecosystem": "npm", "package": "b", "version": "1.0.0"},
			DiscoveredAt: now, LastSeen: now},
	}
	svc := NewService(repo)
	// Each package gets the fresh edge that makes it live inventory
	// (livePackageIDs) — the set both readers count.
	edges := make([]Edge, 0, len(pkgs))
	for _, a := range pkgs {
		edges = append(edges, Edge{SrcID: p + "repo", SrcType: "github_repo", DstID: a.ID, DstType: "package", EdgeType: "depends_on"})
	}
	require.NoError(t, svc.Ingest(ctx, pkgs, edges))
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
		_ = ch.Exec(context.Background(), "ALTER TABLE graph_edges DELETE WHERE dst_id LIKE ?", p+"%")
	})

	after, err := repo.CountPackages(ctx)
	require.NoError(t, err)
	require.Equal(t, before+2, after, "count must increase by exactly the number of package assets ingested")

	// Cross-check against the paged listing this same count feeds the
	// denominator for — the two must never diverge.
	var paged int64
	_, err = svc.ScanLivePackages(ctx, func(page []PackageCoord) error {
		paged += int64(len(page))
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, after, paged, "CountPackages must match ScanLivePackages' own paged total")
}
