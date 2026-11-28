//go:build integration

package asset_test

import (
	"context"
	"maps"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestGraphSourceProjectionSemantics(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated graph projection and lifecycle replay")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 1)
	require.NoError(t, err)
	defer admin.Close()
	repo := asset.NewCHRepo(ch)
	now, err := repo.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	metadata := map[string]string{"discarded": "large policy", "quoted": "quote\" slash\\ café 😀"}
	for _, key := range graphstore.SyncMetadataKeys {
		metadata[key] = "value-for-" + key
	}
	base := asset.Asset{ID: "projection-current", Name: "before", Type: "ec2_instance", Provider: asset.ProviderAWS, AccountID: "synthetic", RiskScore: 5,
		Tags: map[string]string{"owner": "synthetic"}, Metadata: metadata, DiscoveredAt: now.Add(-time.Hour).Truncate(time.Second), FirstDiscoveredAt: now.Add(-24 * time.Hour).Truncate(time.Second), LastSeen: now}
	require.NoError(t, repo.UpsertAssets(ctx, []asset.Asset{base}))
	base.Name = "latest"
	base.Metadata = maps.Clone(metadata)
	base.Metadata["public"] = "latest-value"
	delete(base.Metadata, "version")
	base.LastSeen, err = repo.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, repo.UpsertAssets(ctx, []asset.Asset{base}))
	version, err := repo.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, repo.PublishFindingRisk(ctx, version, map[string]uint8{base.ID: 80, "projection-absent": 99}))
	anchor := base
	anchor.ID = "projection-pod-anchor"
	anchor.Type = "k8s_pod"
	dead := anchor
	dead.ID = "projection-pod-dead"
	dead.LastSeen = now.Add(-30 * 24 * time.Hour)
	pkg := base
	pkg.ID = "projection-package"
	pkg.Type = "package"
	require.NoError(t, repo.UpsertAssets(ctx, []asset.Asset{anchor, dead, pkg}))
	assertModes := func(expectedScore uint8, present bool) {
		t.Helper()
		for _, p := range []asset.SyncProjection{{}, {SkipTags: true}, {MetadataKeys: graphstore.SyncMetadataKeys}, graphstore.SyncProjection()} {
			result, e := repo.ListAllForSync(ctx, p)
			require.NoError(t, e)
			require.False(t, result.Truncated)
			got := map[string]asset.Asset{}
			for _, a := range result.Assets {
				got[a.ID] = a
			}
			require.NotContains(t, got, "projection-absent", "derived contribution must not create base assets")
			require.NotContains(t, got, dead.ID)
			require.NotContains(t, got, pkg.ID)
			require.Contains(t, got, anchor.ID)
			if !present {
				require.NotContains(t, got, base.ID)
				continue
			}
			want := base
			want.RiskScore = expectedScore
			if p.SkipTags {
				want.Tags = nil
			}
			if len(p.MetadataKeys) > 0 {
				want.Metadata = map[string]string{}
				for _, key := range p.MetadataKeys {
					if v, ok := base.Metadata[key]; ok {
						want.Metadata[key] = v
					}
				}
			}
			a := got[base.ID]
			a.DiscoveredAt = a.DiscoveredAt.UTC()
			a.FirstDiscoveredAt = a.FirstDiscoveredAt.UTC()
			a.LastSeen = a.LastSeen.UTC()
			require.Equal(t, want, a, "production projection %+v", p)
		}
	}
	assertModes(80, true)
	cutoff, err := repo.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	retired, err := repo.RetireAssets(ctx, map[string]time.Time{base.ID: cutoff})
	require.NoError(t, err)
	require.Equal(t, []string{base.ID}, retired)
	assertModes(80, false)
	base.Name = "reappeared"
	base.Metadata["public"] = "fresh-reappearance"
	base.LastSeen, err = repo.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, repo.UpsertAssets(ctx, []asset.Asset{base}))
	assertModes(80, true)
	reset, err := repo.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, repo.PublishFindingRisk(ctx, reset, map[string]uint8{}))
	assertModes(5, true)
	require.NoError(t, repo.PublishFindingRisk(ctx, version, map[string]uint8{base.ID: 80, "projection-absent": 99}))
	assertModes(5, true)
	for _, table := range []string{"assets", "asset_finding_risk"} {
		require.NoError(t, admin.Exec(ctx, "OPTIMIZE TABLE "+table+" FINAL"))
	}
	assertModes(5, true)
}
