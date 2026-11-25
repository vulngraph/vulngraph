//go:build integration

package coverage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestQFreshAssetsByType_AnchorsOnProviderHighWaterNotWallClock is the
// regression test for the anchor mismatch: AssetFreshness used to compare
// last_seen against now(), which reads a whole provider's estate as "gone
// stale" the moment ITS OWN collector stops running for the margin — even
// though every asset is exactly as fresh as that provider's data has ever
// been. Anchored on high_water (this provider's own most recent last_seen)
// instead, a healthy-but-old-relative-to-wall-clock provider still counts as
// fully fresh, matching asset.ProviderStaleness's own anchoring discipline.
//
// Requires `docker compose up` and applied migrations (graph migrate).
func TestQFreshAssetsByType_AnchorsOnProviderHighWaterNotWallClock(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewRepo(ch)

	provider := "it-stale-prov-" + time.Now().Format("150405.000000")
	// This provider's own collector last ran 30 days ago (well past any
	// wall-clock freshness window) — but every asset it collected is exactly
	// as fresh as that provider's data ever gets: high_water == last_seen for
	// all of them, so they must all count as fresh.
	syncedAt := time.Now().Add(-30 * 24 * time.Hour)
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE provider = ?", provider) })

	insert := `INSERT INTO assets (id, provider, type, last_seen, synced_at) VALUES (?, ?, ?, ?, ?)`
	require.NoError(t, ch.Exec(ctx, insert, "a1-"+provider, provider, "ec2_instance", syncedAt, syncedAt))
	require.NoError(t, ch.Exec(ctx, insert, "a2-"+provider, provider, "ec2_instance", syncedAt, syncedAt))

	f := &LiveFacts{}
	require.NoError(t, repo.assets(ctx, f))

	var n uint64
	for _, tc := range f.Assets {
		if tc.Provider == provider {
			n += tc.Count
		}
	}
	require.Equal(t, uint64(2), n,
		"a provider whose own collector is stale relative to wall-clock, but internally consistent "+
			"(every asset as fresh as that provider's data ever is), must still count as fully fresh")
}

// TestMetaValues_SplitsVMsByInventoryStamp runs the real metadata-value query:
// the placeholder order (key, then the type list twice) and the JSON extraction
// are only checked against a live ClickHouse.
func TestMetaValues_SplitsVMsByInventoryStamp(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewRepo(ch)

	provider := "it-inv-prov-" + time.Now().Format("150405.000000")
	now := time.Now()
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE provider = ?", provider) })
	insert := `INSERT INTO assets (id, provider, type, metadata, last_seen, synced_at) VALUES (?, ?, ?, ?, ?, ?)`
	for id, meta := range map[string]string{
		"vm-ssm":  `{"package_inventory":"ssm","package_cve_matchable":"true","package_ecosystem":"Amazon Linux:2023"}`,
		"vm-eol":  `{"package_inventory":"ssm","package_cve_matchable":"false","package_ecosystem":"CentOS:7","package_cve_gap":"eol_distro"}`,
		"vm-none": `{"package_inventory":"none","package_inventory_gap":"not_ssm_managed"}`,
		"vm-old":  `{}`,
	} {
		require.NoError(t, ch.Exec(ctx, insert, id+"-"+provider, provider, "ec2_instance", meta, now, now))
	}

	f := &LiveFacts{}
	require.NoError(t, repo.metaValues(ctx, f))
	got := map[[2]string]uint64{}
	for _, mv := range f.MetaValues {
		got[[2]string{mv.Key, mv.Value}] += mv.Count
	}
	require.GreaterOrEqual(t, got[[2]string{"package_inventory", "ssm"}], uint64(1))
	require.GreaterOrEqual(t, got[[2]string{"package_inventory", "none"}], uint64(1))
	require.GreaterOrEqual(t, got[[2]string{"package_cve_matchable", "true"}], uint64(1))
	require.GreaterOrEqual(t, got[[2]string{"package_ecosystem", "Amazon Linux:2023"}], uint64(1))
	require.GreaterOrEqual(t, got[[2]string{"package_cve_gap", "eol_distro"}], uint64(1))
}
