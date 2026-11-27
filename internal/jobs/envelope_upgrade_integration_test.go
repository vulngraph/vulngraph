//go:build integration

package jobs

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestEnvelopeDerivedUpgradeAndReappearance(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated derived-state upgrade and reappearance replay")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer admin.Close()
	a := asset.NewService(asset.NewCHRepo(ch))
	now, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	legacy := asset.Asset{ID: "legacy-risk-resource", Type: "ec2_instance", Name: "legacy",
		Provider: asset.ProviderAWS, RiskScore: 80, DiscoveredAt: now.Add(-24 * time.Hour), LastSeen: now,
		Metadata: map[string]string{"revision": "legacy"}}
	require.NoError(t, a.Ingest(ctx, []asset.Asset{legacy}, nil))
	old, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, a.PublishFindingRisk(ctx, old, map[string]uint8{}))
	got, err := a.Get(ctx, legacy.ID)
	require.NoError(t, err)
	// Pre-upgrade rows do not identify whether their score came from CIEM or
	// the historical finding writer. Preserve it until a collector supplies a
	// fresh observation; blindly zeroing it could hide current IAM risk.
	require.Equal(t, uint8(80), got.RiskScore)
	legacy.Name = "fresh-observation"
	legacy.Metadata["revision"] = "fresh"
	legacy.RiskScore = 25
	legacy.LastSeen, err = a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, a.Ingest(ctx, []asset.Asset{legacy}, nil))
	got, err = a.Get(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, uint8(25), got.RiskScore)
	firstObservation := got.FirstDiscoveredAt
	active, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, a.PublishFindingRisk(ctx, active, map[string]uint8{legacy.ID: 60}))
	cutoff, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	retired, err := a.RetireAssets(ctx, map[string]time.Time{legacy.ID: cutoff})
	require.NoError(t, err)
	require.Equal(t, []string{legacy.ID}, retired)
	_, err = a.Get(ctx, legacy.ID)
	require.ErrorIs(t, err, asset.ErrNotFound, "a derived row cannot resurrect inventory")
	legacy.Name = "reappeared"
	legacy.Metadata["revision"] = "reappeared"
	legacy.LastSeen, err = a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	// A provider may retain its original discovery/creation date for this ID.
	// FirstDiscoveredAt therefore cannot serve as a resource incarnation token.
	require.NoError(t, a.Ingest(ctx, []asset.Asset{legacy}, nil))
	got, err = a.Get(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, firstObservation, got.FirstDiscoveredAt)
	require.Equal(t, legacy.Name, got.Name)
	require.Equal(t, legacy.Metadata, got.Metadata)
	require.Equal(t, uint8(60), got.RiskScore, "unresolved canonical-ID risk remains conservative until a complete refresh")
	cleared, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, a.PublishFindingRisk(ctx, cleared, map[string]uint8{}))
	require.NoError(t, a.PublishFindingRisk(ctx, active, map[string]uint8{legacy.ID: 60}))
	assertFresh := func() {
		read, e := a.Get(ctx, legacy.ID)
		require.NoError(t, e)
		require.Equal(t, uint8(25), read.RiskScore)
		require.Equal(t, legacy.Name, read.Name)
		require.Equal(t, legacy.Metadata, read.Metadata)
		require.WithinDuration(t, legacy.LastSeen, read.LastSeen, time.Nanosecond)
	}
	assertFresh()
	for _, table := range []string{"assets", "asset_finding_risk", "asset_risk_publications"} {
		require.NoError(t, admin.Exec(ctx, "OPTIMIZE TABLE "+table+" FINAL SETTINGS optimize_skip_merged_partitions=0"))
	}
	assertFresh()
}
