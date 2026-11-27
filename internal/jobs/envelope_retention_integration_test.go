//go:build integration

package jobs

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestEnvelopeDerivedRetention(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated derived-state retention replay")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer admin.Close()
	ch, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	for _, table := range []string{"asset_finding_risk", "asset_risk_publications"} {
		require.NoError(t, admin.Exec(ctx, "TRUNCATE TABLE "+table))
	}
	svc := asset.NewService(asset.NewCHRepo(ch))
	now, err := svc.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	base := asset.Asset{ID: "retention-resource", Type: "ec2_instance", Name: "current", Provider: asset.ProviderAWS,
		RiskScore: 5, DiscoveredAt: now.Add(-10 * 24 * time.Hour), LastSeen: now}
	require.NoError(t, svc.Ingest(ctx, []asset.Asset{base}, nil))
	old := now.Add(-3 * 24 * time.Hour)
	digest := strings.Repeat("b", 64)
	insertRisk := func(at time.Time, key string, score, pinned uint8) {
		require.NoError(t, admin.Batch(ctx, "INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned)", func(batch driver.Batch) error {
			return batch.Append(at, key, base.ID, score, pinned)
		}))
	}
	insertMarker := func(retired uint8, retiredAt time.Time) {
		require.NoError(t, admin.Batch(ctx, "INSERT INTO asset_risk_publications (generation,digest,retired,retired_at)", func(batch driver.Batch) error {
			return batch.Append(old, digest, retired, retiredAt)
		}))
	}
	count := func(query string, args ...any) uint64 {
		var n uint64
		require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
			require.True(t, rows.Next())
			return rows.Scan(&n)
		}, query, args...))
		return n
	}
	assertRisk := func(score uint8) {
		got, e := svc.Get(ctx, base.ID)
		require.NoError(t, e)
		require.Equal(t, score, got.RiskScore)
		require.Equal(t, base.Name, got.Name)
	}
	merge := func(table string) {
		require.NoError(t, admin.Exec(ctx, "OPTIMIZE TABLE "+table+" FINAL SETTINGS optimize_skip_merged_partitions=0"))
	}
	// Simulate an already published snapshot whose producer has been unavailable
	// longer than the staging TTL. Its data and marker must remain available.
	insertRisk(old, digest, 60, 1)
	insertMarker(0, time.Unix(0, 0))
	require.NoError(t, admin.Batch(ctx, "INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned)", func(batch driver.Batch) error {
		return batch.Append(old, digest, "", uint8(0), uint8(1))
	}))
	insertRisk(old, strings.Repeat("c", 64), 80, 0)
	insertRisk(old, strings.Repeat("d", 64), 80, 1) // crash after pin, before publication
	merge("asset_finding_risk")
	merge("asset_risk_publications")
	assertRisk(60)
	require.Equal(t, uint64(0), count("SELECT count() FROM asset_finding_risk WHERE digest=?", strings.Repeat("c", 64)))

	first, err := svc.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, svc.PublishFindingRisk(ctx, first, map[string]uint8{base.ID: 60}))
	second, err := svc.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, svc.PublishFindingRisk(ctx, second, map[string]uint8{base.ID: 80}))
	assertRisk(80)
	// Reader grace starts when the generation is retired, not when it was
	// created. Two quick publications cannot remove this three-day-old snapshot.
	require.Positive(t, count("SELECT count() FROM asset_finding_risk WHERE generation=parseDateTime64BestEffort(?,9) AND digest=?", old.UTC().Format(time.RFC3339Nano), digest))
	require.Equal(t, uint64(1), count("SELECT count() FROM (SELECT generation,digest FROM asset_risk_publications GROUP BY generation,digest HAVING argMax(retired,updated_at)=1 AND argMax(retired_at,updated_at)>=parseDateTime64BestEffort(?,9))", now.UTC().Format(time.RFC3339Nano)))
	require.Zero(t, count("SELECT count() FROM asset_finding_risk WHERE digest=?", strings.Repeat("d", 64)))
	merge("asset_finding_risk")
	merge("asset_risk_publications")
	assertRisk(80)
	require.Positive(t, count("SELECT count() FROM asset_finding_risk WHERE generation=parseDateTime64BestEffort(?,9) AND digest=?", old.UTC().Format(time.RFC3339Nano), digest))

	// Advance only the test marker's retirement time; no real-time wait is
	// needed to prove cleanup after grace and after replacement-tree merges.
	insertMarker(1, now.Add(-2*time.Hour))
	require.NoError(t, svc.PublishFindingRisk(ctx, second, map[string]uint8{base.ID: 80}))
	require.Zero(t, count("SELECT count() FROM asset_finding_risk WHERE generation=parseDateTime64BestEffort(?,9) AND digest=?", old.UTC().Format(time.RFC3339Nano), digest))
	assertRisk(80)
	merge("asset_risk_publications")
	require.Zero(t, count("SELECT count() FROM asset_risk_publications WHERE generation=parseDateTime64BestEffort(?,9) AND digest=?", old.UTC().Format(time.RFC3339Nano), digest))
	merge("asset_finding_risk")
	assertRisk(80)
	// An expired writer must recompute instead of reviving a retired snapshot.
	require.ErrorContains(t, svc.PublishFindingRisk(ctx, old, map[string]uint8{base.ID: 60}), "recompute")
	assertRisk(80)
}
