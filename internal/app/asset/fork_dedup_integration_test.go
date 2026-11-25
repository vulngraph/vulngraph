//go:build integration

package asset

import (
	"context"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
//
// `assets` is ORDER BY (type, id), and the ReplacingMergeTree dedupe key is
// the whole sort tuple. provider is deliberately not in it: a package
// discovered under two providers (a container-image scan AND a GitHub SBOM)
// would otherwise fork into two permanent rows no FINAL could collapse. The
// two writes must collapse into one FINAL row, with the more-recently-synced
// write's values winning.
func TestCHRepo_ProviderChangeDoesNotForkAssetRow(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })

	repo := NewCHRepo(ch)
	svc := NewService(repo)

	pkgID := "it-fork-" + time.Now().Format("150405.000000") + "-pkg:npm/example@1.0.0"
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", pkgID)
	})

	// Discovered first via a container image scan (provider=kubernetes)...
	require.NoError(t, svc.Ingest(ctx, []Asset{{
		ID: pkgID, Name: "example", Type: "package", Provider: ProviderKubernetes,
		RiskScore: 10, DiscoveredAt: now, LastSeen: now,
	}}, nil))

	// ...then again via a GitHub SBOM (provider=github), synced later. synced_at
	// is a second-precision DateTime stamped at ingest, so two ingests inside
	// the same wall-clock second tie and either row may win; wait for the next
	// second, as a real later sweep would be.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	later := now.Add(time.Minute)
	require.NoError(t, svc.Ingest(ctx, []Asset{{
		ID: pkgID, Name: "example", Type: "package", Provider: ProviderGitHub,
		RiskScore: 20, DiscoveredAt: later, LastSeen: later,
	}}, nil))

	// With provider in the sort key these would be two permanent rows FINAL
	// could never collapse. There must be exactly one.
	var count uint64
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		if rows.Next() {
			return rows.Scan(&count)
		}
		return nil
	}, "SELECT count() FROM assets FINAL WHERE id = ?", pkgID))
	require.Equal(t, uint64(1), count, "a provider change must not fork the asset row")

	got, err := svc.Get(ctx, pkgID)
	require.NoError(t, err)
	require.Equal(t, ProviderGitHub, got.Provider, "the most-recently-synced write's provider wins")
	require.Equal(t, uint8(20), got.RiskScore, "the most-recently-synced write's other columns win too")
}
