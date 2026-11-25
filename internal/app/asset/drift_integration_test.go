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
// Locks the findingsForAssets rollup: ReplacingMergeTree row versions must
// collapse per finding id (the pre-fix query nested aggregates — ClickHouse
// error 184 — and counted duplicate versions).
func TestCHRepo_EnrichWithFindings(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	res := "drift-it-" + time.Now().Format("150405.000000")
	now := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE findings DELETE WHERE resource_id = ?", res)
		_ = ch.Exec(ctx, "ALTER TABLE finding_enrichment DELETE WHERE id LIKE ?", "f%-"+res)
	})

	// f1 twice with different synced_at (two ReplacingMergeTree versions of the
	// same finding), f2 once. score is NOT part of this INSERT: it is not a
	// column on `findings`; it lives in finding_enrichment below.
	insert := `INSERT INTO findings (id, source, type, severity, title, resource_id, detected_at, synced_at)
		VALUES (?, 'cspm', 'exposure', 'high', 'it', ?, ?, ?)`
	require.NoError(t, ch.Exec(ctx, insert, "f1-"+res, res, now, now.Add(-time.Minute)))
	require.NoError(t, ch.Exec(ctx, insert, "f1-"+res, res, now, now))
	require.NoError(t, ch.Exec(ctx, insert, "f2-"+res, res, now, now))
	// score comes from finding_enrichment ONLY — dual-write
	// the same two ReplacingMergeTree versions of f1 (older/lower score,
	// newer/higher score) and f2's one version, keyed on enriched_at rather
	// than synced_at (finding_enrichment's own version column).
	insertEnr := `INSERT INTO finding_enrichment (id, score, enriched_at) VALUES (?, ?, ?)`
	require.NoError(t, ch.Exec(ctx, insertEnr, "f1-"+res, uint8(40), now.Add(-time.Minute)))
	require.NoError(t, ch.Exec(ctx, insertEnr, "f1-"+res, uint8(80), now))
	require.NoError(t, ch.Exec(ctx, insertEnr, "f2-"+res, uint8(60), now))
	// f3: open, then resolved in its latest version, with the highest score —
	// it must count toward neither the open-finding count nor MaxScore.
	require.NoError(t, ch.Exec(ctx, insert, "f3-"+res, res, now, now.Add(-time.Minute)))
	require.NoError(t, ch.Exec(ctx, `INSERT INTO findings (id, source, type, severity, title, resource_id, detected_at, synced_at, resolved_at)
		VALUES (?, 'cspm', 'exposure', 'high', 'it', ?, ?, ?, ?)`, "f3-"+res, res, now, now, now))
	require.NoError(t, ch.Exec(ctx, insertEnr, "f3-"+res, uint8(99), now))

	events := repo.enrichWithFindings(ctx, []DriftEvent{{Kind: DriftKindNewAsset, AssetID: res}})
	require.Len(t, events, 1)
	require.Equal(t, 2, events[0].FindingsCount, "row versions of f1 collapse to one finding; resolved f3 is not counted")
	require.Equal(t, 80, events[0].MaxScore, "latest version of f1 wins via argMax(score, enriched_at); resolved f3's 99 is ignored")
}

// TestCHRepo_EnrichAssetContext is the regression test for the discarded-error
// class of bug this method used to have: the enrichment query's own error was
// dropped (`_ = r.ch.Select(...)`) and a per-row Scan failure was silently
// skipped with no log — either way, every asset's type/provider/region went
// blank with zero signal anything went wrong (found while wiring drift
// scanning end-to-end). The behavioral half this test pins: a real
// asset's context IS filled in, and an event for an asset with NO ClickHouse
// row is left with blank context rather than erroring the whole call.
func TestCHRepo_EnrichAssetContext(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	id := "drift-ctx-it-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE assets DELETE WHERE id = ?", id) })
	require.NoError(t, svc.Ingest(ctx, []Asset{
		{ID: id, Name: "n", Type: "ec2_instance", Provider: "aws", AccountID: "111111111111",
			Region: "eu-west-1", Domain: "x.example.com", PublicIP: "203.0.113.5",
			DiscoveredAt: time.Now(), LastSeen: time.Now()},
	}, nil))

	events := repo.enrichAssetContext(ctx, []DriftEvent{
		{Kind: DriftKindNewAsset, AssetID: id},
		{Kind: DriftKindNewAsset, AssetID: "no-such-asset-" + id}, // no ClickHouse row at all
	})
	require.Len(t, events, 2)

	require.Equal(t, "ec2_instance", events[0].AssetType)
	require.Equal(t, "aws", events[0].Provider)
	require.Equal(t, "111111111111", events[0].AccountID)
	require.Equal(t, "eu-west-1", events[0].Region)
	require.Equal(t, "x.example.com", events[0].Domain)

	require.Empty(t, events[1].AssetType, "an asset with no ClickHouse row must be left blank, not error the whole call")
}

// The three drift queries embed inventoryReadCond, whose bare `type` column a
// same-named aggregate alias would shadow (ClickHouse error 184). A textual
// guard cannot prove the SQL runs, so this executes each one: new assets and
// new exposures through DriftEvents, and the Postgres-feed context lookup
// through enrichAssetContext. An IaC declaration row must stay out of all three.
func TestCHRepo_DriftQueriesRunAndApplyInventoryGate(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	p := "it-drift-" + time.Now().Format("150405.000000") + "-"
	now := time.Now().Truncate(time.Second)
	live, declared := p+"vm", p+"declared"
	t.Cleanup(func() {
		_ = ch.Exec(context.Background(), "ALTER TABLE assets DELETE WHERE id LIKE ?", p+"%")
		_ = ch.Exec(context.Background(), "ALTER TABLE graph_edges DELETE WHERE src_id LIKE ?", p+"%")
	})
	require.NoError(t, svc.Ingest(ctx, []Asset{
		{ID: live, Name: "vm", Type: "ec2_instance", Provider: ProviderAWS, Region: "us-east-1", DiscoveredAt: now, LastSeen: now},
		{ID: declared, Name: "declared", Type: "declared_tf_resource", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
	}, nil))
	require.NoError(t, ch.Batch(ctx,
		`INSERT INTO graph_edges (src_id, src_type, dst_id, dst_type, edge_type, properties, synced_at)`,
		func(b driver.Batch) error {
			if err := b.Append(live, "ec2_instance", "internet", "internet", "exposed_to_internet", "{}", now); err != nil {
				return err
			}
			return b.Append(declared, "declared_tf_resource", "internet", "internet", "exposed_to_internet", "{}", now)
		}))

	events, err := repo.DriftEvents(ctx, time.Hour, 5000)
	require.NoError(t, err)
	kinds := map[DriftKind]bool{}
	for _, e := range events {
		require.NotEqual(t, declared, e.AssetID, "an IaC declaration is not an inventory asset")
		if e.AssetID == live {
			require.Equal(t, "ec2_instance", e.AssetType)
			kinds[e.Kind] = true
		}
	}
	require.True(t, kinds[DriftKindNewAsset], "new asset missing: %v", kinds)
	require.True(t, kinds[DriftKindNewExposure], "new exposure missing: %v", kinds)

	enriched := repo.enrichAssetContext(ctx, []DriftEvent{{Kind: DriftKindChanged, AssetID: live}, {Kind: DriftKindChanged, AssetID: declared}})
	require.Len(t, enriched, 1, "the declaration row is dropped from the Postgres-sourced feed")
	require.Equal(t, live, enriched[0].AssetID)
	require.Equal(t, "ec2_instance", enriched[0].AssetType)
	require.Equal(t, "us-east-1", enriched[0].Region)
}
