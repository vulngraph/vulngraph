//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Replays a derived producer that read A -> B -> C before a complete
// observation retired B, then wrote its stale relationships after retirement.
// This is distinct from a reference to an identity that was never collected.
func TestEnvelopeDeletedCorrelationTraversal(t *testing.T) {
	chURL, pgURL := os.Getenv("TEST_CLICKHOUSE_URL"), os.Getenv("TEST_DATABASE_URL")
	if chURL == "" {
		chURL = "clickhouse://graph:graph@localhost:9000/graph"
	}
	if pgURL == "" {
		pgURL = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"
	}
	if os.Getenv("PERF_ENVELOPE_ISOLATED") == "1" {
		chURL, pgURL = os.Getenv("PERF_APP_CLICKHOUSE_URL"), os.Getenv("PERF_POSTGRES_URL")
	}
	dir := os.Getenv("PERF_ENVELOPE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	ch, err := db.NewCH(ctx, chURL, 4)
	require.NoError(t, err)
	defer ch.Close()
	repo := asset.NewCHRepo(ch)
	pool, err := db.NewPool(ctx, pgURL, db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	proofs := connector.NewPGRepo(pool)
	inv := asset.NewService(repo).WithDeletionProofs(proofs)
	observed := time.Now().UTC().Add(-10 * time.Second)
	prefix := fmt.Sprintf("deleted-chain-%d-", time.Now().UnixNano())
	a, b, c, d, unknown := prefix+"a", prefix+"b", prefix+"c", prefix+"unknown-root", prefix+"never-observed"
	defer func() {
		clean, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		assert.NoError(t, ch.Exec(clean, "DELETE FROM graph_edges WHERE src_id IN (?,?,?,?) SETTINGS lightweight_deletes_sync=1", a, b, d, unknown))
		assert.NoError(t, ch.Exec(clean, "DELETE FROM assets WHERE id IN (?,?,?,?) SETTINGS lightweight_deletes_sync=1", a, b, c, d))
		_, err := pool.Exec(clean, "DELETE FROM asset_deletions WHERE asset_id=$1", b)
		assert.NoError(t, err)
	}()
	var assets []asset.Asset
	for _, id := range []string{a, b, c} {
		assets = append(assets, asset.Asset{ID: id, Name: id, Type: "iam_role", Provider: asset.ProviderAWS, AccountID: id, LastSeen: observed})
	}
	edges := []asset.Edge{
		{SrcID: a, SrcType: "iam_role", DstID: b, DstType: "iam_role", EdgeType: "can_assume", Properties: map[string]string{"origin": "correlate", "rule": "synthetic_delayed_rule"}},
		{SrcID: b, SrcType: "iam_role", DstID: c, DstType: "iam_role", EdgeType: "can_assume", Properties: map[string]string{"origin": "correlate", "rule": "synthetic_delayed_rule"}},
	}
	require.NoError(t, inv.Ingest(ctx, assets, edges))
	proof := time.Now().UTC()
	proven, err := proofs.RecordAssetDeletions(ctx, "synthetic-deletion-owner", []string{b}, proof)
	require.NoError(t, err)
	require.Equal(t, []string{b}, proven)
	retired, err := repo.RetireAssets(ctx, map[string]time.Time{b: proof})
	require.NoError(t, err)
	require.Equal(t, []string{b}, retired)
	_, err = inv.Get(ctx, b)
	require.ErrorIs(t, err, asset.ErrNotFound)
	require.NoError(t, inv.IngestEdges(ctx, edges))
	var raw []map[string]any
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var src, dst, kind, properties string
			var at time.Time
			if err := rows.Scan(&src, &dst, &kind, &properties, &at); err != nil {
				return err
			}
			raw = append(raw, map[string]any{"source": src, "target": dst, "type": kind, "properties": properties, "synced_at": at})
		}
		return rows.Err()
	}, "SELECT src_id,dst_id,edge_type,properties,synced_at FROM graph_edges FINAL WHERE src_id IN (?,?) ORDER BY src_id", a, b))
	queries := explore.NewService(explore.NewCHRepo(ch).WithDeletionVerifier(inv))
	run, err := queries.Run(ctx, explore.GraphQuerySpec{Seed: explore.NodeMatch{IDs: []string{a}}, Traverse: []explore.Traverse{{Direction: explore.DirectionOut, MaxHops: 2}}})
	require.NoError(t, err)
	expanded, err := queries.ExpandNode(ctx, a, nil, explore.DirectionOut)
	require.NoError(t, err)
	blast, err := inv.BlastRadius(ctx, a, 2)
	require.NoError(t, err)
	accounts, err := inv.BlastRadiusAccounts(ctx, a, 2)
	require.NoError(t, err)
	report := map[string]any{"source": os.Getenv("PERF_COMMIT"), "observation_at": observed, "deletion_proof_at": proof, "raw_edges": raw,
		"explore_run": run, "explore_expand": expanded, "blast": blast, "blast_accounts": accounts}
	data, err := json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deleted-edge-readback.json"), data, 0600))
	assert.Len(t, run.Nodes, 1, "deleted middle node must not resurrect or bridge to C")
	assert.Empty(t, run.Edges)
	assert.Empty(t, expanded.Edges)
	assert.Len(t, blast.Assets, 1)
	assert.Empty(t, blast.Edges)
	assert.Zero(t, accounts.Total)

	// A genuinely newer observation restores the canonical identity. An old
	// proof must not suppress it indefinitely, including in another instance.
	assets[1].LastSeen = time.Now().UTC()
	require.NoError(t, inv.Ingest(ctx, assets[1:2], nil))
	fresh := asset.NewService(asset.NewCHRepo(ch)).WithDeletionProofs(connector.NewPGRepo(pool))
	back, err := fresh.BlastRadius(ctx, a, 2)
	require.NoError(t, err)
	assert.Len(t, back.Assets, 3)
	newQueries := explore.NewService(explore.NewCHRepo(ch).WithDeletionVerifier(fresh))
	reappeared, err := newQueries.Run(ctx, explore.GraphQuerySpec{Seed: explore.NodeMatch{IDs: []string{a}}, Traverse: []explore.Traverse{{Direction: explore.DirectionOut, MaxHops: 2}}})
	require.NoError(t, err)
	assert.Len(t, reappeared.Nodes, 3)

	// Compare identical live outputs after reappearance, with the historical
	// proof still populated. Query comments retain measured CH calls/bytes;
	// the wrapper counts actual proof lookups, not an inferred request budget.
	counted := &envelopeCountedProofs{DeletionProofs: proofs}
	costCandidate := asset.NewService(asset.NewCHRepo(ch)).WithDeletionProofs(counted)
	costBaseline := asset.NewService(asset.NewCHRepo(ch))
	costExplore := explore.NewService(explore.NewCHRepo(ch).WithDeletionVerifier(costCandidate))
	baseExplore := explore.NewService(explore.NewCHRepo(ch))
	var costs []map[string]any
	for repeat := range 3 {
		variants := []string{"baseline", "candidate"}
		if repeat%2 == 1 {
			variants = []string{"candidate", "baseline"}
		}
		for _, variant := range variants {
			svc, ex := costBaseline, baseExplore
			if variant == "candidate" {
				svc, ex = costCandidate, costExplore
			}
			for _, kind := range []string{"blast", "explore"} {
				qctx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": fmt.Sprintf("deletion-cost:%s:%s:%d", variant, kind, repeat)})
				before := counted.calls.Load()
				start := time.Now()
				if kind == "blast" {
					got, err := svc.BlastRadius(qctx, a, 2)
					elapsed := time.Since(start).Seconds()
					require.NoError(t, err)
					require.ElementsMatch(t, back.Assets, got.Assets)
					require.ElementsMatch(t, back.Edges, got.Edges)
					costs = append(costs, map[string]any{"operation": kind, "variant": variant, "repeat": repeat, "seconds": elapsed, "proof_lookups": counted.calls.Load() - before})
				} else {
					got, err := ex.Run(qctx, explore.GraphQuerySpec{Seed: explore.NodeMatch{IDs: []string{a}}, Traverse: []explore.Traverse{{Direction: explore.DirectionOut, MaxHops: 2}}})
					elapsed := time.Since(start).Seconds()
					require.NoError(t, err)
					require.ElementsMatch(t, reappeared.Nodes, got.Nodes)
					require.ElementsMatch(t, reappeared.Edges, got.Edges)
					costs = append(costs, map[string]any{"operation": kind, "variant": variant, "repeat": repeat, "seconds": elapsed, "proof_lookups": counted.calls.Load() - before})
				}
				if variant == "candidate" {
					require.LessOrEqual(t, counted.calls.Load()-before, int64(3), "one seed and one endpoint proof lookup per hop")
				}
			}
		}
	}
	report["matched_live_read_costs"] = costs
	data, err = json.MarshalIndent(report, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deleted-edge-readback.json"), data, 0600))

	// Absence without a proof remains unknown, including a virtual middle node.
	require.NoError(t, inv.Ingest(ctx, []asset.Asset{{ID: d, Name: d, Type: "iam_role", Provider: asset.ProviderAWS, LastSeen: time.Now()}}, []asset.Edge{
		{SrcID: d, SrcType: "iam_role", DstID: unknown, DstType: "iam_role", EdgeType: "can_assume"},
		{SrcID: unknown, SrcType: "iam_role", DstID: c, DstType: "iam_role", EdgeType: "can_assume"},
	}))
	unknownPath, err := fresh.BlastRadius(ctx, d, 2)
	require.NoError(t, err)
	assert.Len(t, unknownPath.Assets, 3)
	unknownRun, err := newQueries.Run(ctx, explore.GraphQuerySpec{Seed: explore.NodeMatch{IDs: []string{d}}, Traverse: []explore.Traverse{{Direction: explore.DirectionOut, MaxHops: 2}}})
	require.NoError(t, err)
	assert.Len(t, unknownRun.Nodes, 3)

	// Dependency failure is unmeasured, never an empty proof set.
	brokenPool, err := db.NewPool(ctx, pgURL, db.MaxConnsWorker)
	require.NoError(t, err)
	brokenPool.Close()
	fresh.WithDeletionProofs(connector.NewPGRepo(brokenPool))
	_, err = fresh.BlastRadius(ctx, a, 2)
	require.Error(t, err)
	_, err = fresh.BlastRadiusAccounts(ctx, a, 2)
	require.Error(t, err)
	_, err = newQueries.ExpandNode(ctx, a, nil, explore.DirectionOut)
	require.Error(t, err)
	_, err = newQueries.Run(ctx, explore.GraphQuerySpec{Seed: explore.NodeMatch{IDs: []string{a}}})
	require.Error(t, err)
}

type envelopeCountedProofs struct {
	asset.DeletionProofs
	calls atomic.Int64
}

func (p *envelopeCountedProofs) AssetDeletions(ctx context.Context, ids []string) (map[string]time.Time, error) {
	p.calls.Add(1)
	return p.DeletionProofs.AssetDeletions(ctx, ids)
}
