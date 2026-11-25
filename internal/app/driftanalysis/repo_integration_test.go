//go:build integration

package driftanalysis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/db"
)

// TestRepo_DriftBatchLifecycle covers the sweep end to end on real Postgres:
// a same-hash re-stamp creates no batch, a change does, the batch row and its
// enqueue share one transaction, a duplicate save is inert, and prune deletes.
//
// Requires `docker compose up` and applied migrations (graph migrate).
func TestRepo_DriftBatchLifecycle(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	var cid string
	require.NoError(t, pool.QueryRow(ctx,
		`INSERT INTO connectors (type, name, config_enc) VALUES ('demo', 'drift-it', '\x00') RETURNING id`).Scan(&cid))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", cid) })

	hashes := connector.NewPGRepo(pool)
	repo := NewPGRepo(pool)
	entry := func(hash, ip string) []connector.AssetHashEntry {
		return []connector.AssetHashEntry{{AssetID: "arn:it-1", Hash: hash, PubIP: ip, AssetName: "web"}}
	}
	require.NoError(t, hashes.UpsertAssetHashEntries(ctx, cid, entry("h1", "")))
	// Age the row so it is settled and so a later change is newer than it.
	_, err = pool.Exec(ctx, `UPDATE connector_asset_hashes SET first_seen_at = now() - interval '2 hours',
		last_changed_at = now() - interval '2 hours' WHERE connector_id = $1`, cid)
	require.NoError(t, err)

	state := func() ConnectorState {
		states, err := repo.ConnectorStates(ctx)
		require.NoError(t, err)
		for _, s := range states {
			if s.ConnectorID == cid {
				return s
			}
		}
		t.Fatal("connector state missing")
		return ConnectorState{}
	}
	svc := New(repo, nopAnalyst{}, nil)
	enqueued := 0
	enqueue := func(context.Context, Tx, Batch) error { enqueued++; return nil }

	// First sighting: baseline, nothing enqueued.
	got, err := svc.DiscoverBatches(ctx, enqueue)
	require.NoError(t, err)
	require.Empty(t, got)
	require.False(t, state().Watermark.IsZero())

	// A re-stamp with the same hash is not a change.
	require.NoError(t, hashes.UpsertAssetHashEntries(ctx, cid, entry("h1", "")))
	got, err = svc.DiscoverBatches(ctx, enqueue)
	require.NoError(t, err)
	require.Empty(t, got)
	require.Zero(t, enqueued)

	// A real change (gains a public IP) becomes one batch with its enqueue.
	require.NoError(t, hashes.UpsertAssetHashEntries(ctx, cid, entry("h2", "9.9.9.9")))
	_, err = pool.Exec(ctx, `UPDATE connector_asset_hashes SET last_changed_at = now() - interval '5 minutes' WHERE connector_id = $1`, cid)
	require.NoError(t, err)
	got, err = svc.DiscoverBatches(ctx, enqueue)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, 1, enqueued)
	batch := got[0]

	again, err := svc.DiscoverBatches(ctx, enqueue)
	require.NoError(t, err)
	require.Empty(t, again)
	require.Equal(t, 1, enqueued)

	changes, err := repo.Changes(ctx, cid, batch.AssetIDs)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	require.Equal(t, KindNewExposure, changes[0].Kind)

	// An enqueue failure rolls the row back.
	_, err = pool.Exec(ctx, `UPDATE connector_asset_hashes SET last_changed_at = now() - interval '2 minutes' WHERE connector_id = $1`, cid)
	require.NoError(t, err)
	_, err = svc.DiscoverBatches(ctx, func(context.Context, Tx, Batch) error { return context.DeadlineExceeded })
	require.Error(t, err)
	var n int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM drift_batches WHERE connector_id = $1", cid).Scan(&n))
	require.Equal(t, 2, n, "baseline + first batch only")

	// Save is idempotent: an analysed row is never overwritten.
	v := Verdict{Summary: "s", ScanRecommended: true, ScanRecommendedKnown: true}
	require.NoError(t, repo.RecordAttempt(ctx, batch.ID))
	require.NoError(t, repo.Save(ctx, batch.ID, StatusAnalysed, &v, "", time.Now()))
	require.NoError(t, repo.Save(ctx, batch.ID, StatusUnknown, nil, ReasonLLMError, time.Now()))
	stored, err := repo.Get(ctx, batch.ID)
	require.NoError(t, err)
	require.Equal(t, StatusAnalysed, stored.Status)
	require.Equal(t, 1, stored.Attempts)
	require.True(t, stored.Verdict.ScanRecommendedKnown)

	// Requeue finds a stale pending batch; prune removes old rows.
	_, err = pool.Exec(ctx, `UPDATE drift_batches SET status = 'pending', created_at = now() - interval '1 hour' WHERE id = $1`, batch.ID)
	require.NoError(t, err)
	stale, err := repo.ToRequeue(ctx, time.Now().Add(-15*time.Minute), 3, 10)
	require.NoError(t, err)
	require.Len(t, stale, 1)

	_, err = pool.Exec(ctx, `UPDATE drift_batches SET created_at = now() - interval '100 days' WHERE connector_id = $1`, cid)
	require.NoError(t, err)
	_, err = repo.Prune(ctx, time.Now().Add(-retention))
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM drift_batches WHERE connector_id = $1", cid).Scan(&n))
	require.Zero(t, n)
}

type nopAnalyst struct{}

func (nopAnalyst) AnalyzeDrift(context.Context, AnalysisInput) (Verdict, error) {
	return Verdict{}, nil
}
