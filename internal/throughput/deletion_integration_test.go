//go:build integration

package throughput

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/db"
)

const seedDeletionHashes = `INSERT INTO connector_asset_hashes(connector_id,asset_id,hash,asset_type,region)
 SELECT $1, 'backlog-'||lpad(n::text,7,'0'), 'seed', 'ec2_instance', 'eu-west-1' FROM generate_series(0,$2::integer-1) n`

type deletionMeasurement struct {
	Scenario   string  `json:"scenario"`
	Candidates int     `json:"candidates"`
	Confirmed  int     `json:"confirmed"`
	Seconds    float64 `json:"seconds"`
}

func measureDeletion(t *testing.T, ctx context.Context, dsn string, p profile) []deletionMeasurement {
	t.Helper()
	pool, err := db.NewPool(ctx, dsn, 4)
	require.NoError(t, err)
	defer pool.Close()
	var id string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO connectors(type,name,config_enc) VALUES ('aws','benchmark-deletion','') RETURNING id`).Scan(&id))
	defer func() { _, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id=$1", id); require.NoError(t, err) }()
	n := 1106
	if p.Workloads >= 600000 {
		n = 548000
	}
	_, err = pool.Exec(ctx, seedDeletionHashes, id, n)
	require.NoError(t, err)
	ids := make([]string, n)
	for i := range ids {
		ids[i] = fmt.Sprintf("backlog-%07d", i)
	}
	repo := connector.NewPGRepo(pool)
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-4 * time.Hour)
	var result []deletionMeasurement
	for i, name := range []string{"first_absence", "too_soon", "confirmed_batch", "next_batch"} {
		observed := at.Add(time.Duration(i) * time.Minute)
		if i >= 2 {
			observed = at.Add(3*time.Hour + time.Duration(i)*time.Minute)
		}
		start := time.Now()
		batch, err := repo.ObserveDeletionCandidates(ctx, id, ids, observed, observed.Add(-2*time.Hour), 5000)
		require.NoError(t, err)
		m := deletionMeasurement{Scenario: name, Candidates: len(ids), Confirmed: len(batch), Seconds: time.Since(start).Seconds()}
		if i < 2 {
			require.Empty(t, batch)
		} else {
			require.Len(t, batch, min(5000, len(ids)))
			seen := map[string]bool{}
			for _, item := range batch {
				require.False(t, seen[item])
				seen[item] = true
			}
			require.NoError(t, repo.DeleteAssetHashes(ctx, id, batch))
			remaining := ids[:0]
			for _, item := range ids {
				if !seen[item] {
					remaining = append(remaining, item)
				}
			}
			ids = remaining
		}
		t.Logf("deletion %s: candidates=%d confirmed=%d seconds=%.4f", name, m.Candidates, m.Confirmed, m.Seconds)
		result = append(result, m)
	}
	// A replay after clearing must not reconstitute old confirmation, even if
	// it carries the exact timestamp of a formerly accepted observation.
	clearAt := at.Add(5 * time.Hour)
	_, err = repo.ObserveDeletionCandidates(ctx, id, nil, clearAt, clearAt.Add(-2*time.Hour), 5000)
	require.NoError(t, err)
	_, err = repo.ObserveDeletionCandidates(ctx, id, ids, clearAt, clearAt.Add(-2*time.Hour), 5000)
	require.ErrorContains(t, err, "stale sweep")
	_, err = repo.ObserveDeletionCandidates(ctx, id, ids, at, at.Add(-2*time.Hour), 5000)
	require.ErrorContains(t, err, "stale sweep")
	batch, err := repo.ObserveDeletionCandidates(ctx, id, ids, clearAt.Add(time.Minute), clearAt.Add(-time.Hour), 5000)
	require.NoError(t, err)
	require.Empty(t, batch, "cleared observations must restart confirmation")
	return result
}
