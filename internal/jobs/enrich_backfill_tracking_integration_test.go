//go:build integration

package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Preserve existing singletons and remove only rows inserted while a test
// exercised its isolated queue. Call after stopping any test consumers.
func trackNewBackfillJobs(t *testing.T, ctx context.Context, pool *pgxpool.Pool) func() {
	t.Helper()
	ids := func(ctx context.Context) []int64 {
		rows, err := pool.Query(ctx, "SELECT id FROM river_job WHERE kind='enrich_sweep' AND args->>'backfill_only'='true'")
		require.NoError(t, err)
		defer rows.Close()
		var ids []int64
		for rows.Next() {
			var id int64
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, rows.Err())
		return ids
	}
	before := map[int64]bool{}
	for _, id := range ids(ctx) {
		before[id] = true
	}
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, id := range ids(ctx) {
			if !before[id] {
				_, err := pool.Exec(ctx, "DELETE FROM river_job WHERE id=$1", id)
				require.NoError(t, err)
			}
		}
	}
}
