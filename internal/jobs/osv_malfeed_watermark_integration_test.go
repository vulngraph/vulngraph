//go:build integration

package jobs

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
)

// TestOSVMalFeedWatermark_RoundTrip exercises the real query against
// Postgres: a cold read (no row yet) returns pgx.ErrNoRows — the exact signal
// MalFeedWorker.Work treats as lastSHA=="" — and a write followed by a read
// returns exactly what was written, including the upsert overwrite path.
func TestOSVMalFeedWatermark_RoundTrip(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// The table is a fixed single row (id=1) by design — reset it around this
	// test so it doesn't collide with any other watermark left by a real run
	// of the worker against this same database.
	_, err = pool.Exec(ctx, "DELETE FROM osv_malfeed_watermark WHERE id = 1")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM osv_malfeed_watermark WHERE id = 1")
	})

	q := sqlcgen.New(pool)

	_, err = q.GetOSVMalFeedWatermark(ctx)
	require.ErrorIs(t, err, pgx.ErrNoRows, "cold read with no row yet must be pgx.ErrNoRows")

	require.NoError(t, q.SetOSVMalFeedWatermark(ctx, "sha-one"))
	got, err := q.GetOSVMalFeedWatermark(ctx)
	require.NoError(t, err)
	require.Equal(t, "sha-one", got)

	// Second write must UPDATE the single row, not fail on the id=1 unique
	// constraint or create a second row.
	require.NoError(t, q.SetOSVMalFeedWatermark(ctx, "sha-two"))
	got, err = q.GetOSVMalFeedWatermark(ctx)
	require.NoError(t, err)
	require.Equal(t, "sha-two", got)

	var count int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM osv_malfeed_watermark").Scan(&count))
	require.Equal(t, 1, count, "the watermark must stay a single row across repeated writes")
}
