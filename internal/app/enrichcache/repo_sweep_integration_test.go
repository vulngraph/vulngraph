//go:build integration

package enrichcache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
)

func TestPGRepo_SweepProgressAcrossInstancesAndCAS(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	first, second := NewService(NewPGRepo(pool)), NewService(NewPGRepo(pool))
	original, err := first.GetSweepProgress(ctx)
	require.NoError(t, err)
	defer func() {
		var before any
		if !original.Before.IsZero() {
			before = original.Before
		}
		_, restoreErr := pool.Exec(ctx, `INSERT INTO enrichment_sweep_progress(id,cursor_value,pass_before,revision) VALUES(true,$1,$2,$3)
    ON CONFLICT(id) DO UPDATE SET cursor_value=EXCLUDED.cursor_value,pass_before=EXCLUDED.pass_before,revision=EXCLUDED.revision`, original.Cursor, before, original.Revision)
		require.NoError(t, restoreErr)
	}()
	stale, err := second.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, original.Revision, stale.Revision)
	next := SweepProgress{Cursor: "one", Before: time.Now().UTC().Truncate(time.Millisecond)}
	ok, err := first.AdvanceSweepProgress(ctx, original.Revision, next)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = second.AdvanceSweepProgress(ctx, stale.Revision, SweepProgress{Cursor: "stale-writer", Before: next.Before})
	require.NoError(t, err)
	require.False(t, ok)
	persisted, err := NewService(NewPGRepo(pool)).GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Equal(t, next.Cursor, persisted.Cursor)
	require.True(t, next.Before.Equal(persisted.Before))
	require.Equal(t, original.Revision+1, persisted.Revision)
	ok, err = second.AdvanceSweepProgress(ctx, persisted.Revision, SweepProgress{})
	require.NoError(t, err)
	require.True(t, ok)
	reset, err := first.GetSweepProgress(ctx)
	require.NoError(t, err)
	require.Empty(t, reset.Cursor)
	require.True(t, reset.Before.IsZero())
	_, err = pool.Exec(ctx, "DELETE FROM enrichment_sweep_progress WHERE id")
	require.NoError(t, err)
	_, err = first.GetSweepProgress(ctx)
	require.Error(t, err, "missing operational state must not appear as completed progress")
}
