//go:build integration

package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_ScanRunLifecycle(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool)

	run, err := repo.CreateRun(ctx, 7)
	require.NoError(t, err)
	require.Equal(t, StatusRunning, run.Status)
	require.Equal(t, 7, run.TargetCount)
	require.Nil(t, run.FinishedAt)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM scan_runs WHERE id = $1", run.ID) })

	require.NoError(t, repo.FinishRun(ctx, run.ID, StatusCompleted, 3, "", []string{"exposure", "misconfig"}, 2, []string{"https://example.com"}, "nuclei"))

	got, err := repo.GetRun(ctx, run.ID)
	require.NoError(t, err)
	require.Equal(t, StatusCompleted, got.Status)
	require.Equal(t, 3, got.FindingCount)
	require.NotNil(t, got.FinishedAt)

	runs, err := repo.ListRuns(ctx, 10)
	require.NoError(t, err)
	require.NotEmpty(t, runs)

	_, err = repo.GetRun(ctx, "00000000-0000-0000-0000-000000000000")
	require.ErrorIs(t, err, ErrNotFound)
}
