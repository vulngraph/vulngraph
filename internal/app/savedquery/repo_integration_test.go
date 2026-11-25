//go:build integration

package savedquery

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Every read returns the newest run as LastAttempt, whatever its outcome, and
// a run that does not advance the baseline leaves last_* alone. Requires
// `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_LastAttemptIsTheNewestRun(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool)

	created, err := repo.Create(ctx, SavedQuery{Name: "it-" + time.Now().Format("150405.000000"),
		Cypher: "MATCH (n) RETURN n", Schedule: "0 * * * *", AlertSeverity: SeverityHigh, Enabled: true})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM saved_queries WHERE id = $1", created.ID)
		require.NoError(t, err)
	})
	require.Nil(t, created.LastAttempt, "a new query has never run")

	require.NoError(t, repo.RecordRun(ctx, Run{SavedQueryID: created.ID, NodeCount: 4, ResultHash: "h1", Trigger: TriggerSchedule}, true))
	time.Sleep(10 * time.Millisecond) // ran_at is now(): order the two runs
	require.NoError(t, repo.RecordRun(ctx, Run{SavedQueryID: created.ID, Trigger: TriggerSchedule, Error: "engine down"}, false))

	got, err := repo.Get(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, got.LastAttempt)
	require.Equal(t, "engine down", got.LastAttempt.Error)
	require.Equal(t, RunStatusFailed, got.LastAttempt.Status())
	require.NotNil(t, got.LastRunAt)
	require.Equal(t, 4, got.LastResultCount, "the failed run did not move the baseline")

	list, err := repo.List(ctx)
	require.NoError(t, err)
	var found bool
	for _, q := range list {
		if q.ID == created.ID {
			found = true
			require.NotNil(t, q.LastAttempt)
			require.Equal(t, "engine down", q.LastAttempt.Error)
		}
	}
	require.True(t, found)

	updated, err := repo.Update(ctx, SavedQuery{ID: created.ID, Name: created.Name, Cypher: created.Cypher,
		AlertSeverity: SeverityHigh, Enabled: true})
	require.NoError(t, err)
	require.NotNil(t, updated.LastAttempt, "an update returns the same view as a read")
	require.Equal(t, "engine down", updated.LastAttempt.Error)
}
