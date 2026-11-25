//go:build integration

package enrichcache

import (
	"cmp"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// pgDSN is the compose Postgres; GRAPH_TEST_PG_DSN points the test at another database.
var pgDSN = cmp.Or(os.Getenv("GRAPH_TEST_PG_DSN"), "postgres://graph:graph@localhost:5432/graph?sslmode=disable")

// Requires `docker compose up` and applied migrations. The graph
// context round-trips, invalidation clears only the fingerprint, and the alert
// state survives it.
func TestPGRepo_GraphContextInvalidateAndAlertState(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool)
	id := "it-enrichcache-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM enrich_cache WHERE finding_id = $1`, id)
		_, _ = pool.Exec(ctx, `DELETE FROM finding_alert_state WHERE finding_id = $1`, id)
	})

	at := time.Now().UTC().Truncate(time.Second)
	in := Entry{FindingID: id, InputFP: "fp", ContextFP: "cfp", ScoreBand: "page", EnrichedAt: at,
		Graph: GraphContext{Exposed: "true", PrivescBucket: "1", ReachBucket: "direct"}}
	require.NoError(t, repo.Upsert(ctx, in))
	got, err := repo.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, in.Graph, got.Graph)

	_, err = repo.AlertState(ctx, id)
	require.True(t, errors.Is(err, ErrNotFound), "never alerted reads as not found, not as an empty state")
	require.NoError(t, repo.RecordAlert(ctx, AlertState{FindingID: id, ScoreBand: "page", MustFixClass: "must_fix", AlertedAt: at}))

	require.NoError(t, repo.InvalidateFingerprints(ctx, []string{id, "it-missing"}))
	got, err = repo.Get(ctx, id)
	require.NoError(t, err)
	require.Empty(t, got.InputFP, "the fingerprint is cleared")
	require.Equal(t, "cfp", got.ContextFP, "the rest of the row survives")
	require.Equal(t, in.Graph, got.Graph)

	st, err := repo.AlertState(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "page", st.ScoreBand)
	require.Equal(t, "must_fix", st.MustFixClass)

	// The store keeps the high-water mark: a lower write never lowers it.
	require.NoError(t, repo.RecordAlert(ctx, AlertState{FindingID: id, ScoreBand: "high", MustFixClass: "elevated", AlertedAt: at}))
	st, err = repo.AlertState(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "page", st.ScoreBand)
	require.Equal(t, "must_fix", st.MustFixClass)

	// Resolving clears it.
	require.NoError(t, repo.ClearAlertStates(ctx, []string{id}))
	_, err = repo.AlertState(ctx, id)
	require.True(t, errors.Is(err, ErrNotFound))

	// Prune drops state only for findings no longer enriched — and never a
	// recent alert, even for a finding with no cache row (just alerted, cache
	// write failed).
	fresh := id + "-fresh"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM finding_alert_state WHERE finding_id = $1`, fresh) })
	require.NoError(t, repo.RecordAlert(ctx, AlertState{FindingID: fresh, ScoreBand: "page", AlertedAt: at}))
	_, err = repo.PruneAlertStates(ctx, at.Add(-30*24*time.Hour))
	require.NoError(t, err)
	_, err = repo.AlertState(ctx, fresh)
	require.NoError(t, err, "a recent alert survives the prune")
	old := at.Add(-60 * 24 * time.Hour)
	require.NoError(t, repo.RecordAlert(ctx, AlertState{FindingID: id, ScoreBand: "page", AlertedAt: old}))
	_, err = repo.PruneAlertStates(ctx, at.Add(-30*24*time.Hour))
	require.NoError(t, err)
	_, err = repo.AlertState(ctx, id)
	require.NoError(t, err, "still enriched recently: kept")
	require.NoError(t, repo.Upsert(ctx, Entry{FindingID: id, InputFP: "fp", EnrichedAt: old}))
	_, err = repo.PruneAlertStates(ctx, at.Add(-30*24*time.Hour))
	require.NoError(t, err)
	_, err = repo.AlertState(ctx, id)
	require.True(t, errors.Is(err, ErrNotFound), "not enriched in the retention window: pruned")
}
