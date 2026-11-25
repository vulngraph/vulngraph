//go:build integration

package reasoncache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_UpsertGet(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	svc := NewService(NewPGRepo(pool))

	id := "f-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM reasoning_cache WHERE finding_id = $1", id)
	})

	// Miss before any write.
	_, err = svc.Get(ctx, id)
	require.ErrorIs(t, err, ErrNotFound)

	now := time.Now().UTC().Truncate(time.Second)
	e := Entry{
		FindingID: id, Fingerprint: "fp-1", ActionClass: "remediate", Summary: "s", Rationale: "r",
		Outcome: "parked_for_approval", ConfidenceBand: "high", ConfidenceScore: 0.92,
		EffectiveN: 4.5, SampleCount: 6, BlastRadius: 3, CoVeConcerns: []string{"destructive on prod"},
		SafetyBand: "safe", DecidedAt: now,
	}
	require.NoError(t, svc.Put(ctx, e))

	got, err := svc.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "fp-1", got.Fingerprint)
	require.Equal(t, "remediate", got.ActionClass)
	require.WithinDuration(t, now, got.DecidedAt, time.Second)
	// The full 7-step trace round-trips, not just the plan.
	require.Equal(t, "high", got.ConfidenceBand)
	require.InDelta(t, 0.92, got.ConfidenceScore, 0.001)
	require.InDelta(t, 4.5, got.EffectiveN, 0.001)
	require.Equal(t, 6, got.SampleCount)
	require.Equal(t, 3, got.BlastRadius)
	require.Equal(t, []string{"destructive on prod"}, got.CoVeConcerns)
	// safety_band must survive the round-trip — the Decisions "Safe to Fix" list
	// reads it from here, and its absence is what made that list always empty.
	require.Equal(t, "safe", got.SafetyBand)

	// Upsert overwrites by finding_id.
	require.NoError(t, svc.Put(ctx, Entry{FindingID: id, Fingerprint: "fp-2", ActionClass: "observe", DecidedAt: now}))
	got, err = svc.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, "fp-2", got.Fingerprint)
	require.Equal(t, "observe", got.ActionClass)
}
