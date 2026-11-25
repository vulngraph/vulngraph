//go:build integration

package suppress

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

const pgDSN = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_SuppressionLifecycle(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	svc := NewService(NewPGRepo(pool))
	id := "it-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM finding_suppressions WHERE finding_id = $1", id)
		require.NoError(t, err)
	})

	// Not suppressed yet.
	got, err := svc.IsSuppressed(ctx, id)
	require.NoError(t, err)
	require.False(t, got)

	sup, err := svc.SuppressUntil(ctx, id, "false positive", "admin@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, id, sup.FindingID)
	require.False(t, sup.SuppressedAt.IsZero(), "DB default now() populates the timestamp")

	got, err = svc.IsSuppressed(ctx, id)
	require.NoError(t, err)
	require.True(t, got)

	// Re-suppress updates the reason in place (ON CONFLICT upsert).
	_, err = svc.SuppressUntil(ctx, id, "accepted risk", "other@b.example", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	active, _, err := svc.SuppressionStates(ctx)
	require.NoError(t, err)
	_, ok := active[id]
	require.True(t, ok)

	list, err := svc.List(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, list)

	require.NoError(t, svc.Unsuppress(ctx, id, "integration@example.com"))
	got, err = svc.IsSuppressed(ctx, id)
	require.NoError(t, err)
	require.False(t, got)

	// Lifting an absent suppression is ErrNotFound.
	require.ErrorIs(t, svc.Unsuppress(ctx, id, "integration@example.com"), ErrNotFound)
}

// Expiry against real Postgres: an expired row stops matching but is kept (so
// the finding can say its exception expired), shows up in the expired set, and a
// review re-instates it and stamps the reviewer.
func TestPGRepo_SuppressionExpiryAndReview(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	svc := NewService(NewPGRepo(pool))
	id := "it-exp-" + time.Now().Format("150405.000000")
	soon := "it-soon-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM finding_suppressions WHERE finding_id IN ($1, $2)", id, soon)
		require.NoError(t, err)
	})

	expiry := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Microsecond)
	sup, err := svc.SuppressUntil(ctx, id, "accepted risk", "admin@b.example", expiry)
	require.NoError(t, err)
	require.True(t, expiry.Equal(sup.ExpiresAt))
	require.True(t, sup.LastReviewedAt.IsZero(), "NULL last_reviewed_at reads as never reviewed")
	require.Empty(t, sup.ReviewedBy)

	// Lapse it behind the service's back, as the clock would.
	_, err = pool.Exec(ctx, "UPDATE finding_suppressions SET expires_at = now() - interval '1 hour' WHERE finding_id = $1", id)
	require.NoError(t, err)

	got, err := svc.IsSuppressed(ctx, id)
	require.NoError(t, err)
	require.False(t, got, "an expired suppression stops matching")
	active, expired, err := svc.SuppressionStates(ctx)
	require.NoError(t, err)
	require.NotContains(t, active, id)
	require.Contains(t, expired, id, "the expired row is kept so the finding can say so")

	renewed := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Microsecond)
	sup, err = svc.Review(ctx, id, "carol@b.example", renewed)
	require.NoError(t, err)
	require.True(t, renewed.Equal(sup.ExpiresAt))
	require.Equal(t, "carol@b.example", sup.ReviewedBy)
	require.False(t, sup.LastReviewedAt.IsZero())
	require.Equal(t, "accepted risk", sup.Reason)
	got, err = svc.IsSuppressed(ctx, id)
	require.NoError(t, err)
	require.True(t, got, "renewal re-instates it")

	_, err = svc.Review(ctx, "it-never-suppressed", "carol@b.example", renewed)
	require.ErrorIs(t, err, ErrNotFound)

	// The expiry notice picks up a suppression inside the 14-day window, not one
	// outside it, and announces each expiry once.
	_, err = svc.SuppressUntil(ctx, soon, "temporary", "admin@b.example", time.Now().Add(3*24*time.Hour))
	require.NoError(t, err)
	due, err := svc.ExpiryNoticesDue(ctx)
	require.NoError(t, err)
	require.Contains(t, findingIDs(due), soon)
	require.NotContains(t, findingIDs(due), id, "a 90-day expiry is outside the notice window")

	require.NoError(t, svc.MarkExpiryNoticesSent(ctx, []string{soon}))
	due, err = svc.ExpiryNoticesDue(ctx)
	require.NoError(t, err)
	require.NotContains(t, findingIDs(due), soon, "an announced expiry is not due again")

	_, err = svc.Review(ctx, soon, "carol@b.example", time.Now().Add(5*24*time.Hour))
	require.NoError(t, err)
	due, err = svc.ExpiryNoticesDue(ctx)
	require.NoError(t, err)
	require.Contains(t, findingIDs(due), soon, "moving the expiry clears the notice")
}
