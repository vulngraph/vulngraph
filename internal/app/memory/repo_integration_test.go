//go:build integration

package memory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_RecordAndConfidence(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	svc := NewService(NewPGRepo(pool))

	// Unique action class per run so concurrent/repeat runs don't mix outcomes.
	class := "patch-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM action_outcomes WHERE action_class = $1", class)
	})

	now := time.Now()
	for i := 0; i < 9; i++ {
		require.NoError(t, svc.Record(ctx, Outcome{ActionClass: class, AssetType: "ec2_instance", Success: true, OccurredAt: now}))
	}
	require.NoError(t, svc.Record(ctx, Outcome{ActionClass: class, AssetType: "ec2_instance", Success: false, OccurredAt: now}))

	c, err := svc.Confidence(ctx, class, "ec2_instance")
	require.NoError(t, err)
	require.Equal(t, 10, c.SampleCount)
	require.Equal(t, BandHigh, c.Band)
	require.InDelta(t, 0.9, c.Score, 0.05)

	// A different asset type has no outcomes — escalate.
	other, err := svc.Confidence(ctx, class, "gce_instance")
	require.NoError(t, err)
	require.Equal(t, BandInsufficient, other.Band)
}

// A retried decision or a repeated verdict must not add a second sample for
// the same judgment: the dedupe key makes the insert idempotent.
func TestPGRepo_RecordIsIdempotentPerDedupeKey(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	svc := NewService(NewPGRepo(pool))

	class := "dedupe-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM action_outcomes WHERE action_class = $1", class)
	})

	o := Outcome{ActionClass: class, AssetType: "s3_bucket", Success: true, DedupeKey: class + ":f1:fp1"}
	require.NoError(t, svc.Record(ctx, o))
	require.NoError(t, svc.Record(ctx, o), "a duplicate is dropped, not an error")
	require.NoError(t, svc.Record(ctx, Outcome{ActionClass: class, AssetType: "s3_bucket", Success: true}))
	require.NoError(t, svc.Record(ctx, Outcome{ActionClass: class, AssetType: "s3_bucket", Success: true}))

	c, err := svc.Confidence(ctx, class, "s3_bucket")
	require.NoError(t, err)
	require.Equal(t, 3, c.SampleCount, "one keyed row plus two unkeyed rows")
}
