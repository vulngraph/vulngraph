//go:build integration

package notify

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// SealedSecrets lists every channel's ciphertext, and ResealSecret is a
// compare-and-swap through the real SQL: it replaces a channel's secret only
// while the row still holds the ciphertext the caller read.
// Requires `docker compose up` and applied migrations.
func TestPGRepo_ResealSecretIsCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool, identityCipher{})

	created, err := repo.Create(ctx, Channel{
		Type: TypeWebhook, Name: "it-reseal-" + time.Now().Format("150405.000000"), WebhookURL: "https://example.com/h",
		Enabled: true, EventTypes: []EventType{EventFinding}, Severities: []string{},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Delete(ctx, created.ID) })

	sealed := func() []byte {
		t.Helper()
		all, err := repo.SealedSecrets(ctx)
		require.NoError(t, err)
		for _, s := range all {
			if s.ChannelID == created.ID {
				return s.Ciphertext
			}
		}
		t.Fatalf("channel %s missing from SealedSecrets", created.ID)
		return nil
	}
	original := sealed()
	require.NotEmpty(t, original)

	swapped, err := repo.ResealSecret(ctx, created.ID, []byte("not the stored ciphertext"), []byte("resealed-a"))
	require.NoError(t, err)
	require.False(t, swapped, "a stale read must not overwrite the row")
	require.Equal(t, original, sealed())

	swapped, err = repo.ResealSecret(ctx, created.ID, original, []byte("resealed-b"))
	require.NoError(t, err)
	require.True(t, swapped)
	require.Equal(t, []byte("resealed-b"), sealed())

	swapped, err = repo.ResealSecret(ctx, created.ID, original, []byte("resealed-c"))
	require.NoError(t, err)
	require.False(t, swapped, "the old ciphertext no longer matches once resealed")
	require.Equal(t, []byte("resealed-b"), sealed())
}
