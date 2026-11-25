//go:build integration

package connector

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// ResealConfig is a compare-and-swap through the real SQL: it replaces the
// sealed config only while the row still holds the ciphertext the caller
// read, so a rotation never overwrites a config written after its read.
// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_ResealConfigIsCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	cipher, err := NewCipher(testKey(t))
	require.NoError(t, err)
	repo := NewPGRepo(pool)
	created, err := NewService(repo, cipher).Create(ctx, TypeAWS, "it-reseal-"+time.Now().Format("150405.000000"),
		map[string]string{"role_arn": "arn:aws:iam::1:role/x", "region": "eu-west-1"}, "")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM connectors WHERE id = $1", created.ID)
		require.NoError(t, err)
	})
	sealed := func() []byte {
		t.Helper()
		got, err := repo.Get(ctx, created.ID)
		require.NoError(t, err)
		return got.ConfigCiphertext
	}
	original := sealed()
	require.NotEmpty(t, original)

	swapped, err := repo.ResealConfig(ctx, created.ID, []byte("not the stored ciphertext"), []byte("resealed-a"))
	require.NoError(t, err)
	require.False(t, swapped, "a stale read must not overwrite the row")
	require.Equal(t, original, sealed())

	swapped, err = repo.ResealConfig(ctx, created.ID, original, []byte("resealed-b"))
	require.NoError(t, err)
	require.True(t, swapped)
	require.Equal(t, []byte("resealed-b"), sealed())

	swapped, err = repo.ResealConfig(ctx, created.ID, original, []byte("resealed-c"))
	require.NoError(t, err)
	require.False(t, swapped, "the old ciphertext no longer matches once resealed")
	require.Equal(t, []byte("resealed-b"), sealed())

	swapped, err = repo.ResealConfig(ctx, "00000000-0000-0000-0000-000000000000", original, []byte("x"))
	require.NoError(t, err)
	require.False(t, swapped, "no row, no swap")
}
