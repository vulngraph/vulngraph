//go:build integration

package govern

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_LinkNonceIsSingleUse(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool)

	nonce, err := newLinkNonce()
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM approval_link_nonces WHERE nonce = $1", nonce) })

	spent, err := repo.Spent(ctx, nonce)
	require.NoError(t, err)
	require.False(t, spent)

	first, err := repo.Consume(ctx, nonce, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.True(t, first)

	first, err = repo.Consume(ctx, nonce, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.False(t, first, "a replay is refused")

	spent, err = repo.Spent(ctx, nonce)
	require.NoError(t, err)
	require.True(t, spent)
}
