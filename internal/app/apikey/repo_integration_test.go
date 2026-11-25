//go:build integration

package apikey

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_VerifyEnforcesExpiry(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, testPGDSN(), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	suffix := time.Now().Format("150405.000000")
	email := "apikey-it-" + suffix + "@example.com"
	user, err := auth.NewPGRepo(pool, nil).CreateUser(ctx, email, "fake-hash", auth.RoleAdmin) // CreateUser never uses the TOTP cipher
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM api_keys WHERE user_id = $1", user.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email)
	})

	repo := NewPGRepo(pool)

	// A valid (unexpired) key authenticates.
	future := time.Now().Add(time.Hour)
	_, validPlain, err := repo.Create(ctx, user.ID, "valid", ScopeRead, &future)
	require.NoError(t, err)
	got, err := repo.Verify(ctx, validPlain)
	require.NoError(t, err)
	require.Equal(t, ScopeRead, got.Scopes)
	require.Equal(t, email, got.OwnerEmail, "the owner, not the key name, is the principal")
	require.Equal(t, "admin", got.OwnerRole)
	require.WithinDuration(t, user.CreatedAt, got.OwnerCreatedAt, time.Second,
		"the owner's account age rides along for the executor's approver check")
	require.WithinDuration(t, user.AdminSince, got.OwnerAdminSince, time.Second,
		"so does when the owner became admin")

	// An expired key must NOT authenticate, even though lookup_id+hash still match.
	past := time.Now().Add(-time.Hour)
	_, expiredPlain, err := repo.Create(ctx, user.ID, "expired", ScopeRead, &past)
	require.NoError(t, err)
	_, err = repo.Verify(ctx, expiredPlain)
	require.ErrorIs(t, err, ErrNotFound)

	// A key with no expiry (nil) authenticates indefinitely.
	_, foreverPlain, err := repo.Create(ctx, user.ID, "forever", ScopeAdmin, nil)
	require.NoError(t, err)
	_, err = repo.Verify(ctx, foreverPlain)
	require.NoError(t, err)

	// A disabled owner's keys stop authenticating.
	_, err = pool.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", user.ID)
	require.NoError(t, err)
	_, err = repo.Verify(ctx, validPlain)
	require.ErrorIs(t, err, ErrNotFound)
}

// Only the full key authenticates: a plaintext that shares a real key's
// lookup_id but not its secret part is rejected, a revoked key is rejected,
// and deleting the owning user revokes their keys.
func TestPGRepo_LookupIDNeedsTheSecretAndUserCascade(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, testPGDSN(), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	email := "apikey-cascade-" + time.Now().Format("150405.000000") + "@example.com"
	user, err := auth.NewPGRepo(pool, nil).CreateUser(ctx, email, "fake-hash", auth.RoleAdmin) // CreateUser never uses the TOTP cipher
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email) })

	repo := NewPGRepo(pool)
	created, fresh, err := repo.Create(ctx, user.ID, "fresh", ScopeRead, nil)
	require.NoError(t, err)
	var stored string
	require.NoError(t, pool.QueryRow(ctx, "SELECT key_hash FROM api_keys WHERE id = $1", created.ID).Scan(&stored))
	require.Equal(t, hashKey(fresh), stored, "the row holds the key's SHA-256 digest, never the key")

	first, err := repo.Verify(ctx, fresh)
	require.NoError(t, err)
	require.NotNil(t, first.LastUsedAt)
	second, err := repo.Verify(ctx, fresh)
	require.NoError(t, err)
	require.WithinDuration(t, *first.LastUsedAt, *second.LastUsedAt, time.Microsecond,
		"a key used again within lastUsedResolution does not rewrite last_used_at")

	revoked, revokedPlain, err := repo.Create(ctx, user.ID, "revoked", ScopeRead, nil)
	require.NoError(t, err)
	require.NoError(t, repo.Delete(ctx, revoked.ID, user.ID))
	_, err = repo.Verify(ctx, revokedPlain)
	require.ErrorIs(t, err, ErrNotFound, "a revoked key must stop working")

	forged := []byte(fresh)
	for i := lookupIDLen; i < len(forged); i++ {
		forged[i] = '0'
	}
	_, err = repo.Verify(ctx, string(forged))
	require.ErrorIs(t, err, ErrNotFound, "a matching lookup_id without the secret must not authenticate")

	_, err = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	require.NoError(t, err)
	_, err = repo.Verify(ctx, fresh)
	require.ErrorIs(t, err, ErrNotFound, "a deleted user's keys must stop working")
}

// testPGDSN is the compose Postgres; GRAPH_TEST_PG_DSN points the test at another database.
func testPGDSN() string {
	if v := os.Getenv("GRAPH_TEST_PG_DSN"); v != "" {
		return v
	}
	return "postgres://graph:graph@localhost:5432/graph?sslmode=disable"
}
