//go:build integration

package pkginv

import (
	"cmp"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/apikey"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires Postgres with migrations applied (graph migrate); GRAPH_TEST_PG_DSN
// points at another database than the compose one.
func TestPGRepo_ReplaceBySource(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, cmp.Or(os.Getenv("GRAPH_TEST_PG_DSN"), "postgres://graph:graph@localhost:5432/graph?sslmode=disable"), db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	email := "pkginv-it-" + time.Now().Format("150405.000000") + "@example.com"
	user, err := auth.NewPGRepo(pool, nil).CreateUser(ctx, email, "fake-hash", auth.RoleAdmin)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM users WHERE email = $1", email) })
	exp := time.Now().Add(time.Hour)
	keys := apikey.NewPGRepo(pool)
	keyA, _, err := keys.Create(ctx, user.ID, "a", apikey.ScopeInventory, &exp)
	require.NoError(t, err)
	keyB, _, err := keys.Create(ctx, user.ID, "b", apikey.ScopeInventory, &exp)
	require.NoError(t, err)
	got, err := keys.List(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, apikey.ScopeInventory, got[0].Scopes, "the inventory scope round-trips through Postgres")

	repo := NewPGRepo(pool)
	at := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	rec := func(key apikey.APIKey, asset string, observed time.Time, known bool) InventoryRecord {
		return InventoryRecord{
			Source: SourceKey(key.ID, "acme-agent"), AssetID: asset, APIKeyID: key.ID,
			Scanner: Scanner{Name: "acme-agent", Version: "1.0"}, OS: OS{ID: "ubuntu", VersionID: "22.04"},
			Ecosystem: "Ubuntu:22.04:LTS", ObservedAt: observed, ReceivedAt: observed, Complete: known,
			PackageCount: 3, Covered: []Covered{{Path: "/"}}, InventoryKnown: known, CVEMatchableKnown: known,
		}
	}
	a1 := rec(keyA, "i-it-1", at, true)

	require.NoError(t, repo.Upsert(ctx, a1))
	stored, found, err := repo.Get(ctx, a1.Source, a1.AssetID)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, a1, stored)

	t.Run("the same claim twice is idempotent", func(t *testing.T) {
		require.NoError(t, repo.Upsert(ctx, a1))
	})
	t.Run("a newer claim replaces, an older one is rejected untouched", func(t *testing.T) {
		newer := rec(keyA, "i-it-1", at.Add(time.Hour), false)
		newer.Gap = GapIncomplete
		require.NoError(t, repo.Upsert(ctx, newer))
		require.ErrorIs(t, repo.Upsert(ctx, rec(keyA, "i-it-1", at.Add(-time.Hour), true)), ErrStale)
		stored, _, err := repo.Get(ctx, a1.Source, a1.AssetID)
		require.NoError(t, err)
		require.Equal(t, newer, stored)
	})
	t.Run("sources are isolated and ListForAssets sees all", func(t *testing.T) {
		require.NoError(t, repo.Upsert(ctx, rec(keyB, "i-it-1", at.Add(-2*time.Hour), true)))
		recs, err := repo.ListForAssets(ctx, []string{"i-it-1", "i-it-none"})
		require.NoError(t, err)
		require.Len(t, recs, 2)
		stored, _, err := repo.Get(ctx, a1.Source, a1.AssetID)
		require.NoError(t, err)
		require.Equal(t, at.Add(time.Hour), stored.ObservedAt, "key B did not touch key A's claim")
	})
	t.Run("an empty covered list round-trips", func(t *testing.T) {
		r := rec(keyA, "i-it-2", at, true)
		r.Covered = nil
		require.NoError(t, repo.Upsert(ctx, r))
		stored, _, err := repo.Get(ctx, r.Source, r.AssetID)
		require.NoError(t, err)
		require.Empty(t, stored.Covered)
	})
	t.Run("a missing claim is not found", func(t *testing.T) {
		_, found, err := repo.Get(ctx, "byoa:none:x", "i-it-1")
		require.NoError(t, err)
		require.False(t, found)
	})
	t.Run("revoking a key removes its claims, never leaving them to read as clean", func(t *testing.T) {
		require.NoError(t, keys.Delete(ctx, keyB.ID, user.ID))
		_, found, err := repo.Get(ctx, SourceKey(keyB.ID, "acme-agent"), "i-it-1")
		require.NoError(t, err)
		require.False(t, found)
	})
	t.Run("forget tombstones are readable", func(t *testing.T) {
		gone := at.Add(-time.Hour)
		_, err := pool.Exec(ctx, `INSERT INTO forget_tombstones (asset_id, connector_id, scope, asset_type, last_seen, believed_gone_at)
			VALUES ('i-it-tomb', 'c', 's', 'ec2_instance', $1, $1)`, gone)
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = pool.Exec(ctx, "DELETE FROM forget_tombstones WHERE asset_id = 'i-it-tomb'") })
		out, err := forget.NewPGRepo(pool).Tombstones(ctx, []string{"i-it-tomb", "i-it-1"})
		require.NoError(t, err)
		require.Len(t, out, 1)
		require.True(t, out["i-it-tomb"].Equal(gone))
	})
}
