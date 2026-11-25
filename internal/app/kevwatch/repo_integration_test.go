//go:build integration

package kevwatch

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

const pgDSN = "postgres://graph:graph@localhost:5432/graph?sslmode=disable"

// Requires `docker compose up` and applied migrations (graph migrate).
func TestPGRepo_CatalogAndAdditions(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool)

	prefix := "CVE-IT-" + time.Now().Format("150405.000000") + "-"
	t.Cleanup(func() {
		for _, table := range []string{"kev_catalog", "kev_added_events"} {
			_, err := pool.Exec(ctx, "DELETE FROM "+table+" WHERE cve_id LIKE $1", prefix+"%")
			require.NoError(t, err)
		}
	})
	added := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	a, b := prefix+"A", prefix+"B"

	inserted, err := repo.Commit(ctx,
		[]Entry{{CVEID: a, DateAdded: added, Name: "first"}, {CVEID: b}},
		[]Addition{{CVEID: a, DateAdded: added, Name: "first", OpenFindings: 5}, {CVEID: b}})
	require.NoError(t, err)
	require.Len(t, inserted, 2)
	byID := map[string]Addition{}
	for _, x := range inserted {
		byID[x.CVEID] = x
	}
	require.Equal(t, added, byID[a].DateAdded)
	require.Equal(t, 5, byID[a].OpenFindings)
	require.False(t, byID[a].DetectedAt.IsZero())
	require.True(t, byID[b].DateAdded.IsZero(), "an unknown dateAdded round-trips as unknown (NULL)")

	known, err := repo.KnownCVEs(ctx)
	require.NoError(t, err)
	require.True(t, known[a])
	require.True(t, known[b])

	var storedNull bool
	require.NoError(t, pool.QueryRow(ctx, "SELECT date_added IS NULL FROM kev_catalog WHERE cve_id = $1", b).Scan(&storedNull))
	require.True(t, storedNull)

	// The same additions again (a retried refresh) insert nothing, and a
	// changed name refreshes the catalog row in place.
	again, err := repo.Commit(ctx,
		[]Entry{{CVEID: a, DateAdded: added, Name: "renamed"}},
		[]Addition{{CVEID: a, OpenFindings: 99}})
	require.NoError(t, err)
	require.Empty(t, again)
	var name string
	require.NoError(t, pool.QueryRow(ctx, "SELECT name FROM kev_catalog WHERE cve_id = $1", a).Scan(&name))
	require.Equal(t, "renamed", name)

	list, err := repo.ListAdditions(ctx, MaxListLimit)
	require.NoError(t, err)
	var mine []Addition
	for _, x := range list {
		if x.CVEID == a || x.CVEID == b {
			mine = append(mine, x)
		}
	}
	require.Len(t, mine, 2)
	for _, x := range mine {
		if x.CVEID == a {
			require.Equal(t, 5, x.OpenFindings, "the first record stands")
		}
	}
}
