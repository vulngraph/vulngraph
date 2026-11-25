package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMergeWorksInLadybug pins the engine's MERGE semantics through the Go
// write API: MERGE creates a missing node, updates a matched one in place, and
// never duplicates a key. Production node loads use COPY into a fresh engine,
// but sentinel seeding (seedSentinels in repo.go) relies on MERGE being
// idempotent, so an engine upgrade that changes these semantics fails here.
func TestMergeWorksInLadybug(t *testing.T) {
	svc, err := Open("", 256, 0, 0, "")
	require.NoError(t, err, "open in-memory Ladybug")
	defer svc.Close()

	svc.mu.Lock()
	db := svc.db
	svc.mu.Unlock()
	require.NotNil(t, db, "Ladybug db not initialised")

	wc, err := db.newWriteConn()
	require.NoError(t, err, "write conn")
	defer wc.Close()

	exec := func(t *testing.T, q string) {
		t.Helper()
		res, err := wc.Query(q)
		require.NoError(t, err, q)
		if res != nil {
			res.Close()
		}
	}
	scalar := func(t *testing.T, q, col string) any {
		t.Helper()
		res, err := wc.Query(q)
		require.NoError(t, err, q)
		defer res.Close()
		require.True(t, res.HasNext(), "no row for %s", q)
		row, err := res.Next()
		require.NoError(t, err)
		defer row.Close()
		m, err := row.GetAsMap()
		require.NoError(t, err)
		return m[col]
	}

	t.Run("MERGE_creates_node", func(t *testing.T) {
		exec(t, "MERGE (a:Asset {id: 'test-merge-1'}) SET a.name = 'initial', a.type = 'test'")
		require.Equal(t, "initial", scalar(t, "MATCH (a:Asset {id: 'test-merge-1'}) RETURN a.name AS name", "name"))
	})

	t.Run("MERGE_updates_existing_node", func(t *testing.T) {
		exec(t, "MERGE (a:Asset {id: 'test-merge-1'}) SET a.name = 'updated'")
		require.Equal(t, "updated", scalar(t, "MATCH (a:Asset {id: 'test-merge-1'}) RETURN a.name AS name", "name"))
	})

	t.Run("MERGE_dedup_count", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			exec(t, "MERGE (a:Asset {id: 'test-merge-dedup'}) SET a.name = 'x', a.type = 'test'")
		}
		require.EqualValues(t, 1, scalar(t, "MATCH (a:Asset {id: 'test-merge-dedup'}) RETURN count(*) AS n", "n"))
	})
}
