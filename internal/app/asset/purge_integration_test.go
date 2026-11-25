//go:build integration

package asset

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// TestCHRepo_PurgeEdgesForAssets is the regression guard for the account-purge
// dangling-edges gap: PurgeAccount only ever touched the assets table, leaving
// graph_edges rows referencing a purged account's assets to sit in ClickHouse
// (passing every reader's 48h freshness filter, then the full edge TTL)
// presenting phantom attack paths for an account that no longer exists.
//
// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_PurgeEdgesForAssets(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	p := "it-purge-" + time.Now().Format("150405.000000") + "-"
	role, secret, unrelated := p+"role", p+"secret", p+"unrelated"
	now := time.Now().Truncate(time.Second)

	assets := []Asset{
		{ID: role, Name: "role", Type: "iam_role", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
		{ID: secret, Name: "secret", Type: "secretsmanager_secret", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
		{ID: unrelated, Name: "unrelated", Type: "iam_role", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
	}
	edges := []Edge{
		// Both endpoints belong to the purged account — must be deleted.
		{SrcID: role, SrcType: "iam_role", DstID: secret, DstType: "secretsmanager_secret", EdgeType: "accesses_secret"},
		// Only src belongs to the purged account (dst is a dangling reference
		// to something never collected) — src IN the list is still enough.
		{SrcID: role, SrcType: "iam_role", DstID: p + "ghost", DstType: "iam_role", EdgeType: "can_assume"},
		// Neither endpoint belongs to the purged account — must survive.
		{SrcID: unrelated, SrcType: "iam_role", DstID: unrelated, DstType: "iam_role", EdgeType: "can_assume"},
	}
	require.NoError(t, svc.Ingest(ctx, assets, edges))

	n, err := repo.PurgeEdgesForAssets(ctx, []string{role, secret})
	require.NoError(t, err)
	require.Equal(t, 2, n, "both edges touching role/secret must be counted and deleted")

	// ClickHouse ALTER TABLE ... DELETE is an async mutation — give it a moment.
	require.Eventually(t, func() bool {
		rem, err := repo.EdgesFrom(ctx, []string{role})
		return err == nil && len(rem) == 0
	}, 15*time.Second, 200*time.Millisecond, "role's outgoing edges must be gone")

	survivors, err := repo.EdgesFrom(ctx, []string{unrelated})
	require.NoError(t, err)
	require.Len(t, survivors, 1, "the unrelated account's own edge must survive untouched")
}

// TestCHRepo_PurgeEdgesForAssets_ChunkBoundaryNotDoubleCounted is the
// regression guard for a chunk-boundary double-count: counting PER CHUNK,
// after already issuing the PREVIOUS chunk's delete mutation. An edge with one
// endpoint in chunk 1 and the other in chunk 2 would still be physically present
// (ClickHouse's ALTER TABLE ... DELETE is an async mutation with no
// synchronous completion guarantee) when chunk 2's count ran, so it would be
// counted a second time — inflating the returned total without leaving
// anything undeleted, but the count itself is the one number an admin reads
// to confirm a purge worked. Fixed by counting entirely before any chunk's
// delete runs.
//
// The count queries themselves are now ALSO chunked (an
// unchunked count() over a large account's full id list risks the same
// max_query_size failure as an unchunked DELETE — see purgeEdgeChunk's doc
// comment), which reintroduces the exact same cross-chunk double-match this
// test guards against, just at the count-query level instead of the
// count-vs-delete-ordering level: chunk 1's OR matches the edge via src_id,
// chunk 2's OR matches it via dst_id. Deduping by (src_id, dst_id, edge_type)
// in a Go set (rather than summing each chunk's count()) is what still makes
// this test pass.
func TestCHRepo_PurgeEdgesForAssets_ChunkBoundaryNotDoubleCounted(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)
	svc := NewService(repo)

	p := "it-purge-chunk-" + time.Now().Format("150405.000000") + "-"
	first, last := p+"first", p+"last"
	now := time.Now().Truncate(time.Second)

	require.NoError(t, svc.Ingest(ctx, []Asset{
		{ID: first, Name: "first", Type: "iam_role", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
		{ID: last, Name: "last", Type: "iam_role", Provider: ProviderAWS, DiscoveredAt: now, LastSeen: now},
	}, []Edge{
		// The one edge straddling what will be the chunk-1/chunk-2 boundary below.
		{SrcID: first, SrcType: "iam_role", DstID: last, DstType: "iam_role", EdgeType: "can_assume"},
	}))

	// ids' first and last elements are the two real assets; everything in
	// between is padding so the real IDs land in different purgeEdgeChunk-sized
	// chunks.
	ids := make([]string, purgeEdgeChunk+1)
	ids[0] = first
	for i := 1; i < len(ids)-1; i++ {
		ids[i] = p + "pad" + strconv.Itoa(i)
	}
	ids[len(ids)-1] = last

	n, err := repo.PurgeEdgesForAssets(ctx, ids)
	require.NoError(t, err)
	require.Equal(t, 1, n, "the one edge spanning the chunk boundary must be counted exactly once, not once per chunk it touches")
}
