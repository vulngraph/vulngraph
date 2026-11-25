package explore

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// chunkIDs guards the cross-verification sweep finding: Neighbors is
// fed a traversal frontier capped at hardMaxNodes=2000 (explore/service.go), and
// explore's ids are commonly AWS ARNs (80-120+ bytes) — 2000 of them unchunked
// risks the ClickHouse max_query_size failure that internal/app/asset/optimize.go's
// VerifyExpiredEphemeral guards against, except user-facing (Explore UI, MCP
// run_cypher, NL→Cypher) rather than a batch job.
func TestChunkIDs_SplitsIntoIDChunkSizeBatches(t *testing.T) {
	ids := make([]string, 2*idChunkSize+37)
	for i := range ids {
		ids[i] = fmt.Sprintf("arn:aws:iam::123456789012:role/some-long-role-name-%d", i)
	}

	chunks := chunkIDs(ids)

	require.Len(t, chunks, 3, "2*idChunkSize+37 ids must split into 3 chunks, not one unbounded batch")
	require.Len(t, chunks[0], idChunkSize)
	require.Len(t, chunks[1], idChunkSize)
	require.Len(t, chunks[2], 37)

	var flat []string
	for _, c := range chunks {
		flat = append(flat, c...)
	}
	require.Equal(t, ids, flat, "chunking must not drop, reorder, or duplicate any id")
}

func TestChunkIDs_EmptyAndUnderSizeInputs(t *testing.T) {
	require.Nil(t, chunkIDs(nil))
	require.Len(t, chunkIDs([]string{"a", "b"}), 1)
}

// TestSeedReadersApplyInventoryGate mirrors asset.TestAssetReadersApplyLiveness
// for the graph's ClickHouse fallback tier: the fallback is taken for
// any node Ladybug pruned — routine, not outage-only — so an ungated seed read
// resurrects dead pods/containers and IaC declared_* rows as live graph nodes,
// the same corpse-read the Assets page was fixed for.
func TestSeedReadersApplyInventoryGate(t *testing.T) {
	for name, q := range map[string]string{
		"seedByIDs":   seedByIDs,
		"seedByMatch": seedByMatch,
	} {
		require.Contains(t, q, asset.EphemeralLivenessCond,
			"%s reads the raw assets table for UI-facing graph nodes and must exclude dead ephemeral resources", name)
		require.Contains(t, q, "declared_cloud_identity",
			"%s must exclude the IaC declaration types (asset.InventoryReadCond)", name)
	}
}
