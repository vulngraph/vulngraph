package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// An asset ID carrying a COPY delimiter or line break used to fail every
// rebuild: the node row's id was sanitized but the rel row's endpoint was not,
// so COPY could not resolve the endpoint ("Unable to find primary key value").
// Such a row is now dropped and counted, and the rest of the graph loads.
func TestBulkSyncCopy_UnsafeIDsDropNotAbort(t *testing.T) {
	_, wc := openTestDB(t)
	unsafe := []string{"lb|pipe", "lb\nnewline", "lb\rcr"}
	assets := []asset.Asset{
		{ID: "role-1", Name: "admin", Type: "iam_role", Provider: "aws"},
		{ID: "lb-ok", Name: "ok", Type: "load_balancer", Provider: "aws"},
	}
	edges := []asset.Edge{
		{SrcID: "lb-ok", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role", EdgeType: "has_role"},
	}
	for _, id := range unsafe {
		assets = append(assets, asset.Asset{ID: id, Name: "x", Type: "load_balancer", Provider: "aws"})
		edges = append(edges, asset.Edge{SrcID: id, SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role", EdgeType: "has_role"})
	}

	stats, err := bulkSyncCopy(context.Background(), wc, assets, edges, newReachOverlay(edges), nil, true, 1, nil)
	require.NoError(t, err, "one bad id must not abort the whole rebuild")
	require.Equal(t, len(unsafe), stats.droppedUnsafeID)
	require.Equal(t, 1, stats.edgesLoaded)
	require.Equal(t, len(unsafe), stats.droppedEndpointMiss, "edges to a dropped node are dropped, not COPY'd")
	require.EqualValues(t, 1, countQuery(t, wc, "MATCH (:Asset {id:'lb-ok'})-[r]->(:IamRole {id:'role-1'}) RETURN count(r)"))
	require.EqualValues(t, 0, countQuery(t, wc, "MATCH (n:Asset) WHERE n.id STARTS WITH 'lb ' RETURN count(n)"),
		"no sanitized look-alike id may be loaded in place of the real one")
}
