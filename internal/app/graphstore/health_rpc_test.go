package graphstore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
)

// The serve pod reads the worker's build state through explore.LadybugRPCRepo.
// Round-trip it against the real internal handler: before a build the worker
// must report not ready with no build time (the serve pod used to show
// last_rebuilt: now), and after one, ready with the real build time.
func TestInternalHealth_RoundTripsThroughRPCRepo(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()
	mux := http.NewServeMux()
	NewHandler(svc).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	rpc := explore.NewLadybugRPCRepo(srv.URL, "")

	hl, err := rpc.GraphHealth(ctx)
	require.NoError(t, err)
	require.False(t, hl.Ready)
	require.True(t, hl.LastBuiltAt.IsZero(), "never built must not read as a build time")
	_, known := hl.MultiHopMayBeIncomplete()
	require.False(t, known, "never built: the multi-hop guard is unknown, not clean")

	assets, edges, sigs := digestFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))

	hl, err = rpc.GraphHealth(ctx)
	require.NoError(t, err)
	require.True(t, hl.Ready)
	require.Positive(t, hl.NodeCount)
	require.True(t, hl.LastBuiltAt.Equal(svc.LastBuiltAt()), "the worker's own build time crosses the RPC")

	incomplete, known := hl.MultiHopMayBeIncomplete()
	require.True(t, known)
	require.False(t, incomplete)

	nAssets, _, _, err := rpc.NodeCounts(ctx)
	require.NoError(t, err)
	require.Positive(t, nAssets)

	// The upgraded worker must not send legacy incomplete warnings just
	// because a table spans more than one storage node group.
	svc.mu.Lock()
	svc.publishNodeTableRows(map[string]int64{NodePackage: LadybugNodeGroupRows + 1})
	svc.mu.Unlock()
	hl, err = rpc.GraphHealth(ctx)
	require.NoError(t, err)
	incomplete, known = hl.MultiHopMayBeIncomplete()
	require.True(t, known)
	require.False(t, incomplete)
	require.Empty(t, hl.OversizedNodeTables)
	res, err := rpc.RunCypher(ctx, `MATCH (n:Asset) RETURN n LIMIT 1`, 10, 10)
	require.NoError(t, err)
	require.False(t, res.MultiHopMayBeIncomplete)
}
