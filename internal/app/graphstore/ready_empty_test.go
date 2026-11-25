package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// A fresh install has no assets. One empty build could be a ClickHouse blip, so it
// must not report ready; the same empty graph a sweep later is the estate, and the
// worker has to come up healthy or `docker compose up --wait` never returns.
func TestReady_EmptyEstateIsReadyOnceConfirmed(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	src := &fidelityEdges{res: asset.EdgeSyncResult{}}
	sync := func(assets []asset.Asset) {
		t.Helper()
		require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil}))
	}

	sync(nil)
	require.False(t, svc.Ready(), "one empty build is indistinguishable from a blip")

	sync(nil)
	require.True(t, svc.Ready(), "the same empty graph twice is an empty estate")

	sync([]asset.Asset{{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50}})
	require.True(t, svc.Ready())
	require.False(t, svc.emptyConfirmed.Load(), "a populated graph no longer relies on the empty confirmation")
}
