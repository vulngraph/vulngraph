package graphstore

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignalDeltaWritesOnlyChangedOrClearedNodes(t *testing.T) {
	_, _, signals := signalFixture()
	svc, _, _ := openSynced(t, signals)
	ctx := context.Background()
	require.NoError(t, svc.RefreshSignals(ctx, stubSignals{signals}))
	rows, _ := svc.SignalRefreshStats()
	require.Zero(t, rows, "identical signals must not issue native writes")
	// Mutate the original map to prove the successful-write baseline owns a copy.
	sig := signals["lb-1"]
	sig.MaxScore = 99
	signals["lb-1"] = sig
	require.NoError(t, svc.RefreshSignals(ctx, stubSignals{signals}))
	rows, _ = svc.SignalRefreshStats()
	require.EqualValues(t, 1, rows)
	require.Equal(t, 99, cachedSignals(t, svc, "lb-1").MaxScore)
	require.ElementsMatch(t, []string{"lb-1", "role-1"}, kevIDs(t, svc))
	delete(signals, "role-1")
	require.NoError(t, svc.RefreshSignals(ctx, stubSignals{signals}))
	rows, _ = svc.SignalRefreshStats()
	require.EqualValues(t, 1, rows, "resolving findings must clear their former node")
	require.Equal(t, []string{"lb-1"}, kevIDs(t, svc))
	require.False(t, cachedSignals(t, svc, "role-1").HasKEV)
	// Inventory-only package updates change package query seeds, not native rows.
	signals["pkg:npm/test@1"] = NodeSignals{HasKEV: true, MaxScore: 95, CveID: "CVE-2026-12345"}
	require.NoError(t, svc.RefreshSignals(ctx, stubSignals{signals}))
	rows, _ = svc.SignalRefreshStats()
	require.Zero(t, rows)
	require.True(t, cachedSignals(t, svc, "pkg:npm/test@1").HasKEV)
}

func TestSignalDeltaRepairsUnknownStateEvenWhenInputReverts(t *testing.T) {
	_, _, signals := signalFixture()
	svc, _, _ := openSynced(t, signals)
	ctx := context.Background()
	// Simulate a partial native write whose overall operation failed. The next
	// input can equal the old baseline, so ordinary diffing alone is unsafe.
	wc, err := svc.db.newWriteConn()
	require.NoError(t, err)
	res, err := wc.Query(`MATCH (n:Asset {id:'lb-1'}) SET n.has_kev=0`)
	require.NoError(t, err)
	res.Close()
	wc.Close()
	svc.signalsDirty = true
	require.NoError(t, svc.RefreshSignals(ctx, stubSignals{signals}))
	rows, _ := svc.SignalRefreshStats()
	require.EqualValues(t, 2, rows, "unknown native state requires repairing every loaded signal node")
	require.ElementsMatch(t, []string{"lb-1", "role-1"}, kevIDs(t, svc))
	require.False(t, svc.signalsDirty)
}

func TestSignalDeltaRejectsMissingProjection(t *testing.T) {
	_, _, signals := signalFixture()
	svc, _, _ := openSynced(t, signals)
	svc.blastAdj.Store(nil)
	require.Error(t, svc.RefreshSignals(context.Background(), stubSignals{signals}))
	require.Nil(t, svc.lastDigest.Load())
}
