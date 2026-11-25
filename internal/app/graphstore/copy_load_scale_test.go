package graphstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestBulkSyncCopyScale loads a graph at large scale (~140k nodes / ~500k
// edges) through the COPY loader and asserts it completes quickly — the whole
// point of Phase B. The old UNWIND…MATCH…CREATE path wedged for many minutes at this
// size; COPY must finish in seconds. Skipped under -short.
func TestBulkSyncCopyScale(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}

	const (
		nAssets   = 110_000 // generic Asset nodes
		nRoles    = 15_000  // IamRole nodes
		nPackages = 12_000  // Package nodes
		nRepos    = 1_000   // Repo nodes
	)

	assets := make([]asset.Asset, 0, nAssets+nRoles+nPackages+nRepos)
	for i := 0; i < nAssets; i++ {
		assets = append(assets, asset.Asset{
			ID: fmt.Sprintf("asset-%d", i), Name: fmt.Sprintf("svc-%d", i),
			Type: "load_balancer", Provider: asset.ProviderAWS, Region: "eu-west-1", // catch-all → NodeAsset
		})
	}
	for i := 0; i < nRoles; i++ {
		assets = append(assets, asset.Asset{
			ID: fmt.Sprintf("role-%d", i), Name: fmt.Sprintf("role-%d", i),
			Type: "iam_role", Provider: asset.ProviderAWS,
		})
	}
	for i := 0; i < nPackages; i++ {
		assets = append(assets, asset.Asset{
			ID: fmt.Sprintf("pkg-%d", i), Name: fmt.Sprintf("pkg-%d", i),
			Type: "package", Provider: asset.ProviderGitHub,
			Metadata: map[string]string{"ecosystem": "npm", "version": "1.0.0"},
		})
	}
	for i := 0; i < nRepos; i++ {
		assets = append(assets, asset.Asset{
			ID: fmt.Sprintf("repo-%d", i), Name: fmt.Sprintf("repo-%d", i),
			Type: "github_repo", Provider: asset.ProviderGitHub,
		})
	}

	// ~500k edges across kept rel types, all referencing valid typed endpoints.
	edges := make([]asset.Edge, 0, 510_000)
	edge := func(src, dst, typ string) {
		edges = append(edges, asset.Edge{SrcID: src, DstID: dst, EdgeType: typ,
			Properties: map[string]string{"via": "synthetic"}})
	}
	for i := 0; i < nAssets; i++ {
		edge(fmt.Sprintf("asset-%d", i), "internet", "exposed_to_internet")                  // 110k
		edge(fmt.Sprintf("asset-%d", i), fmt.Sprintf("role-%d", i%nRoles), "executes_as")    // 110k
		edge(fmt.Sprintf("asset-%d", i), fmt.Sprintf("pkg-%d", i%nPackages), "runs_package") // 110k
	}
	for i := 0; i < nRoles; i++ {
		edge(fmt.Sprintf("role-%d", i), fmt.Sprintf("role-%d", (i+1)%nRoles), "can_assume") // 15k
	}
	// SBOM: each repo depends on many packages → ~160k depends_on edges.
	for i := 0; i < nRepos; i++ {
		for j := 0; j < 160; j++ {
			edge(fmt.Sprintf("repo-%d", i), fmt.Sprintf("pkg-%d", (i*160+j)%nPackages), "depends_on")
		}
	}

	t.Logf("scale fixture: %d nodes, %d edges", len(assets), len(edges))

	cfg := newScaleService(t)
	db, err := openAndInit(cfg.bufferMB, cfg.poolSize, cfg.queryThreads)
	require.NoError(t, err)
	defer db.close()
	wc, err := db.newWriteConn()
	require.NoError(t, err)
	defer wc.Close()

	start := time.Now()
	_, copyErr := bulkSyncCopy(context.Background(), wc, assets, edges, newReachOverlay(edges), nil, true, 4, nil)
	require.NoError(t, copyErr)
	elapsed := time.Since(start)
	t.Logf("COPY bulk load of %d nodes / %d edges took %s", len(assets), len(edges), elapsed)

	// The old path took many minutes; COPY must be dramatically faster. Generous local bound.
	require.Less(t, elapsed, 90*time.Second, "COPY load too slow — possible regression toward the wedge")

	got := countQuery(t, wc, `MATCH (a:Asset) RETURN count(a)`)
	require.Positive(t, got)
}

// TestBulkSyncCopyScaleVerifiedExpiredCost measures what the verified-expiry
// check actually costs on top of the COPY load, at a large candidate
// population (tens of thousands of endpoint_absent rows
// across executes_as/deploys_to/targets). It is the answer to "does
// this add 30s to a multi-minute rebuild": the Go-side candidate-collection pass runs
// over the whole edge slice regardless of verifier presence, and the one bulk
// query it triggers is timed here via a stub that sleeps for a deliberately
// pessimistic round-trip (500ms — the 10s CHRepo timeout budget's low end
// for a batch of this size) rather than a real ClickHouse call, so this asserts
// the OVERHEAD floor, not a network-dependent wall-clock number.
func TestBulkSyncCopyScaleVerifiedExpiredCost(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test skipped under -short")
	}

	const (
		nAssets  = 40_000 // Asset nodes (k8s_service)
		nWorkers = 40_000 // K8sWorkload nodes actually loaded (the "live" pods)
		nDead    = 30_000 // referenced k8s_pod ids with NO asset row loaded — candidates
	)

	assets := make([]asset.Asset, 0, nAssets+nWorkers)
	for i := 0; i < nAssets; i++ {
		assets = append(assets, asset.Asset{
			ID: fmt.Sprintf("svc-%d", i), Name: fmt.Sprintf("svc-%d", i),
			Type: "k8s_service", Provider: asset.ProviderKubernetes,
		})
	}
	for i := 0; i < nWorkers; i++ {
		assets = append(assets, asset.Asset{
			ID: fmt.Sprintf("pod-%d", i), Name: fmt.Sprintf("pod-%d", i),
			Type: "k8s_pod", Provider: asset.ProviderKubernetes,
		})
	}

	edges := make([]asset.Edge, 0, nAssets*2)
	for i := 0; i < nAssets; i++ {
		// Half the fan-out targets a live pod (loads); half targets a dead one
		// (candidate for the verified-expiry check — never in the asset slice above).
		edges = append(edges, asset.Edge{
			SrcID: fmt.Sprintf("svc-%d", i), SrcType: "k8s_service",
			DstID: fmt.Sprintf("pod-%d", i%nWorkers), DstType: "k8s_pod",
			EdgeType: "targets", Properties: map[string]string{"via": "synthetic"},
		})
		edges = append(edges, asset.Edge{
			SrcID: fmt.Sprintf("svc-%d", i), SrcType: "k8s_service",
			DstID: fmt.Sprintf("dead-pod-%d", i%nDead), DstType: "k8s_pod",
			EdgeType: "targets", Properties: map[string]string{"via": "synthetic"},
		})
	}

	cfg := newScaleService(t)
	db, err := openAndInit(cfg.bufferMB, cfg.poolSize, cfg.queryThreads)
	require.NoError(t, err)
	defer db.close()
	wc, err := db.newWriteConn()
	require.NoError(t, err)
	defer wc.Close()

	var verifyCalls int
	var verifyIDs int
	verifier := func(_ context.Context, ids []string) (map[string]bool, error) {
		verifyCalls++
		verifyIDs = len(ids)
		time.Sleep(500 * time.Millisecond) // pessimistic stand-in for the real CH round trip
		out := make(map[string]bool, len(ids))
		for _, id := range ids {
			out[id] = true // every dead-pod-N id here really is a verified corpse
		}
		return out, nil
	}

	start := time.Now()
	stats, err := bulkSyncCopy(context.Background(), wc, assets, edges, newReachOverlay(edges), nil, true, 4, verifier)
	require.NoError(t, err)
	elapsed := time.Since(start)
	t.Logf("COPY bulk load with verified-expiry check: %d nodes / %d edges / %d candidate ids / %d verify call(s) took %s",
		len(assets), len(edges), verifyIDs, verifyCalls, elapsed)

	require.Equal(t, 1, verifyCalls, "one bulk verification call per build, never one per edge")
	require.LessOrEqual(t, verifyIDs, nDead, "candidates must be bounded to the distinct missing-endpoint ids, not the edge count")
	require.Equal(t, nAssets, stats.byType["targets"].endpointExpired,
		"every targets edge to a dead-pod-N id was verified, so all of them must classify as expired, not absent")
	require.Zero(t, stats.byType["targets"].endpointAbsent)

	// The floor this asserts: total time minus the simulated round trip must stay
	// well inside a rebuild's noise, i.e. the added Go-side work (the extra
	// candidate-collection pass over the edge slice, plus indexing the verified
	// set) is not itself a second bottleneck stacked on top of the network cost.
	require.Less(t, elapsed-500*time.Millisecond, 20*time.Second,
		"verified-expiry Go-side overhead (excluding the simulated CH round trip) is too large")
}

func newScaleService(t *testing.T) *Service {
	t.Helper()
	return &Service{bufferMB: 2048, poolSize: 4, queryThreads: 4}
}
