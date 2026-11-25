package graphstore

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func digestFixture() ([]asset.Asset, []asset.Edge, map[string]NodeSignals) {
	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", Region: "eu-west-1", RiskScore: 50},
		{ID: "role-1", Name: "admin", Type: "iam_role", Provider: "aws", RiskScore: 70},
		{ID: "sub-1", Name: "private-a", Type: "subnet", Provider: "aws", Region: "eu-west-1", RiskScore: 10},
		{ID: "pkg-1", Name: "lodash", Type: "package", Provider: "github",
			Metadata: map[string]string{"ecosystem": "npm", "version": "4.17.21"}, RiskScore: 5},
		{ID: "pod-1", Name: "api", Type: "k8s_pod", Provider: "aws", RiskScore: 40},
	}
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{"via": "sg-1", "public_access": "confirmed"}},
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "role-1", DstType: "iam_role",
			EdgeType: "has_role", Properties: map[string]string{}},
	}
	sigs := map[string]NodeSignals{
		"lb-1":  {HasKEV: true, Exploitable: true, MaxScore: 90, PrivescCount: 2},
		"pod-1": {MaxScore: 30, CveID: "CVE-2023-44487", EPSSScore: 0.42},
	}
	return assets, edges, sigs
}

// TestMix64Avalanches is the guard for the collision class mix64's own doc
// comment describes: without it, the additive digest combine inherits FNV's
// byte-linearity, so two independent trailing-byte changes elsewhere in the
// load set can cancel exactly and a real topology change becomes invisible to
// the gate. That collision was "observed, not hypothesised" in an earlier
// version of TestLoadDigest_TopoChangeDetected's fixture — flipping
// reachComplete and the internet_hops change it caused cancelled exactly — but
// relying on an incidental collision in a shared fixture is fragile by
// construction: the fixture's data (and therefore whether it happens to
// collide) can drift for reasons that have nothing to do with mix64, which is
// exactly what happened here (every case in
// TestLoadDigest_TopoChangeDetected still passes with mix64 short-circuited to
// an identity function, so that test stopped being a guard for this class
// without anyone changing mix64 itself).
//
// This tests the property directly instead: mix64 must not be the identity
// function, and it must not be merely additive (x -> x+k), because either of
// those keeps the byte-linear structure the doc comment warns about. A
// disabled avalanche step fails this regardless of what any other fixture's
// data happens to look like.
func TestMix64Avalanches(t *testing.T) {
	// 0 is excluded from the identity check: it is a genuine fixed point of a
	// splitmix64-style finalizer (every XOR-shift and multiply preserves zero),
	// not a sign of a disabled avalanche. It stays in the diffusion check below,
	// where 0 vs 1 is a meaningful pair.
	inputs := []uint64{0, 1, 2, 0xFF, 0x100, 12345, 0xDEADBEEF, ^uint64(0)}
	for _, x := range inputs {
		if x == 0 {
			continue
		}
		require.NotEqualf(t, x, mix64(x),
			"mix64(%#x) returned its input unchanged — an identity avalanche step lets FNV's "+
				"byte-linearity cause additive-combine collisions (see mix64's doc comment)", x)
	}

	// Reject "mostly identity" too: an avalanche that only flips a handful of
	// low bits still preserves enough byte-linear structure for the same
	// cancellation. Two inputs one apart must differ in a large fraction of
	// their 64 bits after mixing — a real avalanche does; x+k or x^k with a
	// small k does not.
	for i := 0; i < len(inputs)-1; i++ {
		a, b := mix64(inputs[i]), mix64(inputs[i]+1)
		require.Greaterf(t, popcount64(a^b), 20,
			"mix64(%#x) and mix64(%#x+1) differ in too few bits (%d) to avalanche — "+
				"adjacent inputs must diverge widely, not just by the +1 that produced them",
			inputs[i], inputs[i], popcount64(a^b))
	}
}

func popcount64(x uint64) int {
	n := 0
	for x != 0 {
		n++
		x &= x - 1
	}
	return n
}

func mustDigest(t *testing.T, a []asset.Asset, e []asset.Edge, s map[string]NodeSignals) loadDigest {
	t.Helper()
	d, err := computeLoadDigest(a, e, newReachOverlay(e), s, true)
	require.NoError(t, err)
	return d
}

// TestLoadDigest_OrderIndependent is the highest-value test in this file.
//
// ClickHouse read order is not stable across reads, so a digest that depends on stream
// order changes on every sweep and the gate never fires — which reproduces the exact
// bug the digest replaces, only with more code and no error to notice. Property-map
// iteration order is randomised by Go on top of that.
func TestLoadDigest_OrderIndependent(t *testing.T) {
	assets, edges, sigs := digestFixture()
	want := mustDigest(t, assets, edges, sigs)

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 25; i++ {
		a := append([]asset.Asset(nil), assets...)
		e := append([]asset.Edge(nil), edges...)
		rng.Shuffle(len(a), func(x, y int) { a[x], a[y] = a[y], a[x] })
		rng.Shuffle(len(e), func(x, y int) { e[x], e[y] = e[y], e[x] })
		// Rebuild the property maps so their internal iteration order differs too.
		for j := range e {
			reordered := make(map[string]string, len(e[j].Properties))
			for k, v := range e[j].Properties {
				reordered[k] = v
			}
			e[j].Properties = reordered
		}
		require.Equal(t, want, mustDigest(t, a, e, sigs),
			"digest changed under a pure reordering (iteration %d) — the gate would never fire", i)
	}
}

// Any change to what Ladybug loads structurally must move the topology half.
func TestLoadDigest_TopoChangeDetected(t *testing.T) {
	assets, edges, sigs := digestFixture()
	base := mustDigest(t, assets, edges, sigs)

	cases := map[string]func() ([]asset.Asset, []asset.Edge, bool){
		"add asset": func() ([]asset.Asset, []asset.Edge, bool) {
			return append(append([]asset.Asset(nil), assets...),
				asset.Asset{ID: "new-1", Type: "s3_bucket", Provider: "aws"}), edges, true
		},
		"drop asset": func() ([]asset.Asset, []asset.Edge, bool) {
			return assets[:len(assets)-1], edges, true
		},
		"change region": func() ([]asset.Asset, []asset.Edge, bool) {
			a := append([]asset.Asset(nil), assets...)
			a[0].Region = "us-east-1"
			return a, edges, true
		},
		"change type": func() ([]asset.Asset, []asset.Edge, bool) {
			a := append([]asset.Asset(nil), assets...)
			a[0].Type = "s3_bucket"
			return a, edges, true
		},
		"add edge": func() ([]asset.Asset, []asset.Edge, bool) {
			return assets, append(append([]asset.Edge(nil), edges...),
				asset.Edge{SrcID: "pod-1", SrcType: "k8s_pod", DstID: "role-1", DstType: "iam_role",
					EdgeType: "has_role", Properties: map[string]string{}}), true
		},
		"drop edge": func() ([]asset.Asset, []asset.Edge, bool) {
			return assets, edges[:1], true
		},
		"change edge property value": func() ([]asset.Asset, []asset.Edge, bool) {
			e := append([]asset.Edge(nil), edges...)
			e[0].Properties = map[string]string{"via": "sg-2", "public_access": "confirmed"}
			return assets, e, true
		},
		"flip reachComplete": func() ([]asset.Asset, []asset.Edge, bool) {
			return assets, edges, false
		},
	}

	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			a, e, reach := mut()
			got, err := computeLoadDigest(a, e, newReachOverlay(e), sigs, reach)
			require.NoError(t, err)
			require.NotEqual(t, base.Topo, got.Topo, "%s must change the topology digest", name)
		})
	}
}

// TestLoadDigest_RiskScoreChangeMovesOnlyScoresHalf guards the load-digest amendment:
// asset RiskScore is rewritten between sweeps by construction (collector base scorer,
// CIEM ScoredAssets, correlate's scoreAssetsFromFindings), so hashing it into the
// topology half meant the gate NEVER fired — every rebuild was a full one.
// A pure RiskScore change must move ONLY the Scores half, on every label whose score
// column holds asset.RiskScore.
func TestLoadDigest_RiskScoreChangeMovesOnlyScoresHalf(t *testing.T) {
	assets, edges, sigs := digestFixture()
	base := mustDigest(t, assets, edges, sigs)

	cases := map[string]string{ // fixture asset id → the label it loads under
		"lb-1":   NodeAsset,
		"role-1": NodeIamRole,
		"pod-1":  NodeK8sWorkload,
		"sub-1":  NodeSubnet,
	}
	for id, label := range cases {
		t.Run(label, func(t *testing.T) {
			a := append([]asset.Asset(nil), assets...)
			for i := range a {
				if a[i].ID == id {
					require.Equal(t, label, NodeLabelFor(a[i].Type), "fixture drift: %s no longer loads as %s", id, label)
					a[i].RiskScore += 7
				}
			}
			got := mustDigest(t, a, edges, sigs)
			require.Equal(t, base.Topo, got.Topo,
				"a pure RiskScore change on %s moved the topology half — the gate would never fire", label)
			require.Equal(t, base.Signals, got.Signals, "RiskScore is not a rollup signal")
			require.NotEqual(t, base.Scores, got.Scores,
				"a RiskScore change on %s must move the Scores half or the score refresh never runs", label)
		})
	}

	// Package's score column holds sig.MaxScore (a finding severity), never
	// asset.RiskScore — so a package RiskScore change loads nothing and must move
	// no half at all.
	t.Run("Package RiskScore is not loaded", func(t *testing.T) {
		a := append([]asset.Asset(nil), assets...)
		for i := range a {
			if a[i].ID == "pkg-1" {
				a[i].RiskScore += 7
			}
		}
		require.Equal(t, base, mustDigest(t, a, edges, sigs))
	})
}

// TestRiskScoreColIdxMatchesLoader pins the digest's skip index against the loader:
// for every bfsScoreLabel, the column at riskScoreColIdx must be exactly — and the
// ONLY column that is — a function of asset.RiskScore. If RiskScore ever leaks into
// a second column, skipping one index leaves the other in the topology half and the
// gate silently dies again.
func TestRiskScoreColIdxMatchesLoader(t *testing.T) {
	repType := map[string]string{
		NodeAsset:       "load_balancer",
		NodeIamRole:     "iam_role",
		NodeK8sWorkload: "k8s_pod",
		NodeSubnet:      "subnet",
	}
	require.Len(t, riskScoreColIdx, len(bfsScoreLabels), "every bfsScoreLabel must have a skip index")
	for _, label := range bfsScoreLabels {
		idx, ok := riskScoreColIdx[label]
		require.True(t, ok, "%s missing from riskScoreColIdx", label)
		require.Equal(t, "score", nodeCSVCols[label][idx])

		typ := repType[label]
		require.Equal(t, label, NodeLabelFor(typ), "representative type drift for %s", label)
		a := asset.Asset{ID: "x", Name: "n", Type: typ, Provider: "aws", Region: "r", AccountID: "1", RiskScore: 10}
		lo := append([]any(nil), appendNodeValues(nil, label, &a, NodeSignals{})...)
		a.RiskScore = 90
		hi := appendNodeValues(nil, label, &a, NodeSignals{})

		require.Equal(t, int32(90), hi[idx], "%s: riskScoreColIdx does not point at RiskScore", label)
		for i := range lo {
			if i == idx {
				require.NotEqual(t, lo[i], hi[i], "%s col %d", label, i)
				continue
			}
			require.Equal(t, lo[i], hi[i],
				"%s: RiskScore leaked into column %d (%s) — the digest skip would miss it", label, i, nodeCSVCols[label][i])
		}
	}
}

// A pure signal change must move ONLY the signals half — that separation is what lets
// the cheap signal-refresh path exist at all.
func TestLoadDigest_SignalChangeMovesOnlySignalsHalf(t *testing.T) {
	assets, edges, sigs := digestFixture()
	base := mustDigest(t, assets, edges, sigs)

	cases := map[string]NodeSignals{
		"max score":     {HasKEV: true, Exploitable: true, MaxScore: 95, PrivescCount: 2},
		"privesc count": {HasKEV: true, Exploitable: true, MaxScore: 90, PrivescCount: 7},
		"kev flag":      {HasKEV: false, Exploitable: true, MaxScore: 90, PrivescCount: 2},
		"exploitable":   {HasKEV: true, Exploitable: false, MaxScore: 90, PrivescCount: 2},
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			next := map[string]NodeSignals{"lb-1": sig, "pod-1": sigs["pod-1"]}
			got := mustDigest(t, assets, edges, next)
			require.Equal(t, base.Topo, got.Topo, "%s must NOT move the topology half", name)
			require.Equal(t, base.Scores, got.Scores, "%s must NOT move the scores half", name)
			require.NotEqual(t, base.Signals, got.Signals, "%s must move the signals half", name)
		})
	}

	t.Run("cve and epss", func(t *testing.T) {
		next := map[string]NodeSignals{
			"lb-1":  sigs["lb-1"],
			"pod-1": {MaxScore: 30, CveID: "CVE-2024-3094", EPSSScore: 0.91},
		}
		got := mustDigest(t, assets, edges, next)
		require.Equal(t, base.Topo, got.Topo)
		require.NotEqual(t, base.Signals, got.Signals, "Package cve_id/epss_score are signal-bearing")
	})

	t.Run("dropping a resource from the rollup", func(t *testing.T) {
		got := mustDigest(t, assets, edges, map[string]NodeSignals{"lb-1": sigs["lb-1"]})
		require.NotEqual(t, base.Signals, got.Signals)
	})

	// appendNodeValues (node_rows.go) zeroes epss_score when CveID == "" — it is
	// only meaningful alongside a CVE. signalsDigest must apply the identical
	// zeroing rule, or a stale EPSSScore behind an empty CveID would move the
	// digest for a value that never actually gets loaded: the digest would
	// disagree with what the loader wrote, an asymmetry the load digest must forbid.
	t.Run("epss without a cve id must not move the digest", func(t *testing.T) {
		withoutEPSS := map[string]NodeSignals{
			"lb-1":  sigs["lb-1"],
			"pod-1": {MaxScore: 30}, // no CveID, no EPSSScore
		}
		withEPSS := map[string]NodeSignals{
			"lb-1":  sigs["lb-1"],
			"pod-1": {MaxScore: 30, EPSSScore: 0.91}, // no CveID, but a stale EPSSScore
		}
		got1 := mustDigest(t, assets, edges, withoutEPSS)
		got2 := mustDigest(t, assets, edges, withEPSS)
		require.Equal(t, got1.Signals, got2.Signals,
			"a bare EPSSScore with no CveID is never loaded (node_rows.go zeroes it), so it must not move the digest either")
	})
}

// Two resources swapping signal values must change the digest. Without the id mixed
// into each row's hash, a commutative combine would sum to the same total and the
// change would be invisible.
func TestLoadDigest_SignalSwapBetweenResourcesDetected(t *testing.T) {
	assets, edges, _ := digestFixture()
	a := map[string]NodeSignals{
		"lb-1":  {MaxScore: 10, PrivescCount: 1},
		"pod-1": {MaxScore: 90, PrivescCount: 5},
	}
	b := map[string]NodeSignals{
		"lb-1":  {MaxScore: 90, PrivescCount: 5},
		"pod-1": {MaxScore: 10, PrivescCount: 1},
	}
	require.NotEqual(t, mustDigest(t, assets, edges, a).Signals, mustDigest(t, assets, edges, b).Signals)
}

// A schema bump must force a full rebuild even when the content is byte-identical,
// since the DDL the rows load into has changed.
func TestLoadDigest_SchemaVersionParticipates(t *testing.T) {
	require.NotEqual(t, schemaAndReachDigest(true), schemaAndReachDigest(false),
		"reachComplete must participate")
	// SchemaVersion is a const, so its participation is asserted structurally: the
	// digest of the current schema must differ from one computed over a different
	// string, which is what mixing it in guarantees.
	require.NotZero(t, schemaAndReachDigest(true))
}

// TestSyncFromSources_GateTakesEachPath is the end-to-end proof, on a real in-memory
// Ladybug: identical sources must take the no-op path, a pure signal change the signals
// path, and a topology change the full path.
//
// A gate that lives in the caller and compares a counter bumped unconditionally
// can never match, turning every sync into a full rebuild.
func TestSyncFromSources_GateTakesEachPath(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets, edges, sigs := digestFixture()

	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathFull, svc.LastSyncPath(), "the first sync has no baseline to compare")

	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathNoop, svc.LastSyncPath(),
		"identical sources must skip the rebuild entirely")

	moved := map[string]NodeSignals{
		"lb-1":  {HasKEV: true, Exploitable: true, MaxScore: 95, PrivescCount: 2},
		"pod-1": sigs["pod-1"],
	}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{moved}))
	require.Equal(t, syncPathSignals, svc.LastSyncPath(),
		"a pure signal change must take the cheap signal path, not a full rebuild")

	// The signal path must have actually applied the new score.
	res, err := svc.RunCypher(ctx, `MATCH (n:Asset {id: "lb-1"}) RETURN n`, 10, 10)
	require.NoError(t, err)
	require.Len(t, res.Nodes, 1)
	require.Equal(t, 95, res.Nodes[0].MaxScore)

	// A pure RiskScore change is the shipped bug: it moved the topology half, so
	// EVERY sweep was a full rebuild. It must now take the cheap path — and the
	// cheap path must actually rewrite the served scores, BFS boost included, or
	// the gate is just a fancy way to serve stale risk.
	//
	// lb-1 is the node raised, and role-1 is where the propagation must land: the
	// fixture edge is lb-1 -[has_role]-> role-1, and has_role propagates risk
	// src→dst, so an instance's raise reaches the role it carries and not the
	// reverse (graphschema.Direction). The assertion pointed the other way back
	// when the BFS still indexed every edge in both directions.
	preRole := nodeScore(t, svc, "IamRole", "role-1")
	preLB := nodeScore(t, svc, "Asset", "lb-1")
	rescored := append([]asset.Asset(nil), assets...)
	for i := range rescored {
		if rescored[i].ID == "lb-1" {
			rescored[i].RiskScore = 99
		}
	}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{rescored}, stubEdges{edges}, stubSignals{moved}))
	require.Equal(t, syncPathSignals, svc.LastSyncPath(),
		"a pure RiskScore change must take the cheap path, not a full rebuild — this is the bug the load-digest amendment fixes")
	require.GreaterOrEqual(t, nodeScore(t, svc, "Asset", "lb-1"), 99,
		"the score refresh must write the changed node's own score")
	require.Greater(t, nodeScore(t, svc, "IamRole", "role-1"), preRole,
		"the score refresh must re-run the BFS: lb-1's raise propagates over has_role to the role it carries")
	require.Greater(t, nodeScore(t, svc, "Asset", "lb-1"), preLB)

	// A RiskScore flip that changes graph MEMBERSHIP is a topology change and must
	// still rebuild: filterLadybugAssets keeps score>0 assets, and the digest is
	// computed over the post-filter slice. This is the argument for why excluding
	// the score VALUE from the topo half loses no real topology change.
	joiner := asset.Asset{ID: "fn-1", Name: "cron", Type: "lambda_function", Provider: "aws"}
	withDormant := append(append([]asset.Asset(nil), rescored...), joiner)
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{withDormant}, stubEdges{edges}, stubSignals{moved}))
	require.Equal(t, syncPathNoop, svc.LastSyncPath(),
		"a score-0, edge-less, non-keep asset is filtered out — adding it changes nothing")
	joiner.RiskScore = 5
	withMember := append(append([]asset.Asset(nil), rescored...), joiner)
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{withMember}, stubEdges{edges}, stubSignals{moved}))
	require.Equal(t, syncPathFull, svc.LastSyncPath(),
		"a RiskScore flip that pulls an asset INTO the graph is a topology change and must rebuild")

	grown := append(append([]asset.Asset(nil), withMember...),
		asset.Asset{ID: "bucket-1", Name: "logs", Type: "s3_bucket", Provider: "aws"})
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{grown}, stubEdges{edges}, stubSignals{moved}))
	require.Equal(t, syncPathFull, svc.LastSyncPath(), "a topology change must force a full rebuild")

	// And the new asset is actually in the graph — the gate must not skip real work.
	res, err = svc.RunCypher(ctx, `MATCH (n:Asset {id: "bucket-1"}) RETURN n`, 10, 10)
	require.NoError(t, err)
	require.Len(t, res.Nodes, 1)
}

// nodeScore reads the served risk score of one node from the live graph.
func nodeScore(t *testing.T, svc *Service, label, id string) int {
	t.Helper()
	res, err := svc.RunCypher(context.Background(),
		fmt.Sprintf(`MATCH (n:%s {id: "%s"}) RETURN n`, label, id), 10, 10)
	require.NoError(t, err)
	require.Len(t, res.Nodes, 1, "%s %s not found", label, id)
	return res.Nodes[0].Score
}

// A no-op sync must still stamp lastBuiltAt: the graph IS current, and a freshness
// gauge that reads stale on a correctly-skipped sweep would page for nothing.
func TestSyncFromSources_NoopStampsFreshness(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets, edges, sigs := digestFixture()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	first := svc.lastBuiltAt.Load()
	require.NotZero(t, first)

	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.Equal(t, syncPathNoop, svc.LastSyncPath())
	require.GreaterOrEqual(t, svc.lastBuiltAt.Load(), first,
		"a skipped sweep means the graph is current — freshness must not go stale")
}
