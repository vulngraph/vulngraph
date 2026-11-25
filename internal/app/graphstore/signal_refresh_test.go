package graphstore

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// signalBearingCols are the node columns whose value comes from the finding rollup
// (SignalSource) rather than from topology or from the asset row. Any label carrying
// one of these must be refreshed by a signal-only refresh, or it serves whatever the
// last full rebuild wrote.
//
// `score` is absent on purpose: it is signal-bearing on Package (sig.MaxScore) and
// topology/asset-bearing on Asset/IamRole/K8sWorkload (asset.RiskScore, owned by the
// BFS). It is handled explicitly in the Package case below.
var signalBearingCols = []string{
	"has_kev", "exploitable", "toxic_combo", "max_score", "privesc_count",
	"cve_id", "epss_score",
}

// TestSignalRefreshColsMatchNodeLoader derives, from the node loader itself, which
// labels carry signal columns — and asserts signalRefreshCols covers exactly those.
//
// Written as a derivation rather than a list because the defect it guards WAS a list
// that stopped being true. RefreshSignals hardcoded two statements for :Asset and
// :IamRole; :K8sWorkload carries the identical seven signal columns and :Package carries its
// own five, so neither was ever refreshed. This is the same omission
// bfsScoreLabels documents from the other side, where a substantial fraction of
// workloads served a stale score.
//
// It never fired in practice only because the gate that would have taken the
// refresh path could not fire either — so the bug was latent, not benign.
func TestSignalRefreshColsMatchNodeLoader(t *testing.T) {
	signalBearing := make(map[string]bool, len(signalBearingCols))
	for _, c := range signalBearingCols {
		signalBearing[c] = true
	}

	// Derive: a label needs refreshing iff the loader gives it a signal-bearing
	// column, or it is Package (whose `score` is sig.MaxScore).
	wantLabels := map[string][]string{}
	for label, cols := range nodeCSVCols {
		var need []string
		for _, c := range cols {
			if signalBearing[c] || (label == NodePackage && c == "score") {
				need = append(need, c)
			}
		}
		if len(need) > 0 {
			wantLabels[label] = need
		}
	}
	require.NotEmpty(t, wantLabels, "the derivation found no signal-bearing labels — it is broken")

	// Coverage, both directions.
	var missing []string
	for label := range wantLabels {
		if _, ok := signalRefreshCols[label]; !ok {
			missing = append(missing, label)
		}
	}
	sort.Strings(missing)
	require.Emptyf(t, missing,
		"these labels carry signal columns but no signal refresh covers them, so they serve "+
			"values from the last full rebuild: %v", missing)

	for label := range signalRefreshCols {
		require.Containsf(t, nodeCSVCols, label,
			"signalRefreshCols names %q, which the node loader does not load", label)
		require.Containsf(t, wantLabels, label,
			"signalRefreshCols refreshes %q, which carries no signal-bearing column", label)
	}

	// Per label, the declared set must be exactly the derived set.
	for label, want := range wantLabels {
		got := append([]string(nil), signalRefreshCols[label]...)
		w := append([]string(nil), want...)
		sort.Strings(got)
		sort.Strings(w)
		require.Equalf(t, w, got, "signalRefreshCols[%s] does not match what the loader gives it", label)
	}
}

// TestSignalRefreshNeverWritesTopologyColumns is the second half of the contract: a
// signal refresh has no edges, so the rollup carries the zero value for every
// topology-derived column. Writing one would assert "not exposed" / "not reachable"
// across the graph.
//
// toxic_combo is the subtle case and the one that was actually broken: it IS
// refreshable, but only because RefreshSignals recomputes it from the stashed
// exposure set. It must never be taken straight from the rollup.
func TestSignalRefreshNeverWritesTopologyColumns(t *testing.T) {
	for _, banned := range topologyOnlyNodeCols {
		for label, cols := range signalRefreshCols {
			require.NotContainsf(t, cols, banned,
				"signalRefreshCols[%s] writes the topology-derived column %q; a refresh has no "+
					"edges, so it would write the rollup's zero value over real topology", label, banned)
		}
		// And the banned column must really be a loader column, or this guard is
		// asserting against a name that no longer exists.
		found := false
		for _, cols := range nodeCSVCols {
			for _, c := range cols {
				if c == banned {
					found = true
				}
			}
		}
		require.Truef(t, found, "topologyOnlyNodeCols names %q, which the node loader does not load", banned)
	}
}

// The generated statement must match the declaration, so the SET clause cannot drift
// from signalRefreshCols the way the two hardcoded statements drifted from the loader.
func TestSignalRefreshQueryMatchesDeclaration(t *testing.T) {
	for label, cols := range signalRefreshCols {
		q := signalRefreshQuery(label)
		require.Contains(t, q, "MATCH (n:"+label+" {id: r.id})")
		for _, c := range cols {
			require.Containsf(t, q, "n."+c+" = r."+c, "%s: column %q missing from the SET clause", label, c)
		}
		// Exactly len(cols) assignments — no extras smuggled in.
		require.Equalf(t, len(cols), strings.Count(q, " = r."),
			"%s: SET clause assignment count does not match the declared column count", label)
		for _, banned := range topologyOnlyNodeCols {
			require.NotContainsf(t, q, "n."+banned+" = ", "%s writes topology column %q", label, banned)
		}
	}
}

// Stable statement order: map iteration is randomised, and a nondeterministic write
// order makes a partial failure much harder to reason about.
func TestSignalRefreshLabelsAreStablyOrdered(t *testing.T) {
	first := signalRefreshLabels()
	require.Len(t, first, len(signalRefreshCols))
	for i := 0; i < 20; i++ {
		require.Equal(t, first, signalRefreshLabels())
	}
	require.True(t, sort.StringsAreSorted(first))
}

// TestRefreshSignals_PreservesToxicComboAndCoversEveryLabel is the behavioural test,
// on a real in-memory Ladybug.
//
// It exercises the exact runtime shape: a SignalSource that leaves ToxicCombo,
// Exposed and InternetHops at their zero values, because NO real SignalSource
// populates them (graphSignalSource and serveSignalSource both set only
// HasKEV/Exploitable/MaxScore/PrivescCount/CveID/EPSSScore, and finding.ResourceSignals
// has no such fields). ToxicCombo is derived at load time as exposed && privesc>0.
//
// It catches two regressions: toxic_combo written straight from the rollup's
// false, blanket-zeroing it on every matched node; and :K8sWorkload never
// matched at all, so its signal columns keep the previous build's values.
func TestRefreshSignals_PreservesToxicComboAndCoversEveryLabel(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{
		{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50},
		{ID: "pod-1", Name: "api", Type: "k8s_pod", Provider: "aws", RiskScore: 40},
	}
	// Both are CONFIRMED-tier internet-exposed, so both get exposed=true and, with a
	// privesc count, toxic_combo=true at build time.
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{}},
		{SrcID: "pod-1", SrcType: "k8s_pod", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{}},
	}
	build := map[string]NodeSignals{
		"lb-1":  {HasKEV: true, Exploitable: true, MaxScore: 90, PrivescCount: 2},
		"pod-1": {HasKEV: true, Exploitable: true, MaxScore: 80, PrivescCount: 3},
	}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{build}))

	// Sanity: the full path derives toxic_combo for both labels.
	requireToxic := func(t *testing.T, when string) {
		t.Helper()
		for _, q := range []string{
			`MATCH (n:Asset {id: "lb-1"}) RETURN n`,
			`MATCH (n:K8sWorkload {id: "pod-1"}) RETURN n`,
		} {
			res, qErr := svc.RunCypher(ctx, q, 10, 10)
			require.NoError(t, qErr, "%s: %s", when, q)
			require.Len(t, res.Nodes, 1, "%s: %s", when, q)
			require.True(t, res.Nodes[0].ToxicCombo,
				"%s: %s — toxic_combo is exposed && privesc>0 and both hold", when, q)
		}
	}
	requireToxic(t, "after full sync")

	// Now a signals-only refresh with CHANGED scores, and ToxicCombo/Exposed left false
	// exactly as every real SignalSource leaves them.
	refresh := map[string]NodeSignals{
		"lb-1":  {HasKEV: true, Exploitable: true, MaxScore: 95, PrivescCount: 2},
		"pod-1": {HasKEV: true, Exploitable: true, MaxScore: 85, PrivescCount: 3},
	}
	require.NoError(t, svc.RefreshSignals(ctx, stubSignals{refresh}))

	// Bug 2: toxic_combo must survive — recomputed from the stashed exposure set.
	requireToxic(t, "after signal refresh")

	// Bug 1: the refresh must actually reach K8sWorkload, not just Asset.
	res, err := svc.RunCypher(ctx, `MATCH (n:K8sWorkload {id: "pod-1"}) RETURN n`, 10, 10)
	require.NoError(t, err)
	require.Len(t, res.Nodes, 1)
	require.Equal(t, 85, res.Nodes[0].MaxScore,
		"K8sWorkload was not refreshed — it still serves the previous build's max_score")

	// And Asset still refreshes, so the rewrite did not trade one label for another.
	res, err = svc.RunCypher(ctx, `MATCH (n:Asset {id: "lb-1"}) RETURN n`, 10, 10)
	require.NoError(t, err)
	require.Len(t, res.Nodes, 1)
	require.Equal(t, 95, res.Nodes[0].MaxScore)
}

// TestNodeSignals_CacheServesRealExposure guards a live scoring path, not a latent one.
//
// NodeSignals checks nodeSignalsCache BEFORE querying Ladybug, and prewarmSignalCache
// populates that cache from the finding rollup — which carries Exposed=false and
// ToxicCombo=false, because they are topology-derived and no SignalSource sets them.
// So every resource IN the rollup (i.e. exactly the finding-bearing ones being scored)
// got Exposed=false from a cache hit even though Ladybug held the correct value.
//
// That is consumed: cmd/graph/ladybug_blast.go appends a synthetic "exposure" peer finding
// when sig.Exposed is true (feeding enrich's AttackPaths/ToxicCombo) and returns
// sig.Exposed for the enrich fingerprint's IsExposed. A false there silently
// under-scores every exposed, finding-bearing asset.
func TestNodeSignals_CacheServesRealExposure(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws"}}
	edges := []asset.Edge{
		{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet",
			EdgeType: "exposed_to_internet", Properties: map[string]string{}},
	}
	// lb-1 is in the rollup, so it IS prewarmed — the cache-hit path is the one under test.
	sigs := map[string]NodeSignals{"lb-1": {HasKEV: true, MaxScore: 90, PrivescCount: 2}}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))

	got, err := svc.NodeSignals(ctx, "lb-1")
	require.NoError(t, err)
	require.True(t, got.Exposed,
		"the cache served Exposed=false for a confirmed internet-exposed asset; ladybug_blast drops "+
			"the synthetic exposure peer and IsExposed lies, under-scoring it")
	require.True(t, got.ToxicCombo, "toxic_combo is exposed && privesc>0 and both hold")
	require.Equal(t, 2, got.PrivescCount, "the rollup fields must still come through")
}
