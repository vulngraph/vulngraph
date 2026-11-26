package graphstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// largeEstateShapes returns a synthetic healthy build and a degraded build of a
// large estate. The per-type mix is deliberately skewed (one dominant bulk type,
// a long tail of small ones, a couple below minTypeBaselineRows) so the gate has
// to separate a realistic-looking pair, not a trivially different one.
func largeEstateShapes() (healthy, degraded fidelityShape) {
	healthy = fidelityShape{
		Assets:     300000,
		TotalEdges: 1000000,
		ByType: map[string]int{
			"contains_data": 360000, "connected_via_sg": 135000, "member_of": 95000,
			"has_role": 87000, "executes_as": 78000, "runs_container": 42000,
			"runs_image": 44000, "deploys_to": 24000, "protected_by": 19000,
			"exposed_to_internet": 17000, "owns": 15000, "sg_allows_from": 15000,
			"can_assume": 13000, "has_policy": 10000,
			"targets": 10000, "allows_action": 8000, "accesses_secret": 7000,
			"dns_points_to": 5000, "defined_in": 2500, "binds": 1300,
			"can_escalate_to": 700, "grants_access_to": 500, "routes_to": 300,
			"assigned_to": 10300, "federated_access": 270, "peered_with": 100,
			"grants_admin": 30,
		},
	}
	// The degraded build: every bulk-tier type at exactly zero, critical tier intact
	// (a few rows of ordinary churn), and the node loss that follows from it once
	// filterLadybugAssets prunes the newly edgeless packages and DNS records.
	degraded = fidelityShape{Assets: 246000, TotalEdges: 624000, ByType: map[string]int{}}
	for et, n := range healthy.ByType {
		degraded.ByType[et] = n
	}
	for _, bulk := range []string{"contains_data", "dns_points_to", "grants_access_to", "assigned_to", "peered_with"} {
		degraded.ByType[bulk] = 0
	}
	return healthy, degraded
}

// TestCheckFidelity_RefusesABulkTierCollapse is the regression the whole file exists
// for: a build that lost its entire bulk tier must not publish.
func TestCheckFidelity_RefusesABulkTierCollapse(t *testing.T) {
	healthy, degraded := largeEstateShapes()

	// Layer 1 alone catches it — the fetch reported its own failure.
	v := checkFidelity(degraded, healthy, false, "bulk pass errored", nil, false)
	require.True(t, v.Refuse, "a fetch that reported partial coverage must never publish")
	assert.Contains(t, v.Reason, "partial coverage")

	// And Layer 2 catches it independently, which matters because the next
	// degradation of this class may not self-report (a partial correlate sweep, a
	// producer that stopped emitting).
	v = checkFidelity(degraded, healthy, true, "", nil, false)
	require.True(t, v.Refuse, "a ~38%% edge loss must be refused even when the fetch claims success")
	assert.Contains(t, v.Reason, "contains_data (360000 -> 0)")
	assert.Contains(t, v.Reason, "fetched edges 624000 vs baseline 1000000")

	// The healthy build publishes.
	require.False(t, checkFidelity(healthy, healthy, true, "", nil, false).Refuse)
}

// TestCheckFidelity_AllowsLegitimateDrift pins the gate against the kind of
// legitimate sweep-to-sweep change it must tolerate (edges drifting under 1%,
// nodes under ~5%, individual types churning or being deliberately pruned). A
// gate that refuses these is an outage of freshness, which is the failure mode
// opposite to the one it exists to prevent.
func TestCheckFidelity_AllowsLegitimateDrift(t *testing.T) {
	healthy, _ := largeEstateShapes()

	tests := []struct {
		name   string
		mutate func(s *fidelityShape)
	}{
		{"total-edge drop, 0.9924", func(s *fidelityShape) {
			s.TotalEdges = 992400 // -0.76%
		}},
		{"node drop, 0.9480", func(s *fidelityShape) {
			s.Assets = 284400
		}},
		{"can_escalate_to churn, 700 -> 406", func(s *fidelityShape) {
			s.ByType["can_escalate_to"] = 406
		}},
		{"has_policy churn, 0.837", func(s *fidelityShape) {
			s.ByType["has_policy"] = 8370
		}},
		{"dns_record edge gating: dns_points_to collapses 96%", func(s *fidelityShape) {
			// A deliberate prune: a large drop that leaves the type nonzero, so the
			// gate must not see it.
			s.ByType["dns_points_to"] = 200
			s.TotalEdges -= 4800
		}},
		{"a low-volume type flickering to zero stays below the floor", func(s *fidelityShape) {
			s.ByType["grants_admin"] = 0 // baseline 30, under minTypeBaselineRows
			s.TotalEdges -= 30
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cand := fidelityShape{Assets: healthy.Assets, TotalEdges: healthy.TotalEdges, ByType: map[string]int{}}
			for k, v := range healthy.ByType {
				cand.ByType[k] = v
			}
			tc.mutate(&cand)
			v := checkFidelity(cand, healthy, true, "", nil, false)
			assert.False(t, v.Refuse, "legitimate drift must publish; refused with: %s", v.Reason)
		})
	}
}

// TestCheckFidelity_NoBaselineFailsOpenExceptOnASelfReportedPartialFetch covers the
// first-boot case explicitly. With nothing to compare against, Layer 2 cannot have
// an opinion and refusing would mean the platform can never establish a graph at all
// — strictly worse than a degraded graph. Layer 1 still applies, because it needs no
// baseline.
func TestCheckFidelity_NoBaselineFailsOpenExceptOnASelfReportedPartialFetch(t *testing.T) {
	_, degraded := largeEstateShapes()
	var noBaseline fidelityShape
	require.True(t, noBaseline.empty())

	v := checkFidelity(degraded, noBaseline, true, "", nil, false)
	assert.False(t, v.Refuse, "no baseline: Layer 2 must fail open, not deadlock the first build")

	v = checkFidelity(degraded, noBaseline, false, "bulk pass errored", nil, false)
	assert.True(t, v.Refuse, "a self-reported partial fetch must be refused even on a cold start")
}

// TestCheckFidelity_AcceptOnRepeat is the safety valve that makes refusal safe: a
// real estate change costs one sweep of freshness rather than freezing the graph
// forever, and a transient degradation still never publishes because it does not
// reproduce (the very next sweep is normally full).
func TestCheckFidelity_AcceptOnRepeat(t *testing.T) {
	healthy, degraded := largeEstateShapes()

	first := checkFidelity(degraded, healthy, true, "", nil, false)
	require.True(t, first.Refuse, "the first sighting is refused")

	aSweepLater := &pendingRefusal{shape: degraded, age: minRepeatAge}

	// Same shape a full sweep later → published, loudly.
	second := checkFidelity(degraded, healthy, true, "", aSweepLater, false)
	require.False(t, second.Refuse)
	assert.Contains(t, second.Reason, "PUBLISHED ON REPEAT")

	// The River retry. A refusal returns an error, so ladybug_rebuild is retried within
	// seconds; that retry produces an identical shape and must NOT count as a second
	// independent observation, or the safety valve becomes a 30-second bypass.
	retry := &pendingRefusal{shape: degraded, age: 20 * time.Second}
	assert.True(t, checkFidelity(degraded, healthy, true, "", retry, false).Refuse,
		"a retry seconds after the refusal is the same observation, not a repeat")

	// A DIFFERENT degradation after the first is not a repeat — it is a second,
	// distinct failure, and gets its own refusal.
	worse := fidelityShape{Assets: degraded.Assets, TotalEdges: 300000, ByType: degraded.ByType}
	assert.True(t, checkFidelity(worse, healthy, true, "", aSweepLater, false).Refuse,
		"a different shape must not ride in on the previous refusal")

	// A self-reported partial fetch is excluded from accept-on-repeat: we KNOW the
	// edge set is incomplete, so repetition changes nothing about publishability.
	assert.True(t, checkFidelity(degraded, healthy, false, "bulk pass errored", aSweepLater, false).Refuse,
		"a repeated partial fetch must still be refused")
}

// TestLostTypes_ExemptsTypesTakenOutOfTheFetch keeps the deliberate-prune escape
// working: moving an edge type to TierUnsynced in the registry is how a type is
// legitimately removed, and the gate must read that as intent rather than loss.
// runs_in, member_of_zone, in_subnet and in_vpc were all retired exactly this way.
func TestLostTypes_ExemptsTypesTakenOutOfTheFetch(t *testing.T) {
	baseline := fidelityShape{Assets: 100, TotalEdges: 20000, ByType: map[string]int{
		"runs_in":    13326, // TierUnsynced
		"can_assume": 5000,  // TierCritical
	}}
	cand := fidelityShape{Assets: 100, TotalEdges: 5000, ByType: map[string]int{"can_assume": 5000}}
	assert.Empty(t, lostTypes(cand, baseline),
		"an unsynced type at zero is intent, not loss")

	cand.ByType["can_assume"] = 0
	assert.Equal(t, []string{"can_assume (5000 -> 0)"}, lostTypes(cand, baseline))
}

// ─── behavioural: the swap really does not happen ────────────────────────────

// fidelityEdges is an EdgeSource whose result can be swapped between calls, so one
// Service can be driven through a good build and then a degraded one.
type fidelityEdges struct{ res asset.EdgeSyncResult }

func (f *fidelityEdges) AllEdges(context.Context, asset.SyncProjection) (asset.EdgeSyncResult, error) {
	return f.res, nil
}

// VerifyDepartedAssets: no asset-table model in this stub either; see stubEdges.
func (f *fidelityEdges) VerifyDepartedAssets(context.Context, []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

// TestSyncFromSources_AbandonsADegradedRebuild is the end-to-end proof for the
// bulk-tier collapse: after a degraded fetch the LIVE graph must
// still be the previous one.
//
// It asserts the whole refusal contract, because each part of it was a way to get
// this wrong: the error surfaces (so the correlate job fails visibly rather than
// logging into a short log-retention window), the graph still answers the old
// topology, and nothing that marks a successful build was touched.
func TestSyncFromSources_AbandonsADegradedRebuild(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	// A baseline graph: 40 load balancers, each with a has_role edge to its own role,
	// plus one exposed_to_internet seed. 120 assets, 81 edges.
	var assets []asset.Asset
	var edges []asset.Edge
	for i := range 40 {
		lb := fmt.Sprintf("lb-%d", i)
		role := fmt.Sprintf("role-%d", i)
		assets = append(assets,
			asset.Asset{ID: lb, Name: lb, Type: "load_balancer", Provider: "aws", RiskScore: 50},
			asset.Asset{ID: role, Name: role, Type: "iam_role", Provider: "aws", RiskScore: 40},
		)
		edges = append(edges,
			asset.Edge{SrcID: lb, SrcType: "load_balancer", DstID: role, DstType: "iam_role", EdgeType: "has_role"},
			asset.Edge{SrcID: lb, SrcType: "load_balancer", DstID: "internet", DstType: "internet", EdgeType: "exposed_to_internet"},
		)
	}
	src := &fidelityEdges{res: asset.EdgeSyncResult{Edges: edges}}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil}))

	countRoles := func() int {
		res, qErr := svc.RunCypher(ctx, `MATCH (:Asset)-[:HasRole]->(d:IamRole) RETURN count(d) AS n`, 100, 100)
		require.NoError(t, qErr)
		require.Len(t, res.Rows, 1)
		n, ok := res.Rows[0]["n"].(int64)
		require.True(t, ok)
		return int(n)
	}
	require.Equal(t, 40, countRoles(), "baseline graph must be complete")
	builtBefore := svc.LastBuiltAt()
	nodesBefore := svc.NodeCount()

	// Now the bulk-tier collapse, in miniature: the fetch loses has_role entirely — a
	// well-formed, non-empty, plausible-looking edge set that is simply missing a
	// chunk. Nothing about it reports an error.
	var degraded []asset.Edge
	for _, e := range edges {
		if e.EdgeType != "has_role" {
			degraded = append(degraded, e)
		}
	}
	src.res = asset.EdgeSyncResult{Edges: degraded}

	err = svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil})
	require.Error(t, err, "a degraded rebuild must fail, not succeed quietly")
	require.ErrorIs(t, err, ErrRebuildRefused)

	assert.Equal(t, 40, countRoles(),
		"the PREVIOUS graph must still be serving — off-side build plus atomic swap is the "+
			"one real safety property here, and abandoning the candidate is what uses it")
	assert.Equal(t, builtBefore, svc.LastBuiltAt(),
		"a refused rebuild must not stamp lastBuiltAt, or the staleness alert never fires")
	assert.Equal(t, nodesBefore, svc.NodeCount())
	assert.Equal(t, int64(1), svc.FidelityStats().Refusals,
		"the refusal counter is the signal that proves the gate ran")

	// An immediate retry — which is what River does with the error above — must be
	// refused again: it is the same observation, not a second one.
	require.ErrorIs(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil}), ErrRebuildRefused)
	assert.Equal(t, 40, countRoles(), "a retry within minRepeatAge must not publish")
	assert.Equal(t, int64(0), svc.FidelityStats().RepeatPublishes)

	// Backdate the refusal by a full correlate interval: the same shape is now a
	// second, independent observation, so it publishes and says so.
	svc.fidelity.mu.Lock()
	svc.fidelity.lastRefusalUnix -= int64((minRepeatAge + time.Minute).Seconds())
	svc.fidelity.mu.Unlock()
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil}))
	assert.Equal(t, 0, countRoles(), "accept-on-repeat must actually publish")
	assert.Equal(t, int64(1), svc.FidelityStats().RepeatPublishes)
}

// TestSyncFromSources_RefusesASelfReportedPartialFetch covers Layer 1 through the
// real code path, including the case where the edge counts
// look survivable but the fetch told us it failed.
func TestSyncFromSources_RefusesASelfReportedPartialFetch(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50}}
	edges := []asset.Edge{{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet", EdgeType: "exposed_to_internet"}}
	src := &fidelityEdges{res: asset.EdgeSyncResult{Edges: edges}}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil}))
	require.True(t, svc.EdgeFetchComplete())

	// Identical content, but the fetch reports a failed bulk pass. Identical content
	// is deliberate: it proves Layer 1 stands on the report alone, not on a shape
	// difference the digest gate would also have seen.
	src.res = asset.EdgeSyncResult{Edges: edges, BulkPassFailed: true}
	err = svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil})
	require.ErrorIs(t, err, ErrRebuildRefused)
	assert.False(t, svc.EdgeFetchComplete(),
		"graph_ladybug_edge_fetch_complete must read 0 after a self-reported partial fetch")
	assert.Equal(t, int64(1), svc.FidelityStats().Refusals)

	// Repetition does not buy it a publish, unlike a Layer-2 shape change.
	err = svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil})
	require.ErrorIs(t, err, ErrRebuildRefused)
	assert.Equal(t, int64(2), svc.FidelityStats().Refusals)
	assert.Equal(t, int64(0), svc.FidelityStats().RepeatPublishes)
	assert.True(t, errors.Is(err, ErrRebuildRefused))
}

// TestSyncFromSources_RefusesATruncatedAssetLoad: an asset load that hit the sync
// row cap is a partial fetch like a truncated edge type, and the refusal reason
// names the asset truncation rather than labelling it an edge-fetch problem.
func TestSyncFromSources_RefusesATruncatedAssetLoad(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50}}
	edges := []asset.Edge{{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet", EdgeType: "exposed_to_internet"}}
	src := &fidelityEdges{res: asset.EdgeSyncResult{Edges: edges}}
	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil}))
	require.True(t, svc.AssetFetchComplete())

	err = svc.SyncFromSources(ctx, 0, truncatedAssets{assets}, src, stubSignals{nil})
	require.ErrorIs(t, err, ErrRebuildRefused)
	assert.False(t, svc.AssetFetchComplete(),
		"graph_ladybug_asset_fetch_complete must read 0 after a truncated asset load")
	assert.True(t, svc.EdgeFetchComplete(), "the edge fetch itself was whole")
	stats := svc.FidelityStats()
	assert.Equal(t, int64(1), stats.Refusals)
	assert.Contains(t, stats.LastReason, "assets truncated at the sync row cap")
	assert.NotContains(t, stats.LastReason, "edge fetch")
}

type truncatedAssets struct{ a []asset.Asset }

func (s truncatedAssets) ListAll(context.Context, asset.SyncProjection) (asset.AssetSyncResult, error) {
	return asset.AssetSyncResult{Assets: s.a, Truncated: true}, nil
}

// ─── Fidelity-gate hardening: edge cases ──────────────────

// TestCheckFidelity_NoBaselineButSnapshotShapeArmsLayer2 is case 1: a SchemaVersion
// bump makes ReadSnapshot reject the file, and LoadFromSnapshot used to leave Layer 2
// disarmed for exactly the first post-deploy build. This pins the pure-function half:
// once seedBaseline has armed the baseline from the snapshot's version-independent
// shape, checkFidelity must judge the first post-deploy build against it exactly like
// any other baseline — it does not get a first-boot free pass just because the
// SERVED graph is starting cold.
func TestCheckFidelity_NoBaselineButSnapshotShapeArmsLayer2(t *testing.T) {
	healthy, degraded := largeEstateShapes()

	v := checkFidelity(degraded, healthy, true, "", nil, false)
	require.True(t, v.Refuse,
		"a snapshot-derived baseline must catch the same degradation a freshly-published one would")
	assert.Contains(t, v.Reason, "contains_data (360000 -> 0)")
}

// TestLoadFromSnapshot_SchemaBumpArmsBaselineFromShapeNotGraph proves the
// LoadFromSnapshot half of case 1 end-to-end: a snapshot written under an OLD
// SchemaVersion cannot warm-start the graph (ErrSnapshotStale, no in-place Ladybug
// migration), but its shape must still arm the fidelity baseline, so the very next
// SyncFromSources — the first build after the deploy — has a Layer-2 opinion instead
// of the empty-baseline fail-open.
func TestLoadFromSnapshot_SchemaBumpArmsBaselineFromShapeNotGraph(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ladybug.snap")

	// A small but realistic pre-deploy shape: a bulk-tier type well above
	// minTypeBaselineRows (contains_data) plus a critical-tier type that survives the
	// bulk-tier collapse intact (has_role) — the same asymmetry as largeEstateShapes.
	var assets []asset.Asset
	var edges []asset.Edge
	for i := 0; i < 200; i++ {
		src, dst := fmt.Sprintf("pkg-%d", i), fmt.Sprintf("host-%d", i)
		assets = append(assets, asset.Asset{ID: src, Name: src, Type: "os_package", Provider: "aws"},
			asset.Asset{ID: dst, Name: dst, Type: "ec2_instance", Provider: "aws"})
		edges = append(edges, asset.Edge{SrcID: dst, SrcType: "ec2_instance", DstID: src, DstType: "os_package", EdgeType: "contains_data"})
	}
	for i := 0; i < 100; i++ {
		lb, role := fmt.Sprintf("lb-%d", i), fmt.Sprintf("role-%d", i)
		assets = append(assets, asset.Asset{ID: lb, Name: lb, Type: "load_balancer", Provider: "aws"},
			asset.Asset{ID: role, Name: role, Type: "iam_role", Provider: "aws"})
		edges = append(edges, asset.Edge{SrcID: lb, SrcType: "load_balancer", DstID: role, DstType: "iam_role", EdgeType: "has_role"})
	}

	require.NoError(t, WriteSnapshot(path, GraphSnapshot{
		SchemaVersion: "schema-v-before-the-bump",
		Assets:        assets,
		Edges:         edges,
	}))

	svc, err := Open("", 64, 0, 0, path)
	require.NoError(t, err)
	defer svc.Close()

	err = svc.LoadFromSnapshot(ctx, stubSignals{nil})
	require.ErrorIs(t, err, ErrSnapshotStale,
		"a schema-version mismatch must still refuse to warm-start the GRAPH — there is no in-place Ladybug migration")
	require.False(t, svc.Ready(), "the graph itself must not come up from a stale-schema snapshot")

	// The baseline is armed from the snapshot's shape even though the graph load
	// failed. Replaying the bulk-tier collapse against it — the bulk tier (contains_data)
	// collapses to zero, the critical tier (has_role) survives — must be refused
	// rather than slipping through an empty-baseline fail-open.
	svc.fidelity.mu.Lock()
	baseline := svc.fidelity.baseline
	svc.fidelity.mu.Unlock()
	require.False(t, baseline.empty(), "LoadFromSnapshot must arm the fidelity baseline even on ErrSnapshotStale (case 1)")

	degraded := fidelityShape{
		Assets:     baseline.Assets - 200, // os_package/host rows fall out once edgeless, mirroring filterLadybugAssets
		TotalEdges: 100,
		ByType:     map[string]int{"contains_data": 0, "has_role": 100},
	}
	v := checkFidelity(degraded, baseline, true, "", nil, false)
	require.True(t, v.Refuse, "the armed baseline must catch a degraded first-post-deploy build")
	assert.Contains(t, v.Reason, "contains_data (200 -> 0)")
}

// TestCheckFidelity_ColdStartEscapesLayer1OnRepeat is case 2: Layer 1 has no escape
// while a previous graph is being protected, but sustained ClickHouse pressure on a
// cold start (no graph ever published) must not refuse forever — that is strictly
// worse than a degraded graph for every read path, and no worse for respond's
// proposals, since must_fix_class never fires with nothing built either way.
func TestCheckFidelity_ColdStartEscapesLayer1OnRepeat(t *testing.T) {
	_, degraded := largeEstateShapes()
	var noBaseline fidelityShape

	// Warm case (something IS being served): Layer 1 refuses forever, no escape,
	// exactly as before this hardening.
	warmRefused := &pendingRefusal{shape: degraded, age: minRepeatAge}
	v := checkFidelity(degraded, noBaseline, false, "bulk pass errored", warmRefused, false)
	assert.True(t, v.Refuse, "Layer 1 must never accept a repeat while a graph is being protected")

	// Cold case (nothing being served, e.g. every build since boot has been partial):
	// the same repeated partial fetch, old enough not to be the seconds-scale River
	// retry, now escapes.
	coldRefused := &pendingRefusal{shape: degraded, age: minRepeatAge}
	v = checkFidelity(degraded, noBaseline, false, "bulk pass errored", coldRefused, true)
	require.False(t, v.Refuse, "a cold start under sustained pressure must eventually publish something rather than nothing")
	assert.Equal(t, "cold_start", v.RepeatCategory)

	// The River retry within the cold case is still not a second observation.
	coldRetry := &pendingRefusal{shape: degraded, age: 20 * time.Second}
	v = checkFidelity(degraded, noBaseline, false, "bulk pass errored", coldRetry, true)
	assert.True(t, v.Refuse, "a seconds-scale retry must not bypass minRepeatAge even on a cold start")
}

// TestSyncFromSources_ColdStartPublishesADegradedGraphOnRepeat drives case 2 through
// the real SyncFromSources path: a process that has never published anything, fed a
// self-reported partial fetch twice a correlate interval apart, must end up serving
// SOMETHING rather than refusing forever — and the instant it does, noGraphServed
// flips false and a further partial fetch goes back to refusing unconditionally.
func TestSyncFromSources_ColdStartPublishesADegradedGraphOnRepeat(t *testing.T) {
	ctx := context.Background()
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	assets := []asset.Asset{{ID: "lb-1", Name: "web", Type: "load_balancer", Provider: "aws", RiskScore: 50}}
	edges := []asset.Edge{{SrcID: "lb-1", SrcType: "load_balancer", DstID: "internet", DstType: "internet", EdgeType: "exposed_to_internet"}}
	src := &fidelityEdges{res: asset.EdgeSyncResult{Edges: edges, BulkPassFailed: true}}

	// First ever build, self-reported partial, nothing being served: refused.
	err = svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil})
	require.ErrorIs(t, err, ErrRebuildRefused)
	require.False(t, svc.Ready(), "still cold: nothing published yet")

	// Backdate the refusal past minRepeatAge without ever having published — this is
	// the sustained-pressure cold start, not a warm graph's transient.
	svc.fidelity.mu.Lock()
	svc.fidelity.lastRefusalUnix -= int64((minRepeatAge + time.Minute).Seconds())
	svc.fidelity.mu.Unlock()

	require.NoError(t, svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil}),
		"a cold start must eventually publish rather than refuse forever")
	assert.True(t, svc.Ready())
	assert.Equal(t, int64(1), svc.FidelityStats().RepeatPublishesColdStart)

	// Now something IS being served. A further self-reported partial fetch must go
	// straight back to refusing unconditionally — no escape once there is a graph to
	// protect, even immediately after the cold-start publish.
	svc.fidelity.mu.Lock()
	svc.fidelity.lastRefusalUnix -= int64((minRepeatAge + time.Minute).Seconds())
	svc.fidelity.mu.Unlock()
	err = svc.SyncFromSources(ctx, 0, stubAssets{assets}, src, stubSignals{nil})
	require.ErrorIs(t, err, ErrRebuildRefused,
		"once a graph is being served, Layer 1 must refuse forever again — the escape is cold-start only")
}

// TestCheckFidelity_MonotonicDeclineAcceptsAfterThreeShrinkingSweeps is case 3: a
// multi-day teardown shrinks by more than repeatVolumeTolerance every sweep, so
// sameShapeClass never matches and the step rule never fires. Three consecutive,
// independently-timed refusals that each decline further than the last must publish
// the latest one; two must not, because two points cannot separate a ramp from a dip.
func TestCheckFidelity_MonotonicDeclineAcceptsAfterThreeShrinkingSweeps(t *testing.T) {
	healthy, _ := largeEstateShapes()

	shrink := func(pct float64) fidelityShape {
		s := fidelityShape{
			Assets:     int(float64(healthy.Assets) * pct),
			TotalEdges: int(float64(healthy.TotalEdges) * pct),
			ByType:     map[string]int{},
		}
		for et, n := range healthy.ByType {
			s.ByType[et] = int(float64(n) * pct)
		}
		return s
	}

	day1 := shrink(0.80) // -20%, refused (below minVolumeRatio), streak 1
	day2 := shrink(0.60) // a further decline from day1, streak 2
	day3 := shrink(0.40) // a further decline from day2, streak 3 — now trusted

	// Streak of 1 (first sighting): never accepted, regardless of age.
	v := checkFidelity(day1, healthy, true, "", nil, false)
	require.True(t, v.Refuse)

	// Streak of 2: still not enough — a dip and a second dip cannot yet be told from
	// a ramp that is about to recover.
	afterDay1 := &pendingRefusal{shape: day1, age: minRepeatAge, declineStreak: 1}
	v = checkFidelity(day2, healthy, true, "", afterDay1, false)
	require.True(t, v.Refuse, "two shrinking sweeps are not yet a trend — sameShapeClass doesn't match either, since day2 is a further decline, not a repeat")

	// Streak of 3: the third consecutive, independently-timed decline confirms the
	// direction and publishes.
	afterDay2 := &pendingRefusal{shape: day2, age: minRepeatAge, declineStreak: 2}
	v = checkFidelity(day3, healthy, true, "", afterDay2, false)
	require.False(t, v.Refuse, "three consecutive shrinking sweeps must be trusted as a real teardown")
	assert.Equal(t, "monotonic", v.RepeatCategory)
	assert.Contains(t, v.Reason, "3 consecutive shrinking sweeps")

	// A self-reported partial fetch never gets the monotonic escape, however many
	// times it declines — Layer 1 stands on the report alone.
	v = checkFidelity(day3, healthy, false, "bulk pass errored", afterDay2, false)
	assert.True(t, v.Refuse, "a self-reported partial fetch must never ride the monotonic escape")
}

// TestFidelityState_RecordRefusal_TracksDeclineStreak pins recordRefusal's streak
// bookkeeping directly: it must increment across consecutive DECLINING refusals,
// reset on a refusal that is not a further decline (a repeat, or an unrelated
// degradation), and never be inflated by a flat plateau repeating itself.
func TestFidelityState_RecordRefusal_TracksDeclineStreak(t *testing.T) {
	healthy, _ := largeEstateShapes()
	shrink := func(pct float64) fidelityShape {
		return fidelityShape{Assets: int(float64(healthy.Assets) * pct), TotalEdges: int(float64(healthy.TotalEdges) * pct), ByType: map[string]int{}}
	}

	f := &fidelityState{}
	f.recordRefusal(shrink(0.80), "r1", 1000)
	assert.Equal(t, 1, f.declineStreak)
	f.recordRefusal(shrink(0.60), "r2", 2000)
	assert.Equal(t, 2, f.declineStreak)

	// A flat repeat of the same shape must NOT touch the streak either way — see
	// recordRefusal's doc comment. Resetting the streak to 1 on a flat repeat
	// would break it: River's own retry of ErrRebuildRefused triggers a repeat
	// within seconds of every real refusal, so the streak could never exceed 1
	// by the time the next real sweep's check reads it — case 3 (monotonic
	// decline) could never fire in practice.
	f.recordRefusal(shrink(0.60), "r3", 3000)
	assert.Equal(t, 2, f.declineStreak, "a repeat of the last refused shape must leave the streak unchanged, not reset it")

	f.recordRefusal(shrink(0.40), "r4", 4000)
	assert.Equal(t, 3, f.declineStreak)

	// And a genuinely different, non-declining refusal (neither a repeat nor a
	// further decline) still resets to 1.
	f.recordRefusal(shrink(0.90), "r5", 5000)
	assert.Equal(t, 1, f.declineStreak, "a shape that neither declines nor repeats the last one starts a fresh streak")
}

// TestFidelityState_RecordRefusal_RetryDoesNotResetTheAgeClock is the guard for
// the second half of the same River-retry interaction: minRepeatAge's age must be
// measured from the START of a refusal episode, not from the most recent attempt.
// If EVERY call to recordRefusal (including a retry seconds after the original
// refusal) overwrote lastRefusalUnix with `now`, a persistently-retrying failure
// would never accumulate 25 minutes of age and neither accept-on-repeat rule
// could ever mature — the exact wedge case 4 exists to break.
func TestFidelityState_RecordRefusal_RetryDoesNotResetTheAgeClock(t *testing.T) {
	healthy, _ := largeEstateShapes()
	shrink := func(pct float64) fidelityShape {
		return fidelityShape{Assets: int(float64(healthy.Assets) * pct), TotalEdges: int(float64(healthy.TotalEdges) * pct), ByType: map[string]int{}}
	}

	f := &fidelityState{}
	const episodeStart = int64(1_000_000)
	f.recordRefusal(shrink(0.60), "original refusal", episodeStart)

	// River retries ladybug_rebuild seconds later, re-reading ClickHouse and hitting
	// the identical refused shape again.
	f.recordRefusal(shrink(0.60), "retry", episodeStart+5)
	f.recordRefusal(shrink(0.60), "retry", episodeStart+30)

	_, refused := f.snapshotState(time.Unix(episodeStart+int64(minRepeatAge.Seconds())+1, 0))
	require.NotNil(t, refused)
	assert.GreaterOrEqualf(t, refused.age, minRepeatAge,
		"age must be measured from the FIRST refusal in this episode (%d), not the most recent retry — "+
			"otherwise a persistently-retrying failure never accumulates minRepeatAge and repeat-accept never fires",
		episodeStart)
}

// TestFidelityState_RecordRefusal_NewEpisodeResetsTheAgeClock is the companion
// guard: "the start of the current episode" is not only the very first refusal
// ever (f.refused == nil) — it is also true whenever a genuinely new, unrelated
// shape arrives (declineStreak resets to 1 for the same reason). Refreshing
// lastRefusalUnix only on the nil case would let a brand-new failure inherit the
// age of whatever earlier, unrelated episode was on record. If that earlier
// episode was already older than minRepeatAge, the new failure's very first
// retry — seconds later — could satisfy the age gate immediately and publish
// through accept-on-repeat, which is exactly what minRepeatAge exists to prevent.
func TestFidelityState_RecordRefusal_NewEpisodeResetsTheAgeClock(t *testing.T) {
	healthy, _ := largeEstateShapes()
	shrink := func(pct float64) fidelityShape {
		return fidelityShape{Assets: int(float64(healthy.Assets) * pct), TotalEdges: int(float64(healthy.TotalEdges) * pct), ByType: map[string]int{}}
	}

	f := &fidelityState{}
	const oldEpisodeStart = int64(1_000_000)
	f.recordRefusal(shrink(0.60), "old, unrelated failure", oldEpisodeStart)

	// Time passes — long enough for the OLD episode to have matured past
	// minRepeatAge on its own.
	newEpisodeStart := oldEpisodeStart + int64(minRepeatAge.Seconds()) + 60
	// A genuinely different, unrelated shape arrives: not a repeat of the old
	// refusal, not a further decline from it — a fresh episode.
	f.recordRefusal(shrink(0.90), "new, unrelated failure", newEpisodeStart)

	_, refused := f.snapshotState(time.Unix(newEpisodeStart+5, 0))
	require.NotNil(t, refused)
	assert.Lessf(t, refused.age, minRepeatAge,
		"a genuinely new episode must reset the age clock to its own start (%d), not inherit the age of "+
			"an earlier, unrelated episode (%d) — otherwise its very first retry can pass the age gate immediately",
		newEpisodeStart, oldEpisodeStart)
}

// ─── case 4: a durable refusal survives a crash between refusal and repeat ───────

// TestFidelityPersist_WriteReadClearRoundTrip pins the sidecar file's basic contract:
// round-trips a written record, and a cleared or never-written path reads back as
// "nothing pending" rather than erroring.
func TestFidelityPersist_WriteReadClearRoundTrip(t *testing.T) {
	path := refusalRecordPath(filepath.Join(t.TempDir(), "ladybug.snap"))
	require.NotEmpty(t, path)

	_, ok := readRefusalRecord(path)
	require.False(t, ok, "no file yet: nothing pending")

	rec := refusalRecord{
		Shape:         fidelityShape{Assets: 100, TotalEdges: 200, ByType: map[string]int{"has_role": 200}},
		DeclineStreak: 2,
		RefusedUnix:   12345,
		Reason:        "test reason",
	}
	require.NoError(t, writeRefusalRecord(path, rec))
	got, ok := readRefusalRecord(path)
	require.True(t, ok)
	assert.Equal(t, rec, got)

	clearRefusalRecord(path)
	_, ok = readRefusalRecord(path)
	assert.False(t, ok, "cleared record must read back as nothing pending")
}

// TestFidelityPersist_EmptySnapshotPathIsANoOp: snapshots disabled (no PVC) must
// never attempt to write anywhere — refusalRecordPath returns "" and every function
// downstream is a documented no-op on that path.
func TestFidelityPersist_EmptySnapshotPathIsANoOp(t *testing.T) {
	assert.Equal(t, "", refusalRecordPath(""))
	require.NoError(t, writeRefusalRecord("", refusalRecord{}))
	_, ok := readRefusalRecord("")
	assert.False(t, ok)
	clearRefusalRecord("") // must not panic
}

// TestLoadFromSnapshot_RearmsAPendingRefusalAfterACrash is case 4 end-to-end: a
// worker refuses a rebuild, persists that refusal, then "crashes" (a fresh Service,
// fresh in-memory fidelityState) before minRepeatAge elapses. The next boot's
// LoadFromSnapshot must restore the pending refusal — including its age, computed
// against the ORIGINAL wall-clock timestamp — rather than starting minRepeatAge's
// clock over from the new process's zero state.
func TestLoadFromSnapshot_RearmsAPendingRefusalAfterACrash(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ladybug.snap")
	assets, edges, sigs := digestFixture()

	first, err := Open("", 64, 0, 0, path)
	require.NoError(t, err)
	require.NoError(t, first.SyncFromSources(ctx, 0, stubAssets{assets}, stubEdges{edges}, stubSignals{sigs}))
	require.NoError(t, first.LoadFromSnapshot(ctx, stubSignals{sigs})) // no-op path aside; ensures a snapshot exists (already written by the full sync above)

	// A degraded rebuild is refused, and — the point of this test — persisted to disk
	// with a timestamp already minRepeatAge in the past, mimicking a refusal that
	// happened, then a crash, then a slow restart.
	degraded := fidelityShape{Assets: len(assets) / 2, TotalEdges: len(edges) / 3, ByType: map[string]int{}}
	oldEnough := time.Now().Add(-(minRepeatAge + time.Minute)).Unix()
	rec := refusalRecord{Shape: degraded, DeclineStreak: 1, RefusedUnix: oldEnough, Reason: "simulated pre-crash refusal"}
	require.NoError(t, writeRefusalRecord(refusalRecordPath(path), rec))
	first.Close() // simulate the crash: this process's in-memory fidelityState is gone

	// Second life: a brand-new Service, fresh in-memory state.
	second, err := Open("", 64, 0, 0, path)
	require.NoError(t, err)
	defer second.Close()
	require.NoError(t, second.LoadFromSnapshot(ctx, stubSignals{sigs}))

	second.fidelity.mu.Lock()
	refused := second.fidelity.refused
	streak := second.fidelity.declineStreak
	lastRefusal := second.fidelity.lastRefusalUnix
	second.fidelity.mu.Unlock()
	require.NotNil(t, refused, "LoadFromSnapshot must rearm the pending refusal persisted before the crash")
	assert.Equal(t, degraded, *refused)
	assert.Equal(t, 1, streak)
	assert.Equal(t, oldEnough, lastRefusal,
		"the rearmed refusal's timestamp must be the ORIGINAL wall clock, not the new process's start time — otherwise every crash restarts minRepeatAge's clock (the exact bug this fixes)")

	// snapshotState must now report this refusal as already old enough to repeat,
	// proving the age computation used the restored timestamp end to end.
	_, pending := second.fidelity.snapshotState(time.Now())
	require.NotNil(t, pending)
	assert.GreaterOrEqual(t, pending.age, minRepeatAge)
}
