package graphstore

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// TestPropagateRiskReportsWriteFailure is the guard for a defect found in the
// shipped gate: propagateRisk was "best-effort", so a failed BFS write
// returned the full boost map anyway, the caller stashed boosts the graph never
// received, every later sweep no-op'd against the wrong live value, and refreshScores'
// own diff then skipped those nodes because the stash already agreed.
//
// Before the gate a transient write failure self-healed on the next full rebuild.
// After it, the damage was permanent until an unrelated topology change — and the
// likely trigger (Ladybug write errors under memory pressure) is a realistic
// situation for a memory-constrained worker. So the boolean is load-bearing, not cosmetic.
func TestPropagateRiskReportsWriteFailure(t *testing.T) {
	ctx := context.Background()

	t.Run("a failing UNWIND SET must report failure", func(t *testing.T) {
		// A Ladybug db with NO schema applied: the node tables do not exist, so every
		// `MATCH (n:Asset ...)` returns a real error. This exercises the same error
		// return that a Ladybug write failure under memory pressure would take, without
		// the native segfault that operating on a closed handle causes.
		db, err := openLadybug(":memory:", 64, 0, 0)
		require.NoError(t, err)
		defer db.close()

		assets := []asset.Asset{
			{ID: "lb-1", Type: "load_balancer", Provider: "aws", RiskScore: 50},
			{ID: "role-1", Type: "iam_role", Provider: "aws", RiskScore: 10},
		}
		edges := []asset.Edge{{SrcID: "lb-1", SrcType: "load_balancer", DstID: "role-1",
			DstType: "iam_role", EdgeType: "has_role", Properties: map[string]string{}}}

		boosted, applied, err := propagateRisk(ctx, db, assets, edges)
		require.NoError(t, err)
		require.NotEmpty(t, boosted, "fixture must produce at least one boost to be meaningful")
		require.False(t, applied,
			"a BFS write that errored must report failure, or the caller stashes scores "+
				"the graph never received and no later sweep ever repairs them")
	})

	t.Run("nothing to write is not a failure", func(t *testing.T) {
		db, err := openAndInit(64, 0, 0)
		require.NoError(t, err)
		defer db.close()
		// No edges means no boosts, so there is nothing that could fail to land.
		_, applied, err := propagateRisk(ctx, db, nil, nil)
		require.NoError(t, err)
		require.True(t, applied)
	})
}

// TestRefreshScoresRefusesOversizedDiff pins the cap that keeps the in-place path from
// being the worse option. The UNWIND SET runs under the reader-blocking swap lock, and
// the row maps are a large transient allocation — both unbounded before this. Past the
// cap the off-side full rebuild is strictly better: it never holds the read lock.
func TestRefreshScoresRefusesOversizedDiff(t *testing.T) {
	svc, err := Open("", 64, 0, 0, "")
	require.NoError(t, err)
	defer svc.Close()

	// A stash that disagrees with every asset, so every asset is "changed".
	stash := map[string]uint8{}
	assets := make([]asset.Asset, maxScoreRefreshRows+10)
	for i := range assets {
		id := fmt.Sprintf("i-%06d", i)
		assets[i] = asset.Asset{ID: id, Type: "load_balancer", Provider: "aws", RiskScore: 7}
		stash[id] = 99 // differs from whatever finalRiskScores computes
	}
	svc.lastScores.Store(&stash)

	err = svc.refreshScores(context.Background(), assets, nil)
	require.Error(t, err, "an oversized diff must refuse and let the caller rebuild off-side")
	require.Contains(t, err.Error(), "maxScoreRefreshRows")
}

// TestScoreRowsByLabelRoutesEachRowExactlyOnce is the guard for the write
// amplification propagateRisk carried until now: it built ONE row slice from the boost
// map and sent it to all four bfsScoreLabels, relying on MATCH to discard the ~3/4 of
// rows belonging to another label. Correct, and four full MATCH passes over the whole
// boost set — inside the phase that dominates rebuild time.
//
// The routing rule has to be the LOADER's rule (NodeLabelFor over the asset type,
// restricted to the labels whose `score` column holds asset.RiskScore, first
// occurrence wins), because a row sent to a label the node was not loaded under
// matches nothing and silently drops that node's score.
func TestScoreRowsByLabelRoutesEachRowExactlyOnce(t *testing.T) {
	assets := []asset.Asset{
		{ID: "a1", Type: "load_balancer"},   // NodeAsset
		{ID: "r1", Type: "iam_role"},        // NodeIamRole
		{ID: "w1", Type: "k8s_deployment"},  // NodeK8sWorkload
		{ID: "s1", Type: "subnet"},          // NodeSubnet
		{ID: "p1", Type: "package"},         // NodePackage: score is a finding severity
		{ID: "a1", Type: "iam_role"},        // duplicate id under another type
		{ID: "skip", Type: "load_balancer"}, // rowFor declines it
	}
	rows, total, err := scoreRowsByLabel(assets, func(id string) (int32, bool) {
		if id == "skip" {
			return 0, false
		}
		return 42, true
	}, 0)
	require.NoError(t, err)

	require.Equal(t, 4, total, "one row per score-bearing node, not one row per node per label")
	require.Len(t, rows[NodeAsset], 1)
	require.Len(t, rows[NodeIamRole], 1)
	require.Len(t, rows[NodeK8sWorkload], 1)
	require.Len(t, rows[NodeSubnet], 1)
	require.Empty(t, rows[NodePackage],
		"Package's score column holds sig.MaxScore, a finding severity — writing a "+
			"RiskScore-derived value there creates a divergence rather than fixing one")

	// No id may appear under two labels: the duplicate a1/iam_role must lose to the
	// first occurrence, exactly as streamNodeRows' dedup does.
	seen := map[string]string{}
	for label, rs := range rows {
		for _, r := range rs {
			id, ok := r["id"].(string)
			require.True(t, ok)
			require.NotContains(t, seen, id,
				"%s appears under both %s and %s — the loader emits one node per id, so the "+
					"score write must too", id, seen[id], label)
			seen[id] = label
		}
	}
	require.Equal(t, NodeAsset, seen["a1"], "first occurrence wins, matching streamNodeRows")
}

// TestScoreRowsByLabelAbortsBeforeMaterialisingOverTheCap pins the ordering the memory
// argument depends on: the cap must trip DURING construction, not after.
// refreshScores runs on a memory-constrained worker and the diff is unbounded (a cold
// stash makes it the whole corpus), so "build it all then check the size" is the
// failure this prevents.
func TestScoreRowsByLabelAbortsBeforeMaterialisingOverTheCap(t *testing.T) {
	assets := make([]asset.Asset, 0, 50)
	for i := 0; i < 50; i++ {
		assets = append(assets, asset.Asset{ID: fmt.Sprintf("a%d", i), Type: "load_balancer"})
	}
	rows, total, err := scoreRowsByLabel(assets, func(string) (int32, bool) { return 1, true }, 10)
	require.Error(t, err, "over the cap must be an error, so the caller falls back to the off-side rebuild")
	require.Nil(t, rows, "the oversized diff must not be returned — that is the allocation being avoided")
	require.Equal(t, 11, total, "must abort at cap+1, not after walking every asset")
}
