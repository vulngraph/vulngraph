package asset

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// The two graph-input queries must both apply the ephemeral-liveness filter.
// They are the only readers that decide what the GRAPH contains — the Ladybug bulk
// sync and the correlation view — so a missing filter here silently repopulates
// the graph with dead resources and, worse, lets correlation derive fresh edges
// for them (e.g. pod internet-exposure reported on pods deleted weeks earlier).
//
// correlate's loadView is guarded by the sibling test in that package; this one
// covers the sync query and pins the predicate's own properties.
func TestListAllForSyncAppliesEphemeralLiveness(t *testing.T) {
	require.Contains(t, listAllForSyncQ, EphemeralLivenessCond,
		"the Ladybug bulk-sync query must exclude dead ephemeral resources")
}

func TestEphemeralLivenessCondProperties(t *testing.T) {
	c := EphemeralLivenessCond

	// Anchored to the data's own high-water mark, never wall-clock: a
	// broken collector must freeze the cutoff, not mass-drop the estate.
	require.Contains(t, c, "SELECT max(hw.last_seen)")

	// The inner table is aliased and the subquery's predicate is qualified. Left
	// unqualified, `WHERE type = 'k8s_pod'` binds to whatever `type` is in scope
	// where the condition is applied — and several callers apply it over a
	// projection that also exposes `type`. The high-water lookup then filters on
	// the OUTER row, matches nothing for every non-pod row, and judges it deleted.
	require.Contains(t, c, "assets AS hw",
		"the high-water subquery must alias its table so its predicate cannot bind to a caller's projection")
	require.Contains(t, c, "hw.type = 'k8s_pod'",
		"the high-water predicate must be qualified to the aliased table")
	require.NotContains(t, c, "now()",
		"a wall-clock cutoff would delete the estate the moment a collector broke")

	// last_seen, not row presence — asset rows are never deleted.
	require.Contains(t, c, "last_seen")

	// A grace period absorbs missed ticks.
	require.Contains(t, c, "INTERVAL 72 HOUR")

	// Scoped to types where absence genuinely means the resource is gone. Cloud
	// resource types must NOT be here: most assets are older than the grace
	// window and most stale ones are victims of slow collection, not deletions. gce_instance in
	// particular is deliberately excluded even though it churns like a pod does
	// (GKE/spot node churn) — it is a cloud resource type, and most stale rows
	// are still tagged status=RUNNING at last observation, exactly the
	// "victim of broken collection" case this condition must never touch.
	require.Contains(t, c, "'k8s_pod'")
	require.Contains(t, c, "'container'")
	require.Contains(t, c, "'k8s_job'")
	for _, notEphemeral := range []string{"iam_role", "ec2_instance", "s3_bucket", "gcp_service_account", "gce_instance"} {
		require.NotContains(t, c, notEphemeral,
			"%s persists when uncollected — filtering it would delete real inventory", notEphemeral)
	}

	// The type guard must be an OR so non-ephemeral types pass unfiltered.
	require.Contains(t, c, "type NOT IN ('k8s_pod', 'container', 'k8s_job') OR")
}

// EphemeralLivenessCond embeds a CORRELATED subquery — `SELECT max(last_seen)
// FROM assets WHERE type = 'k8s_pod'`. If the SELECT that wraps the condition
// aliases an aggregate back to `type` or `last_seen`, that alias enters scope for
// the subquery, whose `WHERE type = ...` then resolves against the OUTER row
// instead of the assets table it names. The high-water lookup returns nothing for
// every non-pod row, and a 200-day-old iam_role — which the condition is supposed
// to short-circuit to live — is judged gone.
//
// That shipped, and only the integration test caught it, in CI, after the push.
// The identical shadowing bug appeared the same day in cmd/coverage-gen's edge
// queries, where ClickHouse at least rejected it outright with
// ILLEGAL_AGGREGATION rather than silently returning the wrong rows.
//
// This is the cheap half of that guard: it needs no database, so it fails in the
// unit suite before anyone pushes.
func TestQueriesEmbeddingLivenessDoNotShadowItsColumns(t *testing.T) {
	// The columns EphemeralLivenessCond reads, and which its correlated subquery
	// must resolve against `assets` rather than against an enclosing projection.
	shadowed := []string{"type", "last_seen"}

	for name, q := range map[string]string{
		"liveAssetIDs":      liveAssetIDs,
		"driftNewAssets":    driftNewAssets,
		"driftNewExposures": driftNewExposures,
		"pgAssetContext":    pgAssetContext,
	} {
		require.Contains(t, q, EphemeralLivenessCond,
			"%s is in this table because it embeds the condition — keep them together", name)

		for _, col := range shadowed {
			// An aggregate aliased straight back to the column name is the defect.
			// A plain re-projection (`asset_type AS type`) is the fix and must stay
			// allowed, so match only on an aggregate call preceding the alias.
			bad := regexp.MustCompile(`(?i)(argMax|max|any|anyLast)\s*\([^)]*\)\s+AS\s+` + col + `\b`)
			require.NotRegexpf(t, bad, q,
				"%s aliases an aggregate to %q in a SELECT that embeds EphemeralLivenessCond. "+
					"That shadows the column its correlated subquery resolves against — alias to a "+
					"different name and re-project (see liveAssetIDs).", name, col)
		}
	}
}
