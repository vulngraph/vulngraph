package asset

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// bulkEdgesQ must order before capping so truncation is deterministic across
// rebuilds, cap per type so one high-volume type can't starve the rest, and
// spill both the GROUP BY and the ORDER BY to disk (the code-241 OOM guard).
func TestBulkEdgesQIsDeterministicAndCapped(t *testing.T) {
	perType := fmt.Sprintf("LIMIT %d BY edge_type", syncBulkPerTypeLimit)
	require.Contains(t, bulkEdgesQ, "ORDER BY edge_type, src_id, dst_id")
	require.Contains(t, bulkEdgesQ, perType)
	require.Contains(t, bulkEdgesQ, "max_bytes_before_external_group_by")
	require.Contains(t, bulkEdgesQ, "max_bytes_before_external_sort")
	require.Greater(t, strings.Index(bulkEdgesQ, perType),
		strings.Index(bulkEdgesQ, "ORDER BY"), "per-type cap must apply after the sort")
}

// Truncation accounting must read the BULK rows only. The critical and bulk
// passes now scan into one slice (concatenating two full slices at the end built
// an extra copy of the whole edge set at the peak of the graph rebuild), so the
// accounting is separated by an index instead of by two variables — and an index
// off by a pass would report an uncapped critical type as partially covered,
// which fails ReachComplete and fails every finding open on that path to
// "unknown".
func TestBulkTruncationCountsBulkRowsOnly(t *testing.T) {
	edge := func(et string) Edge { return Edge{SrcID: "a", DstID: "b", EdgeType: et} }
	all := []Edge{
		// Critical pass: uncapped, so no count here can mean truncation.
		edge("can_assume"), edge("can_assume"), edge("can_assume"),
		// Bulk pass.
		edge("depends_on"), edge("depends_on"), edge("connected_via_sg"),
	}
	const criticalCount = 3

	// Nothing at a cap.
	require.Empty(t, bulkTruncation(all, criticalCount, 3, 10))

	// A bulk type at its per-type cap is partial; the critical type with the same
	// row count is not, because it was never capped.
	require.Equal(t, map[string]bool{"depends_on": true},
		bulkTruncation(all, criticalCount, 2, 10))

	// Reading the critical rows as bulk would (wrongly) flag can_assume — a reach
	// type — as truncated.
	require.True(t, bulkTruncation(all, 0, 3, 10)["can_assume"],
		"guard: the offset is what keeps critical rows out of the accounting")

	// The shared total cap can't be attributed per type: every bulk type is partial.
	total := bulkTruncation(all, criticalCount, 100, 3)
	require.NotEmpty(t, bulkEdgeTypes)
	for _, et := range bulkEdgeTypes {
		require.True(t, total[et], "%s must be marked partial when the total cap fires", et)
	}
	require.False(t, total["can_assume"], "critical types are never capped by the bulk total")
}

// ReachComplete is what stands between a truncated fetch and silently demoted
// must-fix findings: any truncated reach type, or a failed bulk pass while a
// reach type lives in the bulk tier, must report incomplete.
func TestEdgeSyncResultReachComplete(t *testing.T) {
	require.True(t, EdgeSyncResult{}.ReachComplete())

	require.False(t, EdgeSyncResult{
		TruncatedTypes: map[string]bool{"executes_as": true},
	}.ReachComplete(), "a truncated reach type is incomplete")

	require.True(t, EdgeSyncResult{
		TruncatedTypes: map[string]bool{"depends_on": true},
	}.ReachComplete(), "truncating a non-reach context type is fine")

	// Containment (Inherit) types carry reachability into packages without costing a
	// hop, so truncating one hides a real path exactly like truncating a reach type.
	require.False(t, EdgeSyncResult{
		TruncatedTypes: map[string]bool{"runs_image": true},
	}.ReachComplete(), "a truncated containment type is incomplete")
	require.False(t, EdgeSyncResult{
		TruncatedTypes: map[string]bool{"runs_package": true},
	}.ReachComplete(), "a truncated containment type is incomplete")

	// The containment types are critical-tier alongside the reach
	// types (graphschema.TestReachAndInheritTypesAreCritical enforces it), so a
	// failed BULK pass no longer costs reachability anything: the critical pass is
	// separate and uncapped. This flipped from false — it is the point of the tier
	// move. While the containment types sat in the bulk tier, the tier's shared
	// 500k cap was starving all three to zero rows on every build, so this function
	// returned false on every build and the "contained" demotions were
	// globally disabled.
	require.True(t, EdgeSyncResult{BulkPassFailed: true}.ReachComplete(),
		"no reach or containment type is bulk-tier any more, so a bulk-pass failure cannot invalidate reach")

	// The reason that holds. If any reach/inherit type is ever moved back to the
	// bulk tier, this fails and the assertion above becomes wrong at the same time.
	for t2 := range graphschema.ReachEdgeTypes() {
		require.NotEqual(t, graphschema.TierBulk, graphschema.TierOf(t2), "reach type %q is bulk-tier", t2)
	}
	for t2 := range graphschema.InheritEdgeTypes() {
		require.NotEqual(t, graphschema.TierBulk, graphschema.TierOf(t2), "inherit type %q is bulk-tier", t2)
	}
}
