package coverage

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// namedQueries is every measurement this package runs. The tests below are the
// method discipline made mechanical: a document that states its method and then
// uses a different one is worse than no document.
func namedQueries() map[string]string {
	return map[string]string{
		"qFreshAssetsByType":           qFreshAssetsByType,
		"qFreshAssetMetadataKeys":      qFreshAssetMetadataKeys,
		"qOpenFindingBands":            qOpenFindingBands,
		"qOpenFindingResourceTypes":    qOpenFindingResourceTypes,
		"qFindingSourceLiveness":       qFindingSourceLiveness,
		"qOpenFindingsByCheck":         qOpenFindingsByCheck,
		"qOpenFindingChecksByCategory": qOpenFindingChecksByCategory,
		"qFreshEdgesBySrc":             qFreshEdgesBySrc,
		"qFreshEdgesByDst":             qFreshEdgesByDst,
		"qFreshAssetMetaValues":        qFreshAssetMetaValues,
	}
}

// FINAL on a filtered lookup disables skip indexes and full-scans the table,
// which drives CPU utilization up on large tables.
func TestCoverageQueriesNeverUseFinal(t *testing.T) {
	for name, q := range namedQueries() {
		assert.NotContains(t, strings.ToUpper(q), " FINAL", "%s uses FINAL", name)
	}
}

func TestCoverageQueriesDedupWithArgMax(t *testing.T) {
	for name, q := range namedQueries() {
		assert.Contains(t, q, "argMax(", "%s reads a ReplacingMergeTree without deduping", name)
		assert.Contains(t, q, "GROUP BY", "%s must group its dedup subquery", name)
	}
}

// Every graph_edges reader applies graphschema.EdgeFreshnessCond:
// edges are never deleted, only re-stamped, so an unfiltered reader resurrects
// topology that no longer exists.
func TestEdgeQueriesApplyFreshness(t *testing.T) {
	for name, q := range namedQueries() {
		if !strings.Contains(q, "graph_edges") {
			continue
		}
		assert.Contains(t, q, graphschema.EdgeFreshnessCond, "%s reads graph_edges without the freshness condition", name)
	}
}

func TestAssetQueriesApplyFreshness(t *testing.T) {
	for name, q := range namedQueries() {
		if !strings.Contains(q, "FROM assets") {
			continue
		}
		assert.Contains(t, q, AssetFreshness, "%s reads assets without the freshness window", name)
	}
}

// TestAssetFreshnessQueriesProvideHighWater is the guard AssetFreshness's own
// self-containment gap needs: it references high_water, a column only a
// window-function subquery provides — a query that copy-pastes the
// AssetFreshness constant (passing TestAssetQueriesApplyFreshness above)
// without also computing that column would still pass this substring check
// and then fail at runtime with "Unknown identifier: high_water".
func TestAssetFreshnessQueriesProvideHighWater(t *testing.T) {
	for name, q := range namedQueries() {
		if !strings.Contains(q, AssetFreshness) {
			continue
		}
		assert.Contains(t, q, "AS high_water", "%s uses AssetFreshness but never computes high_water", name)
	}
}

// Open is resolved_at = toDateTime(0). The liveness query deliberately
// counts both, so it is asserted separately rather than exempted silently.
func TestFindingQueriesDefineOpenTheSameWay(t *testing.T) {
	openQueries := []string{"qOpenFindingBands", "qOpenFindingResourceTypes", "qOpenFindingsByCheck", "qOpenFindingChecksByCategory"}
	qs := namedQueries()
	for _, name := range openQueries {
		require.Contains(t, qs, name)
		assert.Contains(t, qs[name], "WHERE resolved_at = toDateTime(0)", "%s must use the platform's definition of open", name)
	}
	assert.Contains(t, qs["qFindingSourceLiveness"], "countIf(resolved_at = toDateTime(0))",
		"source liveness reports open and total, so it filters neither")
}

// Edge dedup must match the table's ORDER BY (src_id, edge_type, dst_id);
// grouping by less collapses distinct edges into one.
func TestEdgeDedupMatchesTheTableOrderBy(t *testing.T) {
	for _, q := range []string{qFreshEdgesBySrc, qFreshEdgesByDst} {
		assert.Contains(t, q, "GROUP BY src_id, edge_type, dst_id")
		assert.Contains(t, q, "max(synced_at)")
	}
}

func TestBandQueryTakesItsBandNamesAsParameters(t *testing.T) {
	assert.Contains(t, qOpenFindingBands, "countIf(score_band = ?)",
		"band names come from enrich.Band, not from a string typed into the query")
	assert.Equal(t, 2, strings.Count(qOpenFindingBands, "?"), "page and high, nothing else")
}
