package explore

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The ClickHouse fallback filters graph_edges.edge_type (snake_case) but its
// callers pass PascalCase rel-table names — before translation a typed
// traversal on the fallback matched zero rows, silently.
func TestCHEdgeTypesTranslatesRelNames(t *testing.T) {
	assert.Equal(t, []string{"exposed_to_internet"}, chEdgeTypes([]string{"ExposedToInternet"}))
	// One rel can be fed by several edge types (Accesses ← runs_in/targets/routes_to).
	assert.ElementsMatch(t, []string{"runs_in", "targets", "routes_to"}, chEdgeTypes([]string{"Accesses"}))
	// snake_case input passes through untouched.
	assert.Equal(t, []string{"can_assume"}, chEdgeTypes([]string{"can_assume"}))
	// Unknown names pass through (they simply match nothing, same as before).
	assert.Equal(t, []string{"NotARel"}, chEdgeTypes([]string{"NotARel"}))
}

// An untyped expand must answer the same question on both engines: the Ladybug
// path traverses only the Expand rel set, so the fallback filters to the edge
// types feeding those rels rather than walking every edge in graph_edges.
func TestExpandEdgeTypesMirrorsLadybugExpandView(t *testing.T) {
	require.NotEmpty(t, expandEdgeTypes)
	for _, et := range expandEdgeTypes {
		assert.Equal(t, strings.ToLower(et), et, "expand filter %q must be snake_case (ClickHouse values)", et)
	}
	assert.Contains(t, expandEdgeTypes, "exposed_to_internet")
	assert.Contains(t, expandEdgeTypes, "has_role")
	assert.NotContains(t, expandEdgeTypes, "contains_data", "ContainsData is loaded but not part of the expand view")
}
