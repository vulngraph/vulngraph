package asset

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// TestPackageReadersGateOnLiveness pins the package-liveness gate on every
// reader the advisory jobs and their gauge use. Package rows are never deleted,
// so a reader without the gate re-queries every package any scan ever wrote —
// including nodes nothing has run for months — and keeps raising findings on
// them.
func TestPackageReadersGateOnLiveness(t *testing.T) {
	require.Contains(t, livePackageIDs, graphschema.EdgeFreshnessCond,
		"livePackageIDs must only count FRESH edges — graph_edges rows are never deleted, so an unfiltered "+
			"read keeps every package that ever had an edge live forever")
	require.Contains(t, packageCount, "WHERE id IN ("+livePackageIDs+")",
		"packageCount must restrict its pre-aggregation id set to live packages")
}

// TestPackagePageIsKeysetWithoutEdgeScan pins the page query's shape: keyset
// on id (an OFFSET over a set that grows mid-pass skips rows) and no
// graph_edges read (liveness is applied from the once-per-pass live set —
// a per-page edge scan re-derives the window against a moving now()).
func TestPackagePageIsKeysetWithoutEdgeScan(t *testing.T) {
	require.Contains(t, packageCoordsAfter, "id > ?")
	require.NotContains(t, packageCoordsAfter, "OFFSET")
	require.NotContains(t, packageCoordsAfter, "graph_edges")
}

// TestLivePackageIDsMatchRegistry keeps the liveness edge set equal to the
// registry's edge types whose rel lands on a Package node. A new producer edge
// into a package that is missing here would leave its packages dead; an edge
// type here the registry no longer routes to a Package would keep them live on
// a meaning nobody declared.
func TestLivePackageIDsMatchRegistry(t *testing.T) {
	var want []string
	for _, e := range graphschema.EdgeTypes {
		rel, ok := graphschema.RelByName(e.Rel)
		if ok && rel.To == graphschema.NodePackage {
			want = append(want, e.Type)
		}
	}
	require.NotEmpty(t, want, "the registry routes no edge type into a Package node — the derivation is broken")

	m := regexp.MustCompile(`edge_type IN \(([^)]*)\)`).FindStringSubmatch(livePackageIDs)
	require.Len(t, m, 2, "livePackageIDs must filter edge_type with a literal IN list")
	var got []string
	for _, v := range strings.Split(m[1], ",") {
		got = append(got, strings.Trim(strings.TrimSpace(v), "'"))
	}
	sort.Strings(want)
	sort.Strings(got)
	require.Equal(t, want, got)
}
