package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestRepoNameWithoutDomainPrefix(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"alpha_svc-a", "svc-a"},
		{"beta_svc-b-jobs", "svc-b-jobs"},
		// Only the FIRST segment is stripped — the rest of the name is preserved.
		{"gamma_svc_c_infra", "svc_c_infra"},
		// Nothing to strip.
		{"svc-d", ""},
		{"svc-a", ""},
		// Degenerate underscores must not produce an empty or bogus key.
		{"_leading", ""},
		{"trailing_", ""},
		{"_", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			require.Equal(t, tt.want, repoNameWithoutDomainPrefix(tt.in))
		})
	}
}

// eu.gcr.io/<project>/<service> must find the repo named <domain>_<service>:
// exact short-name matching alone finds only a small fraction of image names.
func TestDeploysTo_MatchesRepoBehindDomainPrefix(t *testing.T) {
	repo := asset.Asset{ID: "example-corp/alpha_svc-a", Type: "github_repo"}
	workload := asset.Asset{
		ID: "example-cluster/pod/ns-a/svc-a-x", Type: "k8s_pod",
		Metadata: map[string]string{
			"images": "eu.gcr.io/example-project/svc-a:5cb1f5f8",
		},
	}
	g := NewGraph([]asset.Asset{repo, workload})

	edges := DeploysTo{}.Correlate(g)

	require.Len(t, edges, 1)
	require.Equal(t, repo.ID, edges[0].SrcID)
	require.Equal(t, workload.ID, edges[0].DstID)
	require.Equal(t, EdgeDeploysTo, edges[0].EdgeType)
	require.Equal(t, "gcr_image_domain_prefix", edges[0].Properties["matched_via"],
		"a prefix-stripped hit must be distinguishable from an exact one")
	require.Equal(t, "medium", edges[0].Properties["confidence"])
}

// An exact short-name hit keeps its own provenance string, distinct from a
// prefix-stripped one.
func TestDeploysTo_ExactNameKeepsOriginalProvenance(t *testing.T) {
	repo := asset.Asset{ID: "example-corp/svc-d", Type: "github_repo"}
	workload := asset.Asset{
		ID: "example-cluster/pod/ns-d/svc-d-x", Type: "k8s_pod",
		Metadata: map[string]string{"images": "eu.gcr.io/example-project/svc-d:abc"},
	}
	g := NewGraph([]asset.Asset{repo, workload})

	edges := DeploysTo{}.Correlate(g)

	require.Len(t, edges, 1)
	require.Equal(t, "gcr_image", edges[0].Properties["matched_via"])
}

// A repo whose name has no prefix must not gain a duplicate index entry and
// emit two edges for one image.
func TestDeploysTo_NoDuplicateEdgeForUnprefixedRepo(t *testing.T) {
	repo := asset.Asset{ID: "example-corp/svc-d", Type: "github_repo"}
	workload := asset.Asset{
		ID: "example-cluster/pod/ns-d/svc-d-x", Type: "k8s_pod",
		Metadata: map[string]string{"images": "eu.gcr.io/example-project/svc-d:abc"},
	}
	g := NewGraph([]asset.Asset{repo, workload})

	require.Len(t, DeploysTo{}.Correlate(g), 1)
}

// A stripped name can hit more than one repo: each gets its own edge rather
// than one winner picked arbitrarily.
func TestDeploysTo_AmbiguousStrippedNameEmitsEdgePerRepo(t *testing.T) {
	a := asset.Asset{ID: "example-corp/alpha_svc-e", Type: "github_repo"}
	b := asset.Asset{ID: "example-corp/beta_svc-e", Type: "github_repo"}
	workload := asset.Asset{
		ID: "example-cluster/pod/ns-e/svc-e-x", Type: "k8s_pod",
		Metadata: map[string]string{"images": "eu.gcr.io/example-project/svc-e:abc"},
	}
	g := NewGraph([]asset.Asset{a, b, workload})

	edges := DeploysTo{}.Correlate(g)

	require.Len(t, edges, 2)
	got := []string{edges[0].SrcID, edges[1].SrcID}
	require.ElementsMatch(t, []string{a.ID, b.ID}, got)
}
