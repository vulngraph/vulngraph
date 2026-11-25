package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestGhcrRepo(t *testing.T) {
	tests := []struct {
		image string
		want  string
		ok    bool
	}{
		{"ghcr.io/example/payments-api:v1.2.3", "example/payments-api", true},
		{"ghcr.io/example/payments-api@sha256:abc", "example/payments-api", true},
		{"ghcr.io/example/payments-api/sidecar:latest", "example/payments-api", true},
		{"ghcr.io/example/payments-api", "example/payments-api", true},
		{"gcr.io/proj/app:tag", "", false},
		{"docker.io/library/nginx:latest", "", false},
		{"ghcr.io/example", "", false}, // no repo segment
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := ghcrRepo(tt.image)
		require.Equalf(t, tt.ok, ok, "ok for %q", tt.image)
		require.Equalf(t, tt.want, got, "repo for %q", tt.image)
	}
}

func TestDeploysTo_GhcrImageMatch_HighConfidence(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "example/payments-api", Type: "github_repo"},
		{ID: "prod/pod/payments-7f", Type: "k8s_pod", Metadata: map[string]string{
			"images": "ghcr.io/example/payments-api:v1,ghcr.io/example/sidecar:v1",
		}},
	})
	edges := DeploysTo{}.Correlate(g)
	require.Len(t, edges, 1, "only the repo that exists in the graph links")
	e := edges[0]
	require.Equal(t, "example/payments-api", e.SrcID)
	require.Equal(t, "github_repo", e.SrcType)
	require.Equal(t, "prod/pod/payments-7f", e.DstID)
	require.Equal(t, EdgeDeploysTo, e.EdgeType)
	require.Equal(t, "high", e.Properties["confidence"])
	require.Equal(t, "ghcr_image", e.Properties["matched_via"])
	require.Equal(t, edgeOrigin, e.Properties["origin"])
}

func TestDeploysTo_LabelMatch_MediumConfidence(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "example/checkout", Type: "github_repo"},
		{ID: "prod/deploy/checkout", Type: "k8s_deployment", Tags: map[string]string{
			"app.kubernetes.io/name": "checkout",
		}},
	})
	edges := DeploysTo{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "example/checkout", edges[0].SrcID)
	require.Equal(t, "medium", edges[0].Properties["confidence"])
	require.Equal(t, "label", edges[0].Properties["matched_via"])
}

func TestDeploysTo_ImageWinsOverLabel_NoDuplicate(t *testing.T) {
	// Same repo reachable by both an exact image match and a label — emit once,
	// at the higher (image) confidence.
	g := NewGraph([]asset.Asset{
		{ID: "example/api", Type: "github_repo"},
		{ID: "prod/pod/api", Type: "k8s_pod",
			Metadata: map[string]string{"images": "ghcr.io/example/api:v1"},
			Tags:     map[string]string{"app.kubernetes.io/name": "api"},
		},
	})
	edges := DeploysTo{}.Correlate(g)
	require.Len(t, edges, 1, "one edge per repo→workload pair")
	require.Equal(t, "high", edges[0].Properties["confidence"])
}

func TestDeploysTo_NoMatch(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "example/other", Type: "github_repo"},
		{ID: "prod/pod/x", Type: "k8s_pod", Metadata: map[string]string{
			"images": "gcr.io/proj/unrelated:v1", // not ghcr, no repo in graph
		}},
	})
	require.Empty(t, DeploysTo{}.Correlate(g))
}
