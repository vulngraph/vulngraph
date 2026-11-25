package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func k8sClusterAsset(meta map[string]string) asset.Asset {
	return asset.Asset{
		ID: "example-connector-cluster/cluster", Name: "example-cluster", Type: "k8s_cluster",
		Provider: asset.ProviderKubernetes, Metadata: meta,
	}
}

func TestK8sClusterIdentityMismatch(t *testing.T) {
	tests := []struct {
		name  string
		meta  map[string]string
		fires bool
	}{
		{
			name: "configured name is not the cluster's own name",
			// The typical shape: connector configured "example-connector-cluster", GKE says "example-cluster".
			meta:  map[string]string{"configured_name": "example-connector-cluster", "discovered_name": "example-cluster"},
			fires: true,
		},
		{
			name: "names agree",
			meta: map[string]string{"configured_name": "example-cluster", "discovered_name": "example-cluster"},
		},
		{
			name: "cluster stated no name (EKS issuer carries only an opaque id)",
			meta: map[string]string{"configured_name": "prod", "cloud_provider": "aws"},
		},
		{
			name: "discovered_name present but empty is not a name to disagree with",
			meta: map[string]string{"configured_name": "prod", "discovered_name": ""},
		},
		{
			name: "nothing observed at all",
			meta: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.fires, k8sClusterIdentityMismatch.Violates(k8sClusterAsset(tt.meta)))
		})
	}
}

// The finding must carry the two names, or a responder learns that something
// disagrees without learning what to set.
func TestK8sClusterIdentityMismatch_Evidence(t *testing.T) {
	r := NewRegistry()
	r.Register(k8sClusterIdentityMismatch)
	found := r.Run([]asset.Asset{k8sClusterAsset(map[string]string{
		"configured_name":  "example-connector-cluster",
		"discovered_name":  "example-cluster",
		"cloud_cluster_id": "example-gke-project/gke/europe-west4/example-cluster",
	})}, time.Now())

	require.Len(t, found, 1)
	require.Equal(t, "example-connector-cluster", found[0].Metadata["configured_name"])
	require.Equal(t, "example-cluster", found[0].Metadata["discovered_name"])
	require.Equal(t, "example-gke-project/gke/europe-west4/example-cluster", found[0].Metadata["cloud_cluster_id"])
	require.Equal(t, "example-connector-cluster/cluster", found[0].ResourceID)
}

// The registry stamps RequiredKeys from the AST; an unobserved identity must
// leave the check unable to conclude, so a stored finding is never closed as
// fixed on silence that only means "the cluster did not answer".
func TestK8sClusterIdentityMismatch_NotEvaluableWhenIdentityUnobserved(t *testing.T) {
	r := NewRegistry()
	r.Register(k8sClusterIdentityMismatch)
	c, ok := r.ByID("k8s-cluster-identity-mismatch")
	require.True(t, ok)
	require.Equal(t, []string{"configured_name", "discovered_name"}, c.RequiredKeys)

	require.False(t, c.Evaluable(k8sClusterAsset(map[string]string{"configured_name": "prod"})),
		"discovered_name absent: some value of it would have fired")
	require.True(t, c.Evaluable(k8sClusterAsset(map[string]string{
		"configured_name": "example-cluster", "discovered_name": "example-cluster",
	})))
}
