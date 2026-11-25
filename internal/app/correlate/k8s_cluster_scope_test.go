package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestK8sServiceTargets_IgnoresOtherClusters(t *testing.T) {
	const eks = "arn:aws:eks:us-east-1:111:cluster/prod"
	g := NewGraph([]asset.Asset{
		{ID: eks + "/service/prod/web", Type: "k8s_service", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}},
		{ID: eks + "/pod/prod/web-1", Type: "k8s_pod",
			Metadata: map[string]string{"namespace": "prod"}, Tags: map[string]string{"app": "web"}},
		// Same namespace and labels, different cluster: not selected.
		{ID: "arn:aws:eks:us-east-1:111:cluster/staging/pod/prod/web-1", Type: "k8s_pod",
			Metadata: map[string]string{"namespace": "prod"}, Tags: map[string]string{"app": "web"}},
		{ID: "other/deployment/prod/web", Type: "k8s_deployment",
			Metadata: map[string]string{"namespace": "prod"}, Tags: map[string]string{"app": "web"}},
	})
	var dsts []string
	for _, e := range (K8sServiceTargets{}).Correlate(g) {
		if e.EdgeType == EdgeTargets {
			dsts = append(dsts, e.DstID)
		} else {
			require.Equal(t, eks+"/pod/prod/web-1", e.SrcID)
		}
	}
	require.Equal(t, []string{eks + "/pod/prod/web-1"}, dsts)
}

func TestNamespacedClusterOf(t *testing.T) {
	for id, want := range map[string]string{
		"c/pod/ns/name":                        "c",
		"arn:aws:eks:r:1:cluster/x/svc/ns/n":   "arn:aws:eks:r:1:cluster/x",
		"projects/p/clusters/c/service/ns/web": "projects/p/clusters/c",
	} {
		got, ok := namespacedClusterOf(id)
		require.True(t, ok, id)
		require.Equal(t, want, got)
	}
	for _, id := range []string{"pod/ns/name", "/pod/ns/name", "name"} {
		_, ok := namespacedClusterOf(id)
		require.False(t, ok, id)
	}
}
