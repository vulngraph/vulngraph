package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// saPod builds a k8s_pod asset with the ID shape the real collector uses
// ("<cluster>/pod/<ns>/<name>", collect/kubernetes/kubernetes.go's podAsset) —
// serviceAccountIDFor derives the cluster from this ID via clusterPrefixOf, not
// from Region (repo.go's loadView never selects region, so Region is always ""
// in production; this fixture must not paper over that by setting Region, or
// the test proves nothing about the bug it exists to catch).
func saPod(cluster, ns, name, sa string) asset.Asset {
	meta := map[string]string{"namespace": ns}
	if sa != "" {
		meta["service_account"] = sa
	}
	id := name
	if cluster != "" {
		id = cluster + "/pod/" + ns + "/" + name
	}
	return asset.Asset{
		ID:       id,
		Name:     name,
		Type:     "k8s_pod",
		Metadata: meta,
	}
}

func TestK8sPodServiceAccount(t *testing.T) {
	t.Run("emits the pod→ServiceAccount edge when both are collected", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			saPod("prod", "payments", "api-abc123", "api"),
			k8sSA("prod", "payments", "api"),
		})
		edges := K8sPodServiceAccount{}.Correlate(g)
		require.Len(t, edges, 1)
		e := edges[0]
		require.Equal(t, "prod/pod/payments/api-abc123", e.SrcID)
		require.Equal(t, "k8s_pod", e.SrcType)
		require.Equal(t, "prod/namespace/payments/serviceaccount/api", e.DstID)
		require.Equal(t, "k8s_service_account", e.DstType)
		require.Equal(t, EdgeExecutesAs, e.EdgeType)
		require.Equal(t, "k8s_pod_service_account", e.Properties["rule"])
	})

	t.Run("a pod naming no ServiceAccount resolves to default", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			saPod("prod", "payments", "api-abc123", ""),
			k8sSA("prod", "payments", "default"),
		})
		edges := K8sPodServiceAccount{}.Correlate(g)
		require.Len(t, edges, 1)
		require.Equal(t, "prod/namespace/payments/serviceaccount/default", edges[0].DstID)
	})

	t.Run("no edge when the ServiceAccount is not collected", func(t *testing.T) {
		// The dark-cluster case: a dangling edge is strictly worse than none, since
		// a missing edge shows up in coverage and a dangling one does not.
		g := NewGraph([]asset.Asset{saPod("prod", "payments", "api-abc123", "api")})
		require.Empty(t, K8sPodServiceAccount{}.Correlate(g))
	})

	t.Run("does not cross clusters", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			saPod("prod", "payments", "api-abc123", "api"),
			k8sSA("staging", "payments", "api"),
		})
		require.Empty(t, K8sPodServiceAccount{}.Correlate(g))
	})

	t.Run("does not cross namespaces", func(t *testing.T) {
		g := NewGraph([]asset.Asset{
			saPod("prod", "payments", "api-abc123", "api"),
			k8sSA("prod", "billing", "api"),
		})
		require.Empty(t, K8sPodServiceAccount{}.Correlate(g))
	})

	t.Run("deployments are skipped", func(t *testing.T) {
		dep := saPod("prod", "payments", "api", "api")
		dep.Type = "k8s_deployment"
		dep.ID = "prod/namespace/payments/deployment/api"
		g := NewGraph([]asset.Asset{dep, k8sSA("prod", "payments", "api")})
		require.Empty(t, K8sPodServiceAccount{}.Correlate(g))
	})

	t.Run("a pod with no cluster emits nothing", func(t *testing.T) {
		pod := saPod("", "payments", "api-abc123", "api")
		g := NewGraph([]asset.Asset{pod, k8sSA("", "payments", "api")})
		require.Empty(t, K8sPodServiceAccount{}.Correlate(g))
	})
}
