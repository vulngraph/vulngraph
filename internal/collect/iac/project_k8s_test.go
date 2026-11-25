package iac

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProjectDeclaredK8s_AssetsCarryJoinMetadata(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	decls := []DeclaredK8sWorkload{
		{Kind: "Deployment", Namespace: "billing", Name: "api", Path: "k8s/api.yaml"},
		{Kind: "Service", Namespace: "billing", Name: "api", Path: "k8s/api.yaml"},
	}
	assets := ProjectDeclaredK8s(decls, "org/payments-repo", now)
	require.Len(t, assets, 2)

	byKey := map[string]map[string]string{} // manifest_key -> metadata
	for _, a := range assets {
		require.Equal(t, "declared_k8s_workload", a.Type)
		require.Equal(t, now, a.LastSeen)
		byKey[a.Metadata["manifest_key"]] = a.Metadata
	}

	dep := byKey["deployment/billing/api"]
	require.Equal(t, "k8s_deployment", dep["live_type"])
	require.Equal(t, "billing", dep["namespace"])
	require.Equal(t, "org/payments-repo", dep["repo"])
	require.Equal(t, "k8s/api.yaml", dep["path"])

	svc := byKey["service/billing/api"]
	require.Equal(t, "k8s_service", svc["live_type"])
}

func TestProjectDeclaredK8s_StableUniqueIDs(t *testing.T) {
	now := time.Now()
	decls := []DeclaredK8sWorkload{
		{Kind: "Deployment", Namespace: "a", Name: "x", Path: "p1.yaml"},
		{Kind: "Deployment", Namespace: "a", Name: "x", Path: "p2.yaml"},
	}
	assets := ProjectDeclaredK8s(decls, "org/repo", now)
	require.Len(t, assets, 2)
	require.NotEqual(t, assets[0].ID, assets[1].ID, "same object in two files must not collapse to one asset")
}
