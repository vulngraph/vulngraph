package kubernetes

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const gkeIssuer = "https://container.googleapis.com/v1/projects/example-gke-project/locations/europe-west4/clusters/example-cluster"

func TestClusterIdentity_DecodesIssuer(t *testing.T) {
	tests := []struct {
		name       string
		issuer     string
		provider   string
		discovered string
		cloudID    string
	}{
		{
			name: "gke issuer carries project, location and cluster name",
			// Configured as "example-connector-cluster", actually named "example-cluster".
			issuer: gkeIssuer, provider: "gcp", discovered: "example-cluster",
			cloudID: "example-gke-project/gke/europe-west4/example-cluster",
		},
		{
			// The EKS issuer identifies the cluster by an opaque id, so the NAME
			// stays unknown. Inventing one from the configured value is exactly
			// the assumption this file exists to remove.
			name:   "eks issuer identifies the provider but carries no name",
			issuer: "https://oidc.eks.eu-west-1.amazonaws.com/id/9F2A", provider: "aws",
		},
		{name: "unknown issuer decodes to nothing", issuer: "https://kubernetes.default.svc"},
		{name: "absent issuer decodes to nothing"},
		{name: "gke prefix with a truncated path is not parsed",
			issuer: "https://container.googleapis.com/v1/projects/p/locations/l", provider: "gcp"},
		{name: "gke prefix with an empty cluster segment is not parsed",
			issuer: "https://container.googleapis.com/v1/projects/p/locations/l/clusters/", provider: "gcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clusterIdentity{Configured: "example-connector-cluster", Issuer: tt.issuer}
			require.Equal(t, tt.provider, c.cloudProvider())
			require.Equal(t, tt.discovered, c.discoveredName())
			require.Equal(t, tt.cloudID, c.cloudClusterID())
		})
	}
}

func TestIsEKSIssuer(t *testing.T) {
	for issuer, want := range map[string]bool{
		"https://oidc.eks.eu-west-1.amazonaws.com/id/9F2A":         true,
		"https://oidc.eks.cn-north-1.amazonaws.com.cn/id/9F2A":     true,
		"https://oidc.eks.evil.example.com/id/9F2A":                false,
		"https://oidc.eks.eu-west-1.amazonaws.com.evil.io/id/9F2A": false,
		"https://oidc.eks.amazonaws.com.attacker.net/id/9F2A":      false,
		"http://oidc.eks.eu-west-1.amazonaws.com/id/9F2A":          false,
		"https://oidc.eks.eu-west-1.amazonaws.com:8443/id/9F2A":    false,
		"https://evil.com/oidc.eks.eu-west-1.amazonaws.com":        false,
		"https://kubernetes.default.svc":                           false,
		"":                                                         false,
	} {
		require.Equal(t, want, isEKSIssuer(issuer), issuer)
	}
}

func TestClusterIdentity_NameMismatch(t *testing.T) {
	require.True(t, clusterIdentity{Configured: "example-connector-cluster", Issuer: gkeIssuer}.nameMismatch(),
		"configured name differs from the cluster's own name")
	require.False(t, clusterIdentity{Configured: "example-cluster", Issuer: gkeIssuer}.nameMismatch())
	require.False(t, clusterIdentity{Configured: "anything"}.nameMismatch(),
		"an undiscovered name is unknown, not a mismatch")
	require.False(t, clusterIdentity{
		Configured: "prod", Issuer: "https://oidc.eks.eu-west-1.amazonaws.com/id/9F2A",
	}.nameMismatch(), "EKS carries no name, so no disagreement can be observed")
}

func TestClusterIdentity_AssetOmitsUnobservedKeys(t *testing.T) {
	now := time.Now()

	full := clusterIdentity{Configured: "example-connector-cluster", Issuer: gkeIssuer, KubeSystemUID: "uid-1"}.asset(now)
	require.Equal(t, "example-connector-cluster/cluster", full.ID)
	require.Equal(t, "k8s_cluster", full.Type)
	require.Equal(t, "example-cluster", full.Name, "the asset is named what the cluster calls itself")
	require.Equal(t, map[string]string{
		"configured_name":  "example-connector-cluster",
		"oidc_issuer":      gkeIssuer,
		"kube_system_uid":  "uid-1",
		"cloud_provider":   "gcp",
		"discovered_name":  "example-cluster",
		"cloud_cluster_id": "example-gke-project/gke/europe-west4/example-cluster",
	}, full.Metadata)

	// Nothing discovered: every derived key is OMITTED, never written empty or
	// guessed. A check reading discovered_name must see "not observed".
	bare := clusterIdentity{Configured: "in-cluster"}.asset(now)
	require.Equal(t, map[string]string{"configured_name": "in-cluster"}, bare.Metadata)
	require.Equal(t, "in-cluster", bare.Name)
}

func TestKubeSystemUID(t *testing.T) {
	nss := []corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: types.UID("uid-app")}},
		{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("uid-ks")}},
	}
	require.Equal(t, "uid-ks", kubeSystemUID(nss))
	require.Empty(t, kubeSystemUID(nss[:1]))
}

func TestCollect_EmitsClusterIdentityAsset(t *testing.T) {
	f := &fakeK8s{
		namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system", UID: types.UID("uid-ks")}},
		},
		issuer: gkeIssuer,
	}
	res, err := withFakeK8s(f).Collect(context.Background(), nil)
	require.NoError(t, err)

	var cluster int
	for _, a := range res.Assets {
		if a.Type != "k8s_cluster" {
			continue
		}
		cluster++
		require.Equal(t, "prod", a.Metadata["configured_name"])
		require.Equal(t, "example-cluster", a.Metadata["discovered_name"])
		require.Equal(t, "uid-ks", a.Metadata["kube_system_uid"])
	}
	require.Equal(t, 1, cluster, "exactly one cluster identity asset per sweep")
}

func TestCollect_IssuerErrorOmitsIdentityAndIsNotPartial(t *testing.T) {
	f := &fakeK8s{namespaces: appNamespace(), issuerErr: errors.New("forbidden")}
	res, err := withFakeK8s(f).Collect(context.Background(), nil)
	require.NoError(t, err)
	// One unreadable metadata key must not disable deletion reconciliation for
	// the whole connector — that is what Partial does.
	require.False(t, res.Partial)
	for _, a := range res.Assets {
		if a.Type == "k8s_cluster" {
			require.NotContains(t, a.Metadata, "oidc_issuer")
			require.NotContains(t, a.Metadata, "discovered_name")
		}
	}
}

func TestIsAKSIssuer(t *testing.T) {
	for issuer, want := range map[string]bool{
		"https://eastus.oic.prod-aks.azure.com/72f988bf-86f1-41af-91ab-2d7cd011db47/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9/": true,
		"https://eastus.oic.prod-aks.azure.com.evil.io/t/c/":                                                               false,
		"http://eastus.oic.prod-aks.azure.com/t/c/":                                                                        false,
		"https://kubernetes.default.svc.cluster.local":                                                                     false,
	} {
		require.Equal(t, want, isAKSIssuer(issuer), issuer)
	}
	require.Equal(t, "azure", clusterIdentity{Issuer: "https://westeurope.oic.prod-aks.azure.com/t/c/"}.cloudProvider())
}
