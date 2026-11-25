package gcp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeContainer struct {
	clusters []gkeCluster
	err      error
}

func (f fakeContainer) ListClusters(context.Context, string) ([]gkeCluster, error) {
	return f.clusters, f.err
}

func TestCollectGKE(t *testing.T) {
	c := fakeContainer{clusters: []gkeCluster{
		{Name: "prod", Location: "europe-west4", PublicEndpoint: true, AuthorizedNets: false, LegacyABAC: true, NetworkPolicy: false},
		{Name: "internal", Location: "europe-west4", PublicEndpoint: false, AuthorizedNets: true, NetworkPolicy: true},
	}}
	got, err := collectGKE(context.Background(), c, "proj-1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)

	byName := map[string]map[string]string{}
	for _, a := range got {
		require.Equal(t, "gke_cluster", a.Type)
		require.Equal(t, "proj-1", a.AccountID)
		byName[a.Name] = a.Metadata
	}
	require.Equal(t, "true", byName["prod"]["public_endpoint"])
	require.Equal(t, "true", byName["prod"]["legacy_abac"])
	require.Equal(t, "possible", byName["prod"]["public_access"], "public endpoint + no authorized networks is possible-tier exposure")
	require.Equal(t, "false", byName["internal"]["public_endpoint"])
	require.Empty(t, byName["internal"]["public_access"], "a private-endpoint cluster is not exposed")
}

// The Workload Identity pool is the join key from a k8s_service_account to the
// GCP service account it can impersonate — the GKE analogue of the EKS OIDC
// issuer. Absent when Workload Identity is off, which is itself the observation
// that no such binding can exist.
func TestCollectGKE_WorkloadIdentityPoolAndStatus(t *testing.T) {
	c := fakeContainer{clusters: []gkeCluster{
		{Name: "wi-on", Location: "europe-west4", Status: "RUNNING", WorkloadPool: "proj-1.svc.id.goog"},
		{Name: "wi-off", Location: "europe-west4", Status: "DEGRADED"},
	}}
	got, err := collectGKE(context.Background(), c, "proj-1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)

	byName := map[string]map[string]string{}
	for _, a := range got {
		byName[a.Name] = a.Metadata
	}
	require.Equal(t, "proj-1.svc.id.goog", byName["wi-on"]["workload_identity_pool"])
	require.Equal(t, "RUNNING", byName["wi-on"]["status"])
	require.NotContains(t, byName["wi-off"], "workload_identity_pool",
		"Workload Identity disabled must omit the pool, not emit an empty one")
	require.Equal(t, "DEGRADED", byName["wi-off"]["status"])
}

func TestToNeutralGKE_UnobservedStatusAndPoolOmitted(t *testing.T) {
	got, err := collectGKE(context.Background(),
		fakeContainer{clusters: []gkeCluster{{Name: "bare", Location: "europe-west4"}}},
		"proj-1", time.Now())
	require.NoError(t, err)
	require.NotContains(t, got[0].Metadata, "status")
	require.NotContains(t, got[0].Metadata, "workload_identity_pool")
}
