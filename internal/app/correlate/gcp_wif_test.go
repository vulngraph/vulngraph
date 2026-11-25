package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// A GKE pod running as a Workload-Identity-annotated ServiceAccount must
// REACH the bound GCP service account: pod -[executes_as]-> SA -[executes_as]->
// GCP SA, every hop a Reach edge type. federated_access alone is not Reach, so
// it left the chain broken at the ServiceAccount.
func TestGCPWorkloadIdentity_EmitsReachEdge(t *testing.T) {
	const (
		saID  = "gke/namespace/prod/serviceaccount/api"
		gcpSA = "serviceAccount:api@proj.iam.gserviceaccount.com"
	)
	g := NewGraph([]asset.Asset{
		{ID: "gke/pod/prod/api-1", Type: "k8s_pod", Metadata: map[string]string{"namespace": "prod", "service_account": "api"}},
		{ID: saID, Type: "k8s_service_account",
			Metadata: map[string]string{"namespace": "prod", "iam.gke.io/gcp-service-account": "api@proj.iam.gserviceaccount.com"}},
		{ID: gcpSA, Type: "gcp_service_account"},
	})

	types := map[string]bool{}
	for _, e := range (GCPWorkloadIdentity{}).Correlate(g) {
		require.Equal(t, saID, e.SrcID)
		require.Equal(t, gcpSA, e.DstID)
		types[e.EdgeType] = true
	}
	require.Equal(t, map[string]bool{EdgeFederatedAccess: true, EdgeExecutesAs: true}, types)

	podEdges := K8sPodServiceAccount{}.Correlate(g)
	require.Len(t, podEdges, 1)
	require.Equal(t, saID, podEdges[0].DstID)

	reach := graphschema.ReachEdgeTypes()
	require.True(t, reach[podEdges[0].EdgeType], "pod -> SA must be Reach")
	require.True(t, reach[EdgeExecutesAs], "SA -> GCP SA must be Reach")
}

func TestExecutesAs_InterestedInServiceAccounts(t *testing.T) {
	require.Contains(t, ExecutesAs{}.InterestedIn(), "k8s_service_account",
		"an SA's IRSA annotation is its exec_role; a targeted sync of the SA must recompute executes_as")
}
