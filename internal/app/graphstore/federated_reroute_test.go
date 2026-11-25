package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// federated_access has two producers and only one of them was landing:
//
//	github_repo         → iam_role
//	github_repo         → gcp_service_account
//	k8s_service_account → gcp_service_account   ← dropped at COPY
//
// k8s_service_account is K8sWorkload-labeled while FederatedAccess is
// Repo→IamRole, so without a reroute every GKE Workload
// Identity binding was silently discarded and a GKE workload's cloud identity
// was simply absent from the graph. Another instance of this bug class, and one
// the drop detector could not see: it only reported rel tables losing SOME
// rows, and the repo-sourced rows kept this table looking healthy.
func TestFederatedAccessFromServiceAccountReroutesToK8sWorkloadTable(t *testing.T) {
	rows := buildEdgeRows([]asset.Edge{
		// GKE Workload Identity: K8sWorkload-labeled source.
		{SrcID: "c1/namespace/team/serviceaccount/app", SrcType: "k8s_service_account",
			DstID: "sa@proj.iam.gserviceaccount.com", DstType: "gcp_service_account",
			EdgeType: "federated_access", Properties: map[string]string{"trust_type": "wif", "subject": "system:serviceaccount:team:app"}},
		// EKS IRSA (correlate/irsa.go): same K8sWorkload-labeled source, AWS
		// destination. It reuses this reroute rather than declaring a rel table of
		// its own, which is the whole reason IRSA needed no SchemaVersion bump —
		// so it has to be pinned here, not just in correlate's own tests.
		{SrcID: "c1/namespace/payments/serviceaccount/api", SrcType: "k8s_service_account",
			DstID: "arn:aws:iam::1:role/payments", DstType: "iam_role",
			EdgeType: "federated_access", Properties: map[string]string{"trust_type": "eks_irsa"}},
		// GitHub Actions OIDC: Repo-labeled source, stays on the default table.
		{SrcID: "org/repo", SrcType: "github_repo",
			DstID: "arn:aws:iam::1:role/deploy", DstType: "iam_role",
			EdgeType: "federated_access", Properties: map[string]string{"trust_type": "oidc"}},
	})

	require.Len(t, rows[RelFederatedAccessK8sWorkload].rows, 2,
		"both ServiceAccount-sourced federated_access edges (GKE WIF and EKS IRSA) must route to the K8sWorkload table")
	require.Len(t, rows[RelFederatedAccess].rows, 1,
		"the repo-sourced edge stays on the Repo→IamRole table")

	// The federation properties must survive the reroute — they are what the
	// trust-analysis queries read, and a reroute that silently drops them would
	// look like a successful load.
	require.Equal(t, "wif", rows[RelFederatedAccessK8sWorkload].rows[0]["trust_type"])
	require.Equal(t, "system:serviceaccount:team:app", rows[RelFederatedAccessK8sWorkload].rows[0]["subject"])

	// And the endpoints the reroute target declares must match the labels those
	// asset types actually promote to, or COPY drops the rows again.
	spec := ladybugRelSpec[RelFederatedAccessK8sWorkload]
	require.Equal(t, NodeLabelFor("k8s_service_account"), spec.from)
	require.Equal(t, NodeLabelFor("gcp_service_account"), spec.to)
	require.Equal(t, NodeLabelFor("iam_role"), spec.to, "the IRSA destination shares this table's TO label")
}
