package correlate

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// GCPWorkloadIdentity discovers Kubernetes ServiceAccounts annotated with
// "iam.gke.io/gcp-service-account" (GKE Workload Identity Federation) and
// links the K8s SA to the GCP service account with two edges:
//
//   - federated_access: the trust relationship itself, for "who federates into
//     this identity" queries alongside GitHub OIDC and IRSA.
//   - executes_as: the reach edge. A pod running as the K8s SA obtains the
//     GCP SA's token from the metadata server with no further authentication,
//     so an exposed pod reaches the GCP SA. federated_access is deliberately
//     not a Reach type (it is IdP-gated for GitHub OIDC), so without this edge
//     pod -[executes_as]-> K8s SA ended the chain. This mirrors EKS IRSA, whose
//     eks.amazonaws.com/role-arn annotation becomes the SA's exec_role and an
//     executes_as edge via the ExecutesAs rule.
//
// This closes the K8s → GCP attack path: a compromised pod running as a K8s SA
// with WIF enabled can impersonate the bound GCP SA and access GCP resources.
//
// Annotation key: iam.gke.io/gcp-service-account
// Annotation value: <name>@<project>.iam.gserviceaccount.com
//
// The GCP SA must be present in the inventory (collected by the GCP connector)
// for an edge to be emitted — we never emit edges to dangling IDs.
type GCPWorkloadIdentity struct{}

func (GCPWorkloadIdentity) Name() string { return "gcp_workload_identity" }

func (GCPWorkloadIdentity) InterestedIn() []string {
	return []string{"k8s_service_account", "gcp_service_account"}
}

func (GCPWorkloadIdentity) Correlate(g Graph) []asset.Edge {
	var edges []asset.Edge
	for _, sa := range g.K8sServiceAccounts() {
		gcpSAEmail := sa.Metadata["iam.gke.io/gcp-service-account"]
		if gcpSAEmail == "" {
			continue
		}
		// Only emit the edge when the GCP SA is actually present in the inventory
		// so we don't produce dangling references.
		gcpSAID := "serviceAccount:" + gcpSAEmail
		if !g.IsPrincipal(gcpSAID) {
			continue
		}
		for _, edgeType := range []string{EdgeFederatedAccess, EdgeExecutesAs} {
			edges = append(edges, asset.Edge{
				SrcID: sa.ID, SrcType: "k8s_service_account",
				DstID: gcpSAID, DstType: "gcp_service_account",
				EdgeType: edgeType,
				Properties: map[string]string{
					"origin":     edgeOrigin,
					"rule":       "gcp_workload_identity",
					"trust_type": "gke_wif",
					"annotation": gcpSAEmail,
				},
			})
		}
	}
	return edges
}
