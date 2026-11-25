package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// k8sClusterIdentityMismatch fires when the name a Kubernetes connector is
// configured with is not the name the cluster itself reports.
//
// Every Kubernetes asset ID is prefixed with the configured name, and two
// joins assume that prefix IS the cloud provider's cluster name: cloud-cluster
// inventory reconciliation, and the GuardDuty EKS container join
// (collect/aws/guardduty.go). When it isn't, both resolve nothing and report a
// clean, empty answer instead of erroring.
//
// discovered_name (read from the cluster's own OpenID discovery document,
// collect/kubernetes/identity.go) is omitted when the cluster states no name
// (an EKS issuer carries only an opaque id), so an unknown name can never fire
// this.
var k8sClusterIdentityMismatch = Check{
	ID:          "k8s-cluster-identity-mismatch",
	Title:       "Kubernetes connector cluster name does not match the cluster",
	Description: "The Kubernetes connector's configured cluster_name is not the name the cluster reports for itself (read from its own OpenID discovery document). Every Kubernetes asset ID is prefixed with the configured name, so joins keyed on the real cluster name — cloud cluster inventory reconciliation, and the GuardDuty EKS container-to-pod join — silently resolve nothing and report the cluster as having no workloads.",
	Remediation: "Set the connector's cluster_name to the name shown in discovered_name (the cluster's own), or accept the configured label and join on the cluster's oidc_issuer / cloud_cluster_id instead of its name.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster",
	Violates: func(a asset.Asset) bool {
		discovered, ok := a.Metadata["discovered_name"]
		if !ok || discovered == "" {
			return false // the cluster stated no name: unknown, not disagreement
		}
		configured, ok := a.Metadata["configured_name"]
		if !ok {
			return false
		}
		return discovered != configured
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{
			"configured_name": a.Metadata["configured_name"],
			"discovered_name": a.Metadata["discovered_name"],
		}
		for _, k := range []string{"oidc_issuer", "cloud_cluster_id", "cloud_provider"} {
			if v := a.Metadata[k]; v != "" {
				ev[k] = v
			}
		}
		return ev
	},
}
