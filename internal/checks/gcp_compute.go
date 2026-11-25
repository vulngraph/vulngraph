package checks

// gcp_compute.go — CIS GCP Foundation section 4 instance settings read from the
// instances.aggregatedList response the collector already fetches: IP
// forwarding (4.6), Shielded VM (4.8), Confidential Computing (4.11) and the
// default service account with full API access (4.2).

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// gceDefaultSA reports whether the instance runs as the project's default
// Compute Engine service account (<number>-compute@developer.gserviceaccount.com).
func gceDefaultSA(a asset.Asset) bool {
	return strings.Contains(a.Metadata["exec_role"], "compute@developer.gserviceaccount.com")
}

// gceDefaultSAFullScope is gcp-gce-default-sa-full-scope's predicate, shared
// with gcp-gce-default-sa so that check steps aside for it. GKE node VMs are
// excluded as CIS GCP 4.2 directs — when their node pool is graded instead
// (gkeNodeGraded).
func gceDefaultSAFullScope(a asset.Asset) bool {
	return gceDefaultSA(a) && a.Metadata["sa_cloud_platform_scope"] == "true" && !gkeNodeGraded(a)
}

// gkeNode reports whether a GCE instance is a GKE node. GKE sets the
// goog-gke-node label on every node VM; the benchmark exempts those from the
// instance controls GKE itself needs (nodes route pod traffic, so they forward IP).
func gkeNode(a asset.Asset) bool {
	_, ok := a.Tags["goog-gke-node"]
	return ok
}

// gkeNodeGraded reports a GKE node whose cluster was read whole this sweep,
// with the node-pool service-account and private-nodes verdicts present
// (internal/collect/gcp annotateGKENodes): only then do the per-VM
// default-SA and public-IP checks step aside for the per-cluster findings.
// A node whose cluster listing failed is graded like any other VM — the
// label alone must not silence it.
func gkeNodeGraded(a asset.Asset) bool {
	return gkeNode(a) && a.Metadata["gke_node_pool_graded"] == "true"
}

var gcpGCEDefaultSAFullScope = Check{
	ID:          "gcp-gce-default-sa-full-scope",
	Title:       "GCE instance runs as the default service account with full API access",
	Description: "The instance runs as the default Compute Engine service account with the cloud-platform OAuth scope. The default account holds the Editor role unless that grant was removed, and the full scope stops OAuth scopes from narrowing it, so any process on the VM — or anyone who reaches its metadata server through SSRF — gets an Editor token for the whole project. This replaces gcp-gce-default-sa for the instance.",
	Remediation: "Create a dedicated service account with only the roles the workload needs and attach it (`gcloud compute instances set-service-account INSTANCE --service-account=SA --scopes=cloud-platform`, with the instance stopped); with a least-privilege account, the cloud-platform scope is fine.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates:    gceDefaultSAFullScope,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"service_account": strings.TrimPrefix(a.Metadata["exec_role"], "serviceAccount:"), "scope": "cloud-platform"}
	},
}

var gcpGCEIPForwarding = Check{
	ID:          "gcp-gce-ip-forwarding",
	Title:       "GCE instance has IP forwarding enabled",
	Description: "canIpForward is on, so the instance can send and receive packets for addresses that are not its own. Unless it is a deliberate router, NAT or firewall appliance, that lets a compromised VM spoof traffic and route around network controls. GKE nodes, which need forwarding, are excluded.",
	Remediation: "Recreate the instance without IP forwarding (canIpForward cannot be changed on a running instance), or document it as a network appliance. Enforce with the `compute.vmCanIpForward` organization policy.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["can_ip_forward"] == "true" && !gkeNode(a)
	},
}

var gcpGCEShieldedVMDisabled = Check{
	ID:          "gcp-gce-shielded-vm-disabled",
	Title:       "GCE instance does not have Shielded VM fully enabled",
	Description: "The instance runs without vTPM or without integrity monitoring, so boot-level tampering (rootkits, bootkits, a modified kernel) cannot be measured or detected against the instance's known-good baseline.",
	Remediation: "Stop the instance and enable the Shielded VM options: `gcloud compute instances update INSTANCE --shielded-vtpm --shielded-integrity-monitoring` (and --shielded-secure-boot where the image supports it). The image must be Shielded VM capable.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["shielded_vtpm"] == "false" || a.Metadata["shielded_integrity_monitoring"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"vtpm": a.Metadata["shielded_vtpm"], "integrity_monitoring": a.Metadata["shielded_integrity_monitoring"],
			"secure_boot": a.Metadata["shielded_secure_boot"],
		}
	},
}

// gcpGCEConfidentialComputeDisabled is informational: Confidential VMs need
// specific machine families, and memory encryption in use is a hardening
// choice most estates make per workload, not a misconfiguration.
var gcpGCEConfidentialComputeDisabled = Check{
	ID:          "gcp-gce-confidential-compute-disabled",
	Title:       "GCE instance is not a Confidential VM",
	Description: "Confidential Computing is off, so the instance's memory is not encrypted with a key the hypervisor cannot read. CIS recommends it for instances processing sensitive data; it requires a supported machine family (N2D, C2D, C3 and others).",
	Remediation: "Create the instance as a Confidential VM on a supported machine type (`gcloud compute instances create ... --confidential-compute-type=SEV`) where the workload handles sensitive data.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["confidential_compute"] == "false" },
}
