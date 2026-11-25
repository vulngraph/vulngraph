package checks

// gcp_gke_nodes.go — the rest of CIS GKE section 5 read from the Container,
// Artifact Registry and Binary Authorization APIs: node-pool service
// accounts (5.2.1), boot-disk CMEK (5.9.2), VPC-native networking (5.6.2),
// Google Groups for RBAC (5.8.2), alpha clusters (5.10.1), security posture
// (5.10.3), image scanning (5.1.1), repository access (5.1.2) and the
// project Binary Authorization policy (5.1.3).

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var gcpGKENodeDefaultSA = Check{
	ID:          "gcp-gke-node-default-sa",
	Title:       "GKE node pools run as the default Compute Engine service account",
	Description: "One or more node pools use the project's default Compute Engine service account, which holds Editor unless that grant was removed. Every pod on those nodes that can reach the metadata server can mint its token. High when the pool also has the cloud-platform OAuth scope, which stops scopes from narrowing it. This replaces gcp-gce-default-sa for the node VMs.",
	Remediation: "Create a least-privilege node service account (roles/container.defaultNodeServiceAccount) and move workloads to new node pools that use it: `gcloud container node-pools create POOL --cluster=CLUSTER --service-account=SA_EMAIL`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_default_sa"] != "" },
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["node_pools_default_sa_full_scope"] != "" {
			return finding.SeverityHigh
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"node_pools": a.Metadata["node_pools_default_sa"], "cloud_platform_scope": a.Metadata["node_pools_default_sa_full_scope"]}
	},
}

var gcpGKENodeSAPrivileged = Check{
	ID:          "gcp-gke-node-sa-privileged",
	Title:       "GKE node pools run as an over-privileged service account",
	Description: "One or more node pools run as a dedicated service account that holds Owner, Editor or an admin role. Nodes need only to write logs and metrics and pull images; every pod that reaches the metadata server inherits whatever else the account can do.",
	Remediation: "Reduce the node account to roles/container.defaultNodeServiceAccount (plus artifactregistry.reader for private images) and give workloads their own identities through Workload Identity.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_privileged_sa"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_privileged_sa"),
}

var gcpGKEBootDiskNoCMEK = Check{
	ID:          "gcp-gke-boot-disk-no-cmek",
	Title:       "GKE node boot disks are not encrypted with a customer-managed key",
	Description: "One or more node pools use Google-managed encryption for node boot disks, which hold container images, emptyDir volumes and logs, so that data cannot be revoked or audited through a Cloud KMS key the organisation controls.",
	Remediation: "Create node pools with a key: `gcloud container node-pools create POOL --cluster=CLUSTER --boot-disk-kms-key=projects/P/locations/L/keyRings/R/cryptoKeys/K`, then migrate workloads.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_no_boot_disk_cmek"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_no_boot_disk_cmek"),
}

var gcpGKENotVPCNative = Check{
	ID:          "gcp-gke-not-vpc-native",
	Title:       "GKE cluster is not VPC-native",
	Description: "The cluster uses routes-based networking instead of alias IP ranges, so pod addresses are not native VPC addresses: VPC firewall rules and flow logs cannot see pods individually, and features such as Private Service Connect, NEG load balancing and Dataplane V2 are unavailable.",
	Remediation: "VPC-native mode cannot be enabled in place: create a new cluster with `--enable-ip-alias` and migrate workloads.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["vpc_native"] == "false" },
}

var gcpGKEGoogleGroupsRBACDisabled = Check{
	ID:          "gcp-gke-google-groups-rbac-disabled",
	Title:       "GKE cluster does not use Google Groups for RBAC",
	Description: "Google Groups for RBAC is off, so RBAC bindings must name individual users; access then drifts as people join and leave teams instead of following group membership managed in Cloud Identity.",
	Remediation: "Enable it with a gke-security-groups group: `gcloud container clusters update CLUSTER --security-group=gke-security-groups@DOMAIN`, then bind roles to groups.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["google_groups_rbac"] == "false" },
}

var gcpGKEAlphaCluster = Check{
	ID:          "gcp-gke-alpha-cluster",
	Title:       "GKE cluster has Kubernetes alpha features enabled",
	Description: "This is an alpha cluster: alpha APIs and features are enabled, which are not covered by the GKE SLA, receive no security patches through upgrades (auto-upgrade and auto-repair are off), and are deleted after 30 days. Alpha clusters must not run production workloads.",
	Remediation: "Recreate the workload on a standard cluster without --enable-kubernetes-alpha.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["kubernetes_alpha"] == "true" },
}

var gcpGKESecurityPostureDisabled = Check{
	ID:          "gcp-gke-security-posture-disabled",
	Title:       "GKE security posture is disabled",
	Description: "The cluster's security posture mode is DISABLED, so GKE does not report workload misconfigurations or (with vulnerability scanning) known-vulnerable images and OS packages in the security posture dashboard.",
	Remediation: "Enable it: `gcloud container clusters update CLUSTER --security-posture=standard --workload-vulnerability-scanning=standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["security_posture_mode"] == "DISABLED" },
}

var gcpBinAuthzPolicyAllowsAll = Check{
	ID:          "gcp-binauthz-policy-allows-all",
	Title:       "Binary Authorization admits any image on the cluster",
	Description: "The cluster enforces the project's Binary Authorization policy, but the rule that applies to it (its cluster-specific rule, or the default) is ALWAYS_ALLOW or dry-run only — so enforcement is on paper and unsigned images from any registry still deploy. A cluster with enforcement off is gcp-gke-binary-authorization-disabled's finding.",
	Remediation: "Require attestations or trusted registries in the project policy: `gcloud container binauthz policy export > policy.yaml`, set defaultAdmissionRule evaluationMode REQUIRE_ATTESTATION with ENFORCED_BLOCK_AND_AUDIT_LOG (and allowlist Google system images), then `gcloud container binauthz policy import policy.yaml`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["binauthz_policy_allows_all"] == "true" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"rule": a.Metadata["binauthz_policy_rule"]}
	},
}

var gcpArtifactRegistryScanningDisabled = Check{
	ID:          "gcp-artifact-registry-scanning-disabled",
	Title:       "Artifact Registry repository does not scan images for vulnerabilities",
	Description: "Automatic vulnerability scanning is disabled for this repository (its own setting, or the Container Scanning API is off in the project), so images pushed to it are never checked for known-vulnerable OS and language packages before they deploy.",
	Remediation: "Enable the Container Scanning API (`gcloud services enable containerscanning.googleapis.com`) and set the repository to inherit it: `gcloud artifacts repositories update REPO --location=LOC --allow-vulnerability-scanning`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_artifact_repository",
	Violates:    func(a asset.Asset) bool { return a.Metadata["scanning_state"] == "SCANNING_DISABLED" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"reason": a.Metadata["scanning_state_reason"]}
	},
}

var gcpArtifactRegistryPublic = Check{
	ID:          "gcp-artifact-registry-public",
	Title:       "Artifact Registry repository is publicly accessible",
	Description: "The repository's IAM policy grants a role to allUsers or allAuthenticatedUsers. Anyone can pull its images — and any secrets or internal code baked into them — and with a writer role, replace an image your clusters deploy.",
	Remediation: "Remove the public members: `gcloud artifacts repositories remove-iam-policy-binding REPO --location=LOC --member=allUsers --role=ROLE` (and allAuthenticatedUsers).",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_artifact_repository",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_grants"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_grants": a.Metadata["public_grants"]}
	},
}
