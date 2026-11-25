package checks

// gcp_gke.go — CIS GKE Benchmark section 4/5 cluster and node-pool settings,
// from the clusters.list response the collector already fetches
// (internal/collect/gcp/gke_posture.go). One finding per cluster: node-pool
// settings are aggregated into node_pools_<setting> lists of the offending
// pools ("" = every pool read and none offends; absent = some pool's setting
// was not returned and none was seen to offend).

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// nodePoolEvidence names the offending node pools.
func nodePoolEvidence(key string) func(asset.Asset) map[string]string {
	return func(a asset.Asset) map[string]string {
		return map[string]string{"node_pools": a.Metadata[key]}
	}
}

// gkePublicEndpointViolates is gcp-gke-public-endpoint's predicate: a public
// control-plane endpoint with no allowlist, or one admitting 0.0.0.0/0, which
// restricts nothing.
func gkePublicEndpointViolates(a asset.Asset) bool {
	return a.Metadata["public_endpoint"] == "true" &&
		(a.Metadata["authorized_networks"] != "true" || a.Metadata["authorized_networks_world"] == "true")
}

var gcpGKEPrivateEndpointDisabled = Check{
	ID:          "gcp-gke-private-endpoint-disabled",
	Title:       "GKE control plane has a public endpoint",
	Description: "The cluster's control plane accepts connections on a public IP endpoint, restricted by master authorized networks. The allowlist narrows who can connect, but the API server is still an internet-facing endpoint; CIS recommends the private endpoint or the DNS-based endpoint (IAM-authorized) with the public IP endpoint disabled. A public endpoint with no effective allowlist is gcp-gke-public-endpoint's finding.",
	Remediation: "Disable the public IP endpoint and reach the control plane through the DNS-based endpoint or the private endpoint: `gcloud container clusters update CLUSTER --enable-dns-access --no-enable-ip-access` (or --enable-private-endpoint).",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_endpoint"] == "true" && !gkePublicEndpointViolates(a)
	},
}

var gcpGKEAuthorizedNetworksDisabled = Check{
	ID:          "gcp-gke-authorized-networks-disabled",
	Title:       "GKE private control plane has no authorized networks",
	Description: "The control plane's IP endpoint is private but master authorized networks are off, so any address that can route to the VPC — every VM, every peered or VPN-connected network — can reach the API server. A public endpoint without authorized networks is gcp-gke-public-endpoint's finding; a cluster reachable only through its DNS endpoint (IAM-authorized) has no IP endpoint to restrict and does not fire.",
	Remediation: "Enable master authorized networks with the CIDRs that administer the cluster: `gcloud container clusters update CLUSTER --enable-master-authorized-networks --master-authorized-networks=CIDR,...`.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_endpoint"] == "false" && a.Metadata["authorized_networks"] == "false" &&
			a.Metadata["ip_endpoints_enabled"] != "false"
	},
}

var gcpGKEPrivateNodesDisabled = Check{
	ID:          "gcp-gke-private-nodes-disabled",
	Title:       "GKE node pools give nodes public IP addresses",
	Description: "Private nodes are off for one or more node pools, so every node in them gets an external IP and is directly addressable from the internet; only firewall rules stand between the internet and the kubelet, NodePorts and anything bound to host ports.",
	Remediation: "Use private nodes (`gcloud container node-pools update POOL --cluster=CLUSTER --enable-private-nodes`, or create the cluster with --enable-private-nodes) and give them egress through Cloud NAT.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_public_nodes"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_public_nodes"),
}

var gcpGKEWorkloadIdentityDisabled = Check{
	ID:          "gcp-gke-workload-identity-disabled",
	Title:       "GKE cluster does not use Workload Identity",
	Description: "Workload Identity is off, so pods that call Google APIs either use the node's service account — shared by every pod on the node and readable from the metadata server — or a downloaded service-account key. Either way one compromised pod gets the cloud credentials of every workload on its node.",
	Remediation: "Enable Workload Identity (`gcloud container clusters update CLUSTER --workload-pool=PROJECT.svc.id.goog`), set node pools to the GKE metadata server, and bind each Kubernetes service account to its own Google service account.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["workload_identity"] == "false" },
}

var gcpGKEMetadataServerDisabled = Check{
	ID:          "gcp-gke-metadata-server-disabled",
	Title:       "GKE node pools expose the node metadata server to pods",
	Description: "Workload Identity is on, but one or more node pools do not run the GKE metadata server (workloadMetadataConfig mode GKE_METADATA), so pods there reach the Compute Engine metadata server directly: they can read the node's service-account token and instance metadata such as kube-env bootstrap credentials. On a cluster with Workload Identity off this is part of gcp-gke-workload-identity-disabled.",
	Remediation: "Switch the node pools to the GKE metadata server: `gcloud container node-pools update POOL --cluster=CLUSTER --workload-metadata=GKE_METADATA`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["node_pools_no_gke_metadata"] != "" && a.Metadata["workload_identity"] != "false"
	},
	EvidenceFor: nodePoolEvidence("node_pools_no_gke_metadata"),
}

var gcpGKEClientCertificateEnabled = Check{
	ID:          "gcp-gke-client-certificate-enabled",
	Title:       "GKE cluster issues a legacy client certificate",
	Description: "The cluster has a legacy client certificate (masterAuth.clientCertificate / issueClientCertificate). It is a static credential that never expires and cannot be revoked short of rotating the cluster's CA, and anyone with container.clusters.getCredentials can read it.",
	Remediation: "Recreate the cluster without a client certificate (`--no-issue-client-certificate`, the default since GKE 1.12) and authenticate with Google identities; rotate the cluster CA to invalidate the existing certificate.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["client_certificate_issued"] == "true" },
}

var gcpGKEBasicAuthEnabled = Check{
	ID:          "gcp-gke-basic-auth-enabled",
	Title:       "GKE cluster has static basic-auth credentials",
	Description: "The cluster has a master username and password. Basic authentication is a static, unrevocable admin credential readable by anyone with container.clusters.get, and it bypasses Google identity and its MFA entirely.",
	Remediation: "Disable basic authentication (`gcloud container clusters update CLUSTER --no-enable-basic-auth`; it is removed outright in GKE 1.19+, so upgrade the cluster) and use Google identities with RBAC.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["basic_auth"] == "true" },
}

var gcpGKESecretsNotEncrypted = Check{
	ID:          "gcp-gke-secrets-not-encrypted",
	Title:       "GKE cluster does not encrypt Secrets with a KMS key",
	Description: "Application-layer Secrets encryption is off, so Kubernetes Secrets in etcd are protected only by Google's default storage encryption, not by a Cloud KMS key the organisation controls, audits and can revoke.",
	Remediation: "Enable application-layer encryption with a Cloud KMS key: `gcloud container clusters update CLUSTER --database-encryption-key=projects/P/locations/L/keyRings/R/cryptoKeys/K`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["secrets_encryption"] == "DECRYPTED" },
}

var gcpGKENetworkPolicyDisabled = Check{
	ID:          "gcp-gke-network-policy-disabled",
	Title:       "GKE cluster does not enforce NetworkPolicy",
	Description: "Neither the NetworkPolicy addon nor Dataplane V2 is enabled, so NetworkPolicy objects are accepted but not enforced: every pod can reach every other pod and a single compromised workload can move laterally across namespaces. Dataplane V2 clusters (datapathProvider ADVANCED_DATAPATH) enforce policy natively and do not fire.",
	Remediation: "Enable enforcement (`gcloud container clusters update CLUSTER --update-addons=NetworkPolicy=ENABLED` then `--enable-network-policy`), or use Dataplane V2 on new clusters (`--enable-dataplane-v2`), then add default-deny policies per namespace.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates: func(a asset.Asset) bool {
		dp, ok := a.Metadata["datapath_provider"]
		return ok && dp != "ADVANCED_DATAPATH" && a.Metadata["network_policy"] == "false"
	},
}

var gcpGKEBinaryAuthorizationDisabled = Check{
	ID:          "gcp-gke-binary-authorization-disabled",
	Title:       "GKE cluster does not enforce Binary Authorization",
	Description: "Binary Authorization is disabled on the cluster, so it admits any container image — unsigned, unscanned, or pulled from any registry — and a stolen deploy credential can run arbitrary images.",
	Remediation: "Enable enforcement with the project policy (`gcloud container clusters update CLUSTER --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE`) and configure a policy that requires attestations or trusted registries.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["binary_authorization"] == "DISABLED" },
}

var gcpGKEShieldedNodesDisabled = Check{
	ID:          "gcp-gke-shielded-nodes-disabled",
	Title:       "GKE cluster does not use Shielded nodes",
	Description: "Shielded GKE nodes are off, so a node's identity is not backed by a vTPM and an attacker who extracts node bootstrap credentials (for example through the metadata server) can impersonate a node to the control plane.",
	Remediation: "Enable Shielded nodes: `gcloud container clusters update CLUSTER --enable-shielded-nodes`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["shielded_nodes"] == "false" },
}

var gcpGKENodeSecureBootDisabled = Check{
	ID:          "gcp-gke-node-secure-boot-disabled",
	Title:       "GKE node pools boot without Secure Boot",
	Description: "Secure Boot is off on one or more node pools, so their nodes will boot an unsigned or tampered bootloader, kernel or kernel module — the persistence an attacker with root on a node wants.",
	Remediation: "Recreate the node pools with Secure Boot (`gcloud container node-pools create POOL --cluster=CLUSTER --shielded-secure-boot`) and migrate workloads; third-party unsigned kernel modules will not load.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_no_secure_boot"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_no_secure_boot"),
}

var gcpGKENodeIntegrityMonitoringDisabled = Check{
	ID:          "gcp-gke-node-integrity-monitoring-disabled",
	Title:       "GKE node pools do not monitor boot integrity",
	Description: "Integrity monitoring is off on one or more node pools, so changes to their nodes' boot sequence are not measured against a baseline and a compromised boot chain goes unreported.",
	Remediation: "Recreate the node pools with integrity monitoring (`gcloud container node-pools create POOL --cluster=CLUSTER --shielded-integrity-monitoring`) and migrate workloads.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_no_integrity_monitoring"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_no_integrity_monitoring"),
}

var gcpGKENodeAutoUpgradeDisabled = Check{
	ID:          "gcp-gke-node-auto-upgrade-disabled",
	Title:       "GKE node pools do not auto-upgrade",
	Description: "Auto-upgrade is off on one or more node pools, so their nodes stay on the Kubernetes and OS version they were created with and miss security patches until someone upgrades them by hand — and fall out of support once the control plane moves on.",
	Remediation: "Enable auto-upgrade: `gcloud container node-pools update POOL --cluster=CLUSTER --enable-autoupgrade`, and use maintenance windows to control timing.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_no_auto_upgrade"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_no_auto_upgrade"),
}

var gcpGKENodeAutoRepairDisabled = Check{
	ID:          "gcp-gke-node-auto-repair-disabled",
	Title:       "GKE node pools do not auto-repair",
	Description: "Auto-repair is off on one or more node pools, so a node that fails health checks stays broken until someone notices, and capacity silently shrinks.",
	Remediation: "Enable auto-repair: `gcloud container node-pools update POOL --cluster=CLUSTER --enable-autorepair`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_no_auto_repair"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_no_auto_repair"),
}

var gcpGKENodeImageNotCOS = Check{
	ID:          "gcp-gke-node-image-not-cos",
	Title:       "GKE node pools do not run Container-Optimized OS",
	Description: "One or more node pools use an image other than Container-Optimized OS with containerd (COS_CONTAINERD). COS is a minimal, read-only, Google-patched OS built for running containers; general-purpose images carry more packages to patch and a writable root filesystem.",
	Remediation: "Move the node pools to COS: `gcloud container clusters upgrade CLUSTER --node-pool=POOL --image-type=COS_CONTAINERD`, unless a workload needs another image.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_pools_not_cos"] != "" },
	EvidenceFor: nodePoolEvidence("node_pools_not_cos"),
}

var gcpGKENoReleaseChannel = Check{
	ID:          "gcp-gke-no-release-channel",
	Title:       "GKE cluster is not enrolled in a release channel",
	Description: "The cluster runs a static version outside any release channel, so Google does not move it through supported, patched versions and it is upgraded only when it reaches end of support.",
	Remediation: "Enrol the cluster: `gcloud container clusters update CLUSTER --release-channel=regular` (or stable).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "release_channel") },
}

var gcpGKELoggingDisabled = Check{
	ID:          "gcp-gke-logging-disabled",
	Title:       "GKE cluster does not send logs or metrics to Cloud Operations",
	Description: "Cloud Logging or Cloud Monitoring is set to none for the cluster, so control-plane, node and workload logs (or metrics) are not collected and an incident on the cluster leaves nothing to investigate.",
	Remediation: "Enable both: `gcloud container clusters update CLUSTER --logging=SYSTEM,WORKLOAD --monitoring=SYSTEM`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["logging_service"] == "none" || a.Metadata["monitoring_service"] == "none"
	},
}

var gcpGKEIntranodeVisibilityDisabled = Check{
	ID:          "gcp-gke-intranode-visibility-disabled",
	Title:       "GKE cluster does not expose pod-to-pod traffic within a node",
	Description: "Intranode visibility is off, so traffic between pods on the same node never leaves the node's network stack and does not appear in VPC flow logs or pass VPC firewall rules — pod-to-pod lateral movement on one node is invisible to network monitoring.",
	Remediation: "Enable it: `gcloud container clusters update CLUSTER --enable-intra-node-visibility`, and enable flow logs on the cluster's subnet.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["intranode_visibility"] == "false" },
}
