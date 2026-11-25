package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Default returns a registry holding every built-in posture check (CIS
// benchmark controls plus CSPM and hygiene checks for AWS, GCP, Azure,
// Kubernetes and GitHub), each evaluated from collected asset metadata. serve,
// the worker and coverage-gen all read it; a new check is added by
// registering it here.
func Default() *Registry {
	r := NewRegistry()
	r.Register(
		// CIS checks
		awsEC2PublicIP,
		gcpGCEPublicIP,
		githubPublicRepo,
		awsS3PublicBucket,
		gcpGCSPublicBucket,
		gcpFirewallOpenIngress,
		// Hygiene: dangling/orphaned resources
		awsEIPUnassociated,
		awsLBInternetFacing,
		awsSubnetAutoAssignPublicIP,
		// Exposure: world-open security group ingress
		awsSGWorldOpenAdminPort,
		awsSGUnrestrictedEgress,
		// Hygiene: DNS security + subdomain takeover
		// Wildcard (High) and specific (Medium) predicates are mutually exclusive
		// on isWildcardCNAME, so a record gets at most one of the two findings.
		dnsWildcardCNAMETakeoverRisk,
		gcpDNSWildcardCNAMETakeoverRisk,
		dnsRecordCNAMETakeoverRisk,
		gcpDNSCNAMETakeoverRisk,
		// Kubernetes RBAC + pod security
		k8sClusterRoleWildcardVerbs,
		k8sClusterAdminBinding,
		k8sDefaultServiceAccountBound,
		// Kubernetes namespaced RBAC (Role/RoleBinding) — siblings of the
		// ClusterRole/ClusterRoleBinding checks above.
		k8sRoleWildcardVerbs,
		k8sRoleBindingAdminBinding,
		k8sRoleBindingDefaultServiceAccountBound,
		// The worst possible RBAC state: a privileged role bound to a group
		// that contains everyone.
		k8sBindingToEveryone,
		k8sPrivilegedContainer,
		k8sDangerousCapabilities,
		k8sPodRunsAsRoot,       // may run as UID 0
		k8sPodLatestImage,      // :latest or untagged image
		k8sPodAutomountSAToken, // SA token automounted
		// Kubernetes exposure
		k8sServicePublicLoadBalancer,
		k8sServiceNodePort,
		k8sHostNetworkPod,
		k8sIngressNoTLS, // HTTP ingress without TLS
		// Kubernetes namespace hygiene
		k8sNamespaceNoNetworkPolicy, // namespaces with pods but no NetworkPolicy
		// Kubernetes pod resource hygiene
		k8sPodNoResourceLimits, // non-system pods without cpu/memory limits
		// AWS S3 hygiene
		awsS3NoVersioning,          // buckets without versioning = ransomware/deletion risk
		awsS3AccessLoggingDisabled, // no audit trail for object access
		// AWS EC2 hygiene
		awsEC2IMDSv2NotRequired, // IMDSv1 allows SSRF → IAM credential theft
		// VM operating systems past end of life (vm_eol.go)
		awsEC2OSEndOfLife,
		gcpGCEOSEndOfLife,
		// AWS RDS encryption (EBS encryption: aws-ebs-unencrypted in cspm_expanded.go)
		awsRDSNotEncrypted, // unencrypted database storage
		// AWS IAM hygiene
		awsIAMOverprivilegedRole, // admin grant vs Access Advisor actual usage = right-size
		// AWS IAM credential hygiene (CIS 1.x) — dormant users, key sprawl, stale logins
		awsIAMUserInactive,
		awsIAMUserMultipleActiveKeys,
		awsIAMUserUnusedAccessKey, // idle/never-used active key — the leaked-and-never-noticed credential
		awsIAMUserStaleConsole,
		// GCP service-account credential hygiene (CIS GCP 1.x) — the AWS mirror.
		// Each check emits its own finding, so one service account can carry
		// several: an account with an exposed key and an active user-managed
		// key (Google usually disables the exposed one) can carry both
		// gcp-sa-key-exposed and gcp-sa-user-managed-key.
		gcpSAKeyExposed,     // Google-confirmed leaked/compromised key — incident, not hygiene
		gcpSAUserManagedKey, // any downloadable key, graded idle > old > present
		gcpSAUnused,         // dormant SA with standing role bindings
		// AWS IAM Identity Center (SSO) — the human-access layer.
		awsSSOPermissionSetAdmin, // permission set granting admin — the widest standing human privilege
		// GitHub supply-chain
		githubNoBranchProtection, // no branch protection = unreviewed code to prod
		githubNoCodeowners,       // no CODEOWNERS = no automatic owner review
		// Kubernetes cluster identity: the connector's configured cluster_name
		// disagreeing with the cluster's own name breaks every name-keyed join
		// into cloud cluster inventory, silently.
		k8sClusterIdentityMismatch,
		// Kubernetes ConfigMap secrets
		k8sConfigMapPlaintextSecret, // plaintext credentials in ConfigMaps
		// AWS audit controls
		awsCloudTrailNotLogging,
		awsCloudTrailNoValidation,
		// Certificate hygiene — consume k8s_certificate, acm_certificate, gcp_ssl_certificate
		k8sCertExpiringSoon,
		acmCertExpiringSoon,
		gcpSSLCertExpiringSoon,
		// Managed-service breadth: Cloud SQL, Cloud Run, Secrets, ECS
		gcpCloudSQLPublicIP,
		gcpCloudSQLNoSSL,
		gcpCloudRunPublic,
		gcpSecretNoRotation,
		// The guardrail behind gcp-gcs-public-bucket: a bucket whose public-access
		// prevention is `inherited` is one allUsers grant away from public.
		gcpGCSPublicAccessNotPrevented,
		awsECSServicePublicIP,
		awsIAMRootNoMFA,
		awsEKSPublicEndpoint,
		gkePublicEndpoint,
		gkeLegacyABAC,
		awsSecretNoRotation,
		awsECRMutableTags,
		awsECRScanningDisabled,
	)
	// Azure CIS: exposure + misconfiguration checks.
	r.Register(
		azureNSGRDPOpenInternet,
		azureNSGSSHOpenInternet,
		azureStoragePublicAccess,
		azureStorageHTTPSOnly,
		azureSQLServerPublicAccess,
		azureVMDirectPublicIP,
	)
	r.Register(azureFoundationsChecks()...)
	r.Register(azureAttachedDiskNoCMK, azureUnattachedDiskNoCMK, azureWebAppClientCertNotRequired, azureNoLockAdminCustomRole)
	// Azure tenant (Entra), subscription (Defender, Monitor) and Key Vault
	// settings.
	r.Register(azureEntraChecks()...)
	r.Register(azureDefenderChecks()...)
	r.Register(azureDefenderPlanChecks()...)
	r.Register(azureMonitorChecks()...)
	r.Register(azureKeyVaultChecks()...)
	// CIEM privesc findings are produced by the unified engine in
	// internal/app/ciem, not the check registry — so AWS+GCP+Azure and
	// the full technique catalogue share one evaluator. Not registered here.
	r.Register(cspmExtraChecks()...)
	r.Register(cspmExpandedChecks()...)
	// Serverless / API-edge coverage: end-of-life runtimes, open ingress, and
	// internet-facing gateways for cloud_function and api_gateway assets.
	r.Register(serverlessChecks()...)
	// Network placement from route-table-derived subnet facts.
	r.Register(networkChecks()...)
	r.Register(identityPostureChecks()...)
	// AWS account-wide settings, IAM policy documents and data-service posture
	// (CIS AWS Foundations, AWS FSBP).
	r.Register(awsAccountSettingsChecks()...)
	r.Register(awsIAMPolicyChecks()...)
	r.Register(awsIAMCISChecks()...)
	r.Register(awsIAMInlinePolicyChecks()...)
	r.Register(awsIAMRoleTrustChecks()...)
	r.Register(awsOrganizationsChecks()...)
	r.Register(awsDataServiceChecks()...)
	// AWS compute, network, container and database posture (CIS AWS 6.x, FSBP).
	r.Register(awsComputeNetworkChecks()...)
	r.Register(awsDatabaseChecks()...)
	r.Register(awsContainerChecks()...)
	r.Register(awsLifecycleChecks()...)
	r.Register(awsSageMakerChecks()...)
	r.Register(awsAgentCoreChecks()...)
	r.Register(awsAppIntegrationChecks()...)
	r.Register(awsCodeBuildCognitoChecks()...)
	r.Register(awsEMRAppSyncBeanstalkChecks()...)
	r.Register(awsContainerInventoryChecks()...)
	r.Register(awsVPCEdgeChecks()...)
	r.Register(awsLaunchConfigChecks()...)
	r.Register(awsEC2PostureChecks()...)
	r.Register(awsSGPublicRangeChecks()...)
	r.Register(awsELBChecks()...)
	r.Register(awsEdgeTLSChecks()...)
	r.Register(awsCloudFrontChecks()...)
	r.Register(awsWAFChecks()...)
	r.Register(awsAPIGatewayChecks()...)
	r.Register(awsNetworkFirewallChecks()...)
	r.Register(awsSSMChecks()...)
	// AWS logging, monitoring and detection services (CIS AWS 2.18/3.1.3/4.x/5.x, FSBP).
	r.Register(awsLoggingChecks()...)
	r.Register(awsMonitoringChecks()...)
	r.Register(awsDetectionChecks()...)
	r.Register(gcpCISChecks()...)
	r.Register(k8sBenchmarkChecks()...)
	r.Register(k8sControlPlaneChecks()...)
	r.Register(k8sNodeChecks()...)
	r.Register(eksCISChecks()...)
	// Azure resource services (storage/file services, WAF, VPN, flow logs,
	// Databricks) and AKS clusters (CIS Azure Foundations, CIS AKS).
	r.Register(azureResourceChecks()...)
	r.Register(awsAnalyticsChecks()...)
	r.Register(awsS3Checks()...)
	r.Register(awsDataPostureChecks()...)
	r.Register(append(append(awsRDSClusterChecks(), awsDocDBNeptuneChecks()...), awsRDSSettingsChecks()...)...)
	r.Register(awsOpenSearchChecks()...)
	r.Register(append(append(awsDMSChecks(), awsElastiCacheChecks()...), awsMSKChecks()...)...)
	r.Register(awsStorageServiceChecks()...)
	r.Register(awsRedshiftChecks()...)
	return r
}

var awsEC2PublicIP = Check{
	ID:          "aws-ec2-public-ip",
	Title:       "EC2 instance has a public IP",
	Description: "The instance has a public IPv4 address. A running instance is reachable from the internet through it, widening its attack surface (Medium). A stopped instance only keeps a public address when an Elastic IP is associated, and is exposed again the moment it starts (Low).",
	Remediation: "Place the instance in a private subnet behind a NAT gateway or load balancer unless public exposure is required; release or disassociate an Elastic IP a stopped instance no longer needs (`aws ec2 disassociate-address --association-id ASSOC_ID`).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	// FSBP EC2.9 grades every instance carrying a public IPv4, whatever its
	// state: a stopped instance with an Elastic IP is one start away from
	// exposure. Terminated/shutting-down instances are dropped at collection
	// (collect/aws/instances.go).
	Violates:    func(a asset.Asset) bool { return a.PublicIP != "" },
	SeverityFor: func(a asset.Asset) finding.Severity { return runningOr(a, finding.SeverityMedium, finding.SeverityLow) },
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["state"] == "running" {
			return "EC2 instance has a public IP"
		}
		return "Stopped EC2 instance keeps a public IP"
	},
}

// runningOr grades by instance state: a running instance gets running, any
// other (stopped, pending, an unread state) gets otherwise.
func runningOr(a asset.Asset, running, otherwise finding.Severity) finding.Severity {
	if a.Metadata["state"] == "running" {
		return running
	}
	return otherwise
}

var gcpGCEPublicIP = Check{
	ID:          "gcp-gce-public-ip",
	Title:       "Compute Engine instance has a public IP",
	Description: "The instance has an external IP on one of its network interfaces (CIS GCP 4.9). A running instance is reachable from the internet; a stopped one gets its external address back when it starts, so it is reported at a lower severity. GKE nodes are left to gcp-gke-private-nodes-disabled, which reports the node pool once.",
	Remediation: "Remove the access config (`gcloud compute instances delete-access-config INSTANCE --access-config-name=\"External NAT\"`) and route egress through Cloud NAT unless public exposure is required; enforce with the `compute.vmExternalIpAccess` organization policy.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	// external_ip_configured covers every NIC and a stopped VM whose ephemeral
	// address is released; PublicIP is kept for rows collected before it.
	Violates: func(a asset.Asset) bool {
		if gkeNodeGraded(a) {
			return false
		}
		return a.Metadata["external_ip_configured"] == "true" || (a.PublicIP != "" && a.Metadata["status"] == "RUNNING")
	},
	// Only a RUNNING instance is actually reachable; a STOPPED/TERMINATED one
	// serves nothing until it starts. GCE (unlike EC2) is not dropped at
	// collection, so terminated instances arrive here too.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["status"] == "RUNNING" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["status"] == "RUNNING" {
			return "Compute Engine instance has a public IP"
		}
		return "Stopped Compute Engine instance is configured with an external IP"
	},
}

var awsS3PublicBucket = Check{
	ID:          "aws-s3-public-bucket",
	Title:       "S3 bucket is public",
	Description: "The bucket's public-access posture is unsafe. A public bucket policy or ACL (confirmed) exposes objects to anyone on the internet. Otherwise not all four Block Public Access flags are on for the bucket (its own settings combined with the account's): with the block missing (possible) nothing stops a public grant, and with only some flags on a public policy or ACL can still be written even where the rest neutralize it. Neither of those means the bucket is currently public, so they are surfaced at a lower severity.",
	Remediation: "Enable all four S3 Block Public Access settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets) on the bucket, or on the account, and remove any public bucket policy or ACL.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	// Fire on a public grade or an incomplete four-flag block (CIS 3.1.4, FSBP
	// S3.8), but grade everything short of confirmed down to Low — and SAY
	// which one it is via TitleFor, since a static "S3 bucket is public" title
	// on the Low tier would misstate a bucket that merely lacks a flag.
	//
	// Steps aside when aws-s3-public-read / aws-s3-public-write report the
	// grant itself: one public bucket is one finding, named for what it
	// exposes. The confirmed tier still fires for a public grant of neither
	// kind (e.g. a public s3:GetBucketAcl).
	Violates: func(a asset.Asset) bool {
		if s3PublicDataGrant(a) {
			return false
		}
		return a.Metadata["public"] == "true" || a.Metadata["bpa_all_enabled"] == "false"
	},
	SeverityFor: tieredExposureSeverity(finding.SeverityHigh, finding.SeverityLow),
	TitleFor: func(a asset.Asset) string {
		switch {
		case a.Metadata["public_access"] == asset.PublicAccessConfirmed:
			return "S3 bucket is public"
		case a.Metadata["public"] == "true":
			return "S3 bucket has no Block Public Access"
		default:
			return "S3 bucket Block Public Access is not fully enabled"
		}
	},
}

var gcpGCSPublicBucket = Check{
	ID:          "gcp-gcs-public-bucket",
	Title:       "Cloud Storage bucket is public",
	Description: "The bucket grants access to allUsers or allAuthenticatedUsers, exposing its objects to the internet.",
	Remediation: "Remove allUsers/allAuthenticatedUsers IAM bindings and enable public access prevention on the bucket.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcs_bucket",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

var gcpFirewallOpenIngress = Check{
	ID:          "gcp-firewall-open-ingress",
	Title:       "Firewall rule allows ingress from the internet",
	Description: "An enabled ingress firewall rule permits traffic from 0.0.0.0/0 or ::/0, exposing whatever the rule targets to the entire internet. A rule whose every allowed port is blocked first by a higher-priority world-sourced deny on the same network does not fire, and one that opens every port, SSH or RDP is reported by gcp-firewall-all-ports-open-internet / gcp-firewall-ssh-open-internet / gcp-firewall-rdp-open-internet instead. Severity follows what stays open after the denies: every port or protocol, or a database port, is High; only 80/443 is Low (usually a deliberate public service); anything else is Medium. " + gcpFirewallPolicyNote,
	Remediation: "Restrict the rule's source ranges to known CIDRs; remove 0.0.0.0/0 unless the service is intentionally public.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_firewall",
	Violates:    gcpFirewallOpenIngressViolates,
	SeverityFor: firewallOpenSeverity,
	EvidenceFor: firewallEvidence,
}

var githubPublicRepo = Check{
	ID:          "github-public-repo",
	Title:       "Repository is public",
	Description: "The repository is visible to anyone on the internet.",
	Remediation: "Confirm public visibility is intended; otherwise set the repository to private.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGitHub,
	AssetType:   "github_repo",
	Violates:    func(a asset.Asset) bool { return a.Metadata["visibility"] == "public" },
}
