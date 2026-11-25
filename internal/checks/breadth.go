package checks

// breadth.go — posture checks for the managed-service asset types added for
// broader collection coverage: Cloud SQL, Secret Manager, Cloud Run,
// Cloud Functions, and ECS.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var gcpCloudSQLPublicIP = Check{
	ID:          "gcp-cloudsql-public-ip",
	Title:       "Cloud SQL instance has a public IP",
	Description: "The Cloud SQL instance has a public IPv4 address, so the database endpoint is reachable from the internet (subject to authorized networks). Access still requires database credentials — this is network reachability, not confirmed unauthenticated exposure — so it is surfaced at low severity.",
	Remediation: "Disable the public IP and use Private Service Connect or a private IP with the Cloud SQL Auth Proxy.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	// Steps aside when an authorized network admits 0.0.0.0/0:
	// gcp-cloudsql-open-authorized-network reports the same public endpoint at
	// High, so the instance carries one finding.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public"] == "true" && !cloudSQLOpenAuthorizedNetwork(a)
	},
}

var gcpCloudSQLNoSSL = Check{
	ID:          "gcp-cloudsql-no-ssl",
	Title:       "Cloud SQL instance does not require SSL",
	Description: "The Cloud SQL instance accepts unencrypted connections — its SSL mode is ALLOW_UNENCRYPTED_AND_ENCRYPTED, or no SSL mode is set and the legacy require-SSL flag is off — so credentials and data can traverse the network in cleartext.",
	Remediation: "Require TLS: `gcloud sql instances patch INSTANCE --ssl-mode=ENCRYPTED_ONLY` (or TRUSTED_CLIENT_CERTIFICATE_REQUIRED to also require client certificates).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudsql_instance",
	Violates:    cloudSQLNoSSL,
}

var gcpCloudRunPublic = Check{
	ID:          "gcp-cloudrun-public",
	Title:       "Cloud Run service accepts internet ingress",
	Description: "The Cloud Run service ingress allows traffic from the public internet. Whether requests are actually served depends on an allUsers or allAuthenticatedUsers run.invoker binding — gcp-cloudrun-unauthenticated reports that case at high severity — so this network-level exposure alone is surfaced at low severity. Confirm the service enforces its own authentication.",
	Remediation: "Set ingress to 'internal' (or 'internal-and-cloud-load-balancing') unless the service must be publicly reachable.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudrun_service",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public"] == "true" },
}

var gcpSecretNoRotation = Check{
	ID:          "gcp-secret-no-rotation",
	Title:       "Secret Manager secret has no rotation policy",
	Description: "The secret has no rotation period configured, so a leaked value stays valid indefinitely until someone rotates it manually.",
	Remediation: "Configure a rotation period and a rotation Pub/Sub topic so the secret is rotated automatically.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_secret",
	Violates:    func(a asset.Asset) bool { return a.Metadata["rotation"] == "false" },
}

var awsEKSPublicEndpoint = Check{
	ID:          "aws-eks-public-endpoint",
	Title:       "EKS cluster API server is publicly accessible",
	Description: "The EKS cluster's Kubernetes API server endpoint is reachable from the whole internet (endpointPublicAccess=true with publicAccessCidrs including 0.0.0.0/0 or ::/0). A world-open control-plane endpoint is exposed to credential-stuffing, known-CVE exploitation, and misconfigured-RBAC attacks from anywhere. A public endpoint restricted to specific CIDRs is not reported.",
	Remediation: "Disable public endpoint access (endpointPublicAccess=false) and use private access, or restrict publicAccessCidrs to your known egress ranges. Reach the API over a bastion, VPN, or private networking.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	// The allowlist decides: restricting publicAccessCidrs is the remediation
	// this check recommends, so a restricted endpoint must not keep firing. An
	// unreported allowlist is unknown and stays silent.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["endpoint_public_access"] == "true" && csvHasWorldCIDR(a.Metadata["public_access_cidrs"])
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_access_cidrs": a.Metadata["public_access_cidrs"]}
	},
}

// csvHasWorldCIDR reports whether a comma-separated CIDR list includes the
// IPv4 or IPv6 world.
func csvHasWorldCIDR(csv string) bool {
	for _, c := range strings.Split(csv, ",") {
		switch strings.TrimSpace(c) {
		case "0.0.0.0/0", "::/0":
			return true
		}
	}
	return false
}

// gkePublicEndpoint flags a GKE cluster whose control-plane endpoint is public
// with no effective master-authorized-networks allowlist — the GKE analogue of
// the EKS public-endpoint check.
var gkePublicEndpoint = Check{
	ID:          "gcp-gke-public-endpoint",
	Title:       "GKE cluster control plane is publicly accessible",
	Description: "The GKE cluster's Kubernetes API server has a public endpoint and no effective master authorized networks allowlist (none at all, or one that admits 0.0.0.0/0), so the control plane is reachable from anywhere on the internet — exposed to credential-stuffing, known-CVE exploitation, and misconfigured-RBAC attacks.",
	Remediation: "Disable the public IP endpoint in favour of the DNS-based or private endpoint, or configure master authorized networks restricted to known egress ranges (never 0.0.0.0/0).",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    gkePublicEndpointViolates,
}

// gkeLegacyABAC flags a GKE cluster still running legacy attribute-based access
// control, which grants broad permissions and bypasses RBAC.
var gkeLegacyABAC = Check{
	ID:          "gcp-gke-legacy-abac",
	Title:       "GKE cluster has legacy ABAC enabled",
	Description: "Legacy Attribute-Based Access Control is enabled on this cluster. Legacy ABAC grants broad, coarse permissions and undermines Kubernetes RBAC — a privilege-escalation and lateral-movement risk.",
	Remediation: "Disable legacy ABAC (gcloud container clusters update CLUSTER --no-enable-legacy-authorization) and rely on RBAC.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gke_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["legacy_abac"] == "true" },
}

var awsSecretNoRotation = Check{
	ID:          "aws-secretsmanager-no-rotation",
	Title:       "Secrets Manager secret has no rotation configured",
	Description: "The secret does not have automatic rotation enabled, so a leaked value stays valid indefinitely until someone rotates it manually. Parity with the GCP Secret Manager rotation check.",
	Remediation: "Enable rotation with a rotation Lambda and a schedule (aws secretsmanager rotate-secret with RotationRules) so the secret is rotated automatically.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "secretsmanager_secret",
	Violates:    func(a asset.Asset) bool { return a.Metadata["rotation_enabled"] == "false" },
}

var awsECRMutableTags = Check{
	ID:          "aws-ecr-mutable-image-tags",
	Title:       "ECR repository allows mutable image tags",
	Description: "The ECR repository has mutable image tags, so an existing tag (e.g. :latest or a release tag) can be overwritten to point at a different image. Anyone with push access can swap a trusted tag for a malicious image that deployments then pull — an image-provenance / supply-chain risk.",
	Remediation: "Set the repository's tag mutability to IMMUTABLE (aws ecr put-image-tag-mutability --image-tag-mutability IMMUTABLE) so published tags cannot be overwritten.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecr_repository",
	Violates:    func(a asset.Asset) bool { return a.Metadata["tag_mutability"] == "MUTABLE" },
}

// awsECRScanningDisabled surfaces the precondition for trusting ECR as a source of
// vulnerability data at all. A repository with scan-on-push off produces no scan
// results, so anything reading those results reports clean over images that were
// never examined — coverage that looks complete and is empty. That is the same
// failure the image-vuln sweep had for its whole life: wired,
// gated on something nobody set, silently covering nothing.
var awsECRScanningDisabled = Check{
	ID:          "aws-ecr-scanning-disabled",
	Title:       "ECR repository does not scan images for vulnerabilities",
	Description: "Neither the repository (scan-on-push) nor a registry-level scanning rule scans this ECR repository, so images pushed to it are never examined for known CVEs in their OS or language packages. Nothing downstream can report vulnerabilities for these images — an absence of findings here means nobody looked, not that the images are clean.",
	Remediation: "Enable scanning on the repository (aws ecr put-image-scanning-configuration --repository-name <name> --image-scanning-configuration scanOnPush=true), or turn on registry-wide enhanced scanning with Amazon Inspector (aws ecr put-registry-scanning-configuration --scan-type ENHANCED) which also rescans existing images as new CVEs are published.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecr_repository",
	// Registry-level scanning decides first (FSBP ECR.1 passes a repository
	// scanned at either level): a matching on-push or continuous registry rule
	// scans the repository whatever its own flag says, and under ENHANCED
	// scanning AWS ignores the repository flag entirely. An unread registry
	// configuration is unknown coverage and stays silent.
	Violates: func(a asset.Asset) bool {
		if a.Metadata["registry_scan_rule"] != "none" {
			return false
		}
		return a.Metadata["registry_scan_type"] == "ENHANCED" || a.Metadata["scan_on_push"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"scan_on_push":       a.Metadata["scan_on_push"],
			"registry_scan_type": a.Metadata["registry_scan_type"],
		}
	},
}

var awsECSServicePublicIP = Check{
	ID:          "ecs-service-assign-public-ip",
	Title:       "ECS service assigns public IPs to its tasks",
	Description: "The ECS service's awsvpc network configuration sets assignPublicIp=ENABLED, so each task gets a public IP and is directly reachable from the internet rather than sitting behind a load balancer.",
	Remediation: "Set assignPublicIp=DISABLED and place tasks in private subnets behind an internet-facing load balancer or NAT gateway.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ecs_service",
	Violates:    func(a asset.Asset) bool { return a.Metadata["assign_public_ip"] == "ENABLED" },
}
