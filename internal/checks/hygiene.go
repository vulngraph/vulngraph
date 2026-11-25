package checks

// hygiene.go — cloud hygiene checks: dangling/orphaned resources, DNS issues,
// over-exposed network resources. These complement the CIS checks in cis.go.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// --- Elastic IP hygiene ---

var awsEIPUnassociated = Check{
	ID:          "aws-eip-unassociated",
	Title:       "Elastic IP is not associated with any resource",
	Description: "The Elastic IP has no association — it is not attached to an EC2 instance or network interface. Unassociated EIPs waste a public IP address and may indicate a dangling resource left after deprovisioning.",
	Remediation: "Release the Elastic IP if it is no longer needed, or associate it with the intended resource.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "elastic_ip",
	Violates: func(a asset.Asset) bool {
		// An EIP attached to a bare network interface (not directly to an
		// instance) has an empty instance_id but a non-empty
		// network_interface_id — it is associated and must not be flagged.
		return observedNone(a, "association_id") &&
			observedNone(a, "instance_id") &&
			observedNone(a, "network_interface_id")
	},
}

// --- Load balancer hygiene ---

var awsLBInternetFacing = Check{
	ID:          "aws-alb-internet-facing",
	Title:       "Application Load Balancer is internet-facing",
	Description: "The ALB has scheme 'internet-facing', making it reachable from the public internet. Confirm this is intentional for external-facing services.",
	Remediation: "If the ALB only serves internal traffic, change its scheme to 'internal'.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["scheme"] == "internet-facing"
	},
}

// --- Security group exposure ---

// sgIngressRule mirrors the JSON the AWS collector serializes into a
// security_group's metadata["ingress"]. Declared locally so checks stays
// independent of the collector and correlate packages.
type sgIngressRule struct {
	Protocol string   `json:"protocol"`
	FromPort int32    `json:"from_port"`
	ToPort   int32    `json:"to_port"`
	CIDRs    []string `json:"cidrs"`
}

// adminPorts are the management ports that must never be open to the world:
// SSH, RDP, and WinRM (5985 HTTP / 5986 HTTPS — remote PowerShell, which takes
// the same credentials as RDP).
var adminPorts = []int32{22, 3389, 5985, 5986}

// sgWorldOpenAdminPort reports whether any ingress rule exposes an admin port
// (SSH/RDP/WinRM) to the world, 0.0.0.0/0 or ::/0 — including "all protocols" and port-range rules that
// span the port.
func sgWorldOpenAdminPort(a asset.Asset) bool {
	raw := a.Metadata["ingress"]
	if raw == "" {
		return false
	}
	var rules []sgIngressRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return false
	}
	for _, r := range rules {
		// ICMP rules reuse the port fields for type/code (PortAddressed).
		if !ruleWorldOpen(r) || !PortAddressed(r.Protocol) {
			continue
		}
		if r.Protocol == "-1" || r.Protocol == "" {
			return true // all protocols/ports
		}
		for _, p := range adminPorts {
			if r.FromPort <= p && p <= r.ToPort {
				return true
			}
		}
	}
	return false
}

// sgUnrestrictedEgress reports whether any egress rule allows all traffic to
// the world (0.0.0.0/0 or ::/0) — a data-exfiltration path. The default SG egress rule is all-open,
// so this is common, but flagging it surfaces SGs that should be locked down
// for sensitive workloads (PCI/regulated environments require egress filtering).
func sgUnrestrictedEgress(a asset.Asset) bool {
	raw := a.Metadata["egress"]
	if raw == "" {
		return false
	}
	var rules []sgIngressRule
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return false
	}
	for _, r := range rules {
		if r.Protocol != "-1" && r.Protocol != "" {
			continue // only flag all-protocol egress
		}
		if ruleWorldOpen(r) {
			return true
		}
	}
	return false
}

var awsSGUnrestrictedEgress = Check{
	ID:          "aws-security-group-unrestricted-egress",
	Title:       "Security group allows unrestricted outbound traffic",
	Description: "An egress rule allows all protocols to 0.0.0.0/0 or ::/0. A compromised instance in this group can exfiltrate data to any destination and reach any command-and-control endpoint. Egress filtering is required by PCI-DSS and recommended for any workload handling sensitive data.",
	Remediation: "Replace the all-open egress rule with specific destination CIDRs and ports for the services the workload legitimately needs (e.g. package mirrors, API endpoints, VPC endpoints).",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	Violates:    sgUnrestrictedEgress,
}

var awsSGWorldOpenAdminPort = Check{
	// The ID is finding identity in ClickHouse. Do NOT rename — that would
	// orphan every live finding stored under the current ID.
	ID:          "aws-security-group-world-open-admin-port",
	Title:       "Security group exposes an admin port to the internet",
	Description: "An ingress rule allows 0.0.0.0/0 or ::/0 to reach SSH (22), RDP (3389) or WinRM (5985/5986). Any instance in this security group is one misconfiguration away from direct internet access to its management plane.",
	Remediation: "Restrict the ingress rule to a bastion host, VPN CIDR, or specific source security group; never expose 22/3389/5985/5986 to 0.0.0.0/0.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	// Suppressed when the group is open on ALL ports: aws-sg-open-all-ports
	// reports that at Critical and strictly dominates. Without the gate an
	// all-open group matches this check and aws-sg-open-database-ports too, so
	// it would be reported three times.
	Violates: func(a asset.Asset) bool {
		return !sgAllPortsWorldOpen(a) && sgWorldOpenAdminPort(a)
	},
}

// --- DNS hygiene ---

// knownTakeoverServices is a list of external service endpoint suffixes that are
// commonly abused for subdomain takeover when a CNAME or ALIAS points there but
// the service account/bucket/app is no longer claimed.
// Source: https://github.com/EdOverflow/can-i-take-over-xyz (updated 2025)
var knownTakeoverServices = []string{
	// AWS
	".s3.amazonaws.com",
	".s3-website",
	".elasticbeanstalk.com",
	".cloudfront.net", // AWS CloudFront — most common AWS takeover vector
	// Azure
	".azurewebsites.net",
	".cloudapp.azure.com",
	".azurefd.net",
	".azureedge.net",         // Azure CDN
	".azurestaticapps.net",   // Azure Static Web Apps
	".trafficmanager.net",    // Azure Traffic Manager
	".blob.core.windows.net", // Azure Blob Storage
	// GitHub
	".github.io",
	// Heroku
	".herokuapp.com",
	".herokudns.com",
	// CDN / hosting
	".fastly.net",
	".pantheonsite.io",
	".ghost.io",
	".netlify.app",
	".netlify.com",
	".surge.sh",
	".vercel.app", // Vercel (next-gen hosting)
	".render.com", // Render
	".fly.dev",    // Fly.io
	// Content / docs
	".readthedocs.io",
	".webflow.io",
	".gitbook.io",
	".readme.io",
	// E-commerce / SaaS
	".myshopify.com",
	".bitbucket.io",
	".wordpress.com",
	".zendesk.com",
	".wpengine.com",
	".helpscoutdocs.com",
	".freshdesk.com",
}

// isWildcardCNAME returns true if the DNS record is a wildcard (*.example.com).
// Wildcard CNAMEs pointing at takeover-prone services are graded High, above the
// specific-record check, because they expose all subdomains, not just one.
func isWildcardCNAME(a asset.Asset) bool {
	return strings.HasPrefix(a.Name, "*.") || strings.HasPrefix(a.Name, "\\052.")
}

// cnameTakeoverViolates is the shared check logic for AWS and GCP.
func cnameTakeoverViolates(a asset.Asset) bool {
	t := a.Metadata["type"]
	if t != "CNAME" && t != "ALIAS" {
		return false
	}
	values := strings.ToLower(a.Metadata["values"])
	for _, svc := range knownTakeoverServices {
		if strings.Contains(values, svc) {
			return true
		}
	}
	return false
}

var dnsRecordCNAMETakeoverRisk = Check{
	ID:          "dns-cname-takeover-risk",
	Title:       "CNAME points to a takeover-prone service endpoint (verify ownership)",
	Description: "The DNS CNAME or Alias record points to a third-party service platform (S3, Heroku, GitHub Pages, CloudFront, Azure, etc.). If the corresponding resource on that platform is deleted or unclaimed, an attacker can register it and serve content from this subdomain. This is a candidate flagged by pattern only — a correctly-owned, live target is NOT vulnerable and this fires on it too; confirm the target is unclaimed before treating it as a takeover.",
	Remediation: "Verify the target resource (S3 bucket, Heroku app, GitHub Pages site, CloudFront distribution, etc.) is actively claimed and owned. Delete the CNAME if the service is deprovisioned.",
	Type:        "hygiene",
	// Non-wildcard only: wildcards fire the High wildcard check below instead,
	// so a record never gets both. Pattern-match only, so this is a
	// review-severity candidate, not a confirmed takeover.
	Severity:  finding.SeverityMedium,
	Provider:  asset.ProviderAWS,
	AssetType: "dns_record",
	Violates:  func(a asset.Asset) bool { return !isWildcardCNAME(a) && cnameTakeoverViolates(a) },
}

// dnsWildcardCNAMETakeoverRisk is the High-severity variant that fires only
// on wildcard CNAME records. A wildcard like *.example.com →
// defunct-app.herokuapp.com lets an attacker take over every subdomain.
var dnsWildcardCNAMETakeoverRisk = Check{
	ID:          "dns-wildcard-cname-takeover-risk",
	Title:       "Wildcard CNAME points to a service endpoint susceptible to subdomain takeover",
	Description: "The wildcard DNS record (*.subdomain.example.com) points to a third-party service. If the target is deleted or unclaimed, an attacker can serve content from ANY subdomain matching the wildcard — a single takeover compromises all *.subdomain.example.com endpoints. Pattern-matched only: confirm the target is actually unclaimed, as a live owned target fires this too.",
	Remediation: "Verify the target resource is owned. If the service is deprovisioned, delete the wildcard CNAME urgently — a wildcard takeover enables phishing, session hijacking (SameSite cookie bypass), and TLS certificate issuance.",
	Type:        "hygiene",
	// Higher than the specific-CNAME candidate because a wildcard takeover is far
	// broader, but still short of Critical since dangling is not verified.
	Severity:  finding.SeverityHigh,
	Provider:  asset.ProviderAWS,
	AssetType: "dns_record",
	Violates: func(a asset.Asset) bool {
		return isWildcardCNAME(a) && cnameTakeoverViolates(a)
	},
}

// gcpDNSCNAMETakeoverRisk mirrors the AWS check for GCP-hosted DNS records.
var gcpDNSCNAMETakeoverRisk = Check{
	ID:          "gcp-dns-cname-takeover-risk",
	Title:       "GCP-hosted CNAME points to a takeover-prone service endpoint (verify ownership)",
	Description: "The GCP Cloud DNS CNAME record points to a third-party service platform. If the target resource is deleted or unclaimed, an attacker can register it and serve content from this subdomain. Pattern-matched only — a live, owned target fires this too; confirm the target is unclaimed.",
	Remediation: "Verify the target resource is actively claimed. Delete the CNAME if the service is deprovisioned.",
	Type:        "hygiene",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "dns_record",
	Violates:    func(a asset.Asset) bool { return !isWildcardCNAME(a) && cnameTakeoverViolates(a) },
}

// gcpDNSWildcardCNAMETakeoverRisk is the GCP wildcard variant.
var gcpDNSWildcardCNAMETakeoverRisk = Check{
	ID:          "gcp-dns-wildcard-cname-takeover-risk",
	Title:       "GCP wildcard CNAME points to a service endpoint susceptible to subdomain takeover",
	Description: "The wildcard GCP Cloud DNS record points to a third-party service. An attacker who claims the target can serve from any matching subdomain. Pattern-matched only: confirm the target is actually unclaimed.",
	Remediation: "Verify the target resource is owned and delete the wildcard CNAME if deprovisioned.",
	Type:        "hygiene",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "dns_record",
	Violates: func(a asset.Asset) bool {
		return isWildcardCNAME(a) && cnameTakeoverViolates(a)
	},
}

// There is no private-zone-record check. It would report a fact, not a
// problem: a record in a private hosted zone is the correct, intended state
// for internal DNS.

// awsS3NoVersioning fires on S3 buckets without versioning enabled.
// Versioning protects against accidental deletion and ransomware overwrites.
var awsS3NoVersioning = Check{
	ID:          "aws-s3-no-versioning",
	Title:       "S3 bucket does not have versioning enabled",
	Description: "The S3 bucket has versioning disabled or suspended. Without versioning, objects deleted or overwritten cannot be recovered. This is a common ransomware attack vector and a compliance gap for data retention requirements.",
	Remediation: "Enable versioning: aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled. Add a lifecycle policy to expire old versions after a retention period.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates: func(a asset.Asset) bool {
		v := a.Metadata["versioning"]
		return v == "disabled" || v == "suspended"
	},
}

// --- AWS EC2 hygiene ---

var awsEC2IMDSv2NotRequired = Check{
	ID:          "aws-ec2-imdsv2-not-required",
	Title:       "EC2 instance allows IMDSv1 (SSRF token theft risk)",
	Description: "The instance metadata service (IMDS) is configured with HttpTokens=optional, allowing IMDSv1 requests without session tokens. An SSRF vulnerability in the application can be used to steal the instance's IAM credentials from the metadata endpoint without any extra authentication.",
	Remediation: "Enforce IMDSv2: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 1. Set ImdsV2 required in launch templates and enforce via SCP.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		// Explicit "optional" only. DescribeInstances populates http_tokens for
		// every instance today, which is precisely why
		// != "required" looked safe: one failed or partial describe and every
		// instance becomes a High finding at once, with nothing in the data to say
		// they were never observed.
		//
		// Steps aside for a Kubernetes node whose role can push to ECR:
		// aws-eks-node-imdsv1-registry-write reports the same setting with the
		// consequence attached, and one instance should carry one finding.
		return imdsV1Reachable(a) && !eksNodeIMDSv1RegistryWriteViolates(a)
	},
}

// --- AWS S3 logging ---

var awsS3AccessLoggingDisabled = Check{
	ID:          "aws-s3-access-logging-disabled",
	Title:       "S3 bucket has access logging disabled",
	Description: "Server access logging is not enabled for the bucket. Without access logs, there is no record of who accessed or modified objects — forensics after a data breach is impossible and compliance requirements (PCI-DSS, HIPAA, SOC 2) are not met.",
	Remediation: "Enable access logging: aws s3api put-bucket-logging --bucket <name> --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"<log-bucket>\",\"TargetPrefix\":\"<name>/\"}}'",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["logging"] == "disabled"
	},
}

// --- AWS RDS hygiene ---

var awsRDSNotEncrypted = Check{
	ID:          "aws-rds-not-encrypted",
	Title:       "RDS instance storage is not encrypted at rest",
	Description: "The RDS database instance has storage encryption disabled. Unencrypted database storage exposes all table data, indexes, logs, and backups to anyone with physical or AWS-level access to the underlying storage. Its automated snapshots inherit the setting. Aurora, Multi-AZ DB cluster, DocumentDB and Neptune instances take their encryption from the cluster and are reported once, on the cluster (aws-rds-cluster-not-encrypted and its DocumentDB/Neptune counterparts).",
	Remediation: "Encryption can only be enabled at creation time for RDS. To encrypt an existing unencrypted instance: create a snapshot, copy the snapshot with encryption, restore a new encrypted instance from the snapshot. Enable encryption by default via AWS Config rule.",
	Type:        "misconfiguration",
	// Encryption at rest with no exposure attached is posture, not the page
	// band: Medium, like the cluster checks and FSBP RDS.3.
	Severity:  finding.SeverityMedium,
	Provider:  asset.ProviderAWS,
	AssetType: "rds_instance",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["storage_encrypted"] == "false" && !rdsClusterMember(a)
	},
}

// --- IAM MFA ---
//
// MFA is graded only by cspm_extra.go's aws-iam-user-no-mfa, at Critical,
// since console access without MFA is a live account-takeover path, not
// merely hygiene. A second check here on the same iam_user predicate would
// produce two findings per user at two different severities.

// --- IAM over-privileged role (Access Advisor evidence) ---

var awsIAMOverprivilegedRole = Check{
	ID:          "aws-iam-overprivileged-role",
	Title:       "IAM role grants admin but uses a fraction of it (right-size candidate)",
	Description: "The role carries admin-level access (AdministratorAccess or Allow *:*) but IAM Access Advisor shows it has actually used only a small subset of the services that grant allows. An over-privileged role is a blast-radius multiplier: a compromise of whatever assumes it (especially an internet-facing workload) yields far more access than the workload needs.",
	Remediation: "Right-size to least privilege using the recorded usage: replace AdministratorAccess with a policy scoped to the services in 'aa_used_services'. Validate in staging, then roll to prod. For a role unused for 90+ days, delete it instead.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_role",
	Violates:    overprivilegedAdminRole,
}

// overprivilegedAdminRole is aws-iam-overprivileged-role's predicate, named so
// aws-iam-role-full-admin can step aside for it.
func overprivilegedAdminRole(a asset.Asset) bool {
	// A dormant admin role is aws-iam-admin-role-dormant's finding: its fix
	// is deletion, not right-sizing.
	if roleAdminReach(a) != reachAdmin || dormantAdminRole(a) {
		return false
	}
	// Evidence-based: only fire when Access Advisor data is present AND shows
	// the role uses fewer services than its grant allows (always true for a
	// genuine admin role — the value is the recorded used-services list that
	// the remediation scopes to). No AA data → no finding (avoids the sentinel).
	granted, gErr := strconv.Atoi(a.Metadata["aa_services_granted"])
	used, uErr := strconv.Atoi(a.Metadata["aa_services_used"])
	return gErr == nil && uErr == nil && granted > 0 && used < granted
}

// --- GitHub branch protection ---

var githubNoBranchProtection = Check{
	ID:          "github-no-branch-protection",
	Title:       "GitHub repository default branch has no branch protection rules",
	Description: "The repository's default branch has no branch protection rules. Anyone with write access can force-push, delete the branch, or merge unreviewed code directly. This is a supply-chain risk: malicious commits can reach production without code review.",
	Remediation: "Enable branch protection: require pull request reviews before merging, require status checks to pass, and enable 'Require branches to be up to date'. Consider enabling signed commits and dismissal of stale reviews.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGitHub,
	AssetType:   "github_repo",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["branch_protection"] == "disabled" &&
			a.Metadata["archived"] != "true"
	},
}

// --- k8s ConfigMap secrets ---

var k8sConfigMapPlaintextSecret = Check{
	ID:          "k8s-configmap-plaintext-secret",
	Title:       "Kubernetes ConfigMap contains a plaintext secret-like value",
	Description: "A ConfigMap key name matches a secret pattern (password, token, apikey, etc.) and contains a non-placeholder value. Kubernetes treats ConfigMaps as non-secret configuration: Secrets can be envelope-encrypted at rest and RBAC-scoped separately, while ConfigMap read access is commonly granted broadly and ConfigMaps are usually left out of encryption-at-rest configuration." + k8sConfigMapSkippedNote,
	Remediation: "Move the value to a Kubernetes Secret (or preferably external secrets via External Secrets Operator / Vault). Never store credentials, API keys, or passwords in ConfigMaps.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_configmap",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["has_plaintext_secret"] == "true"
	},
}

// --- Subnet hygiene ---

var awsSubnetAutoAssignPublicIP = Check{
	ID:          "aws-subnet-auto-assign-public-ip",
	Title:       "Subnet automatically assigns public IPs to instances",
	Description: "The subnet has 'MapPublicIpOnLaunch' enabled, meaning any EC2 instance launched into this subnet automatically receives a public IPv4 address. This widens the attack surface unless the subnet is intended to host internet-facing resources.",
	Remediation: "Disable MapPublicIpOnLaunch on private subnets. Use Elastic IPs or a load balancer for intentional public exposure.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "subnet",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["map_public_ip_on_launch"] == "true"
	},
}

// --- Certificate hygiene ---
// These checks consume the three cert collectors
// (k8s_certificate from cert-manager, acm_certificate from AWS ACM,
// gcp_ssl_certificate from GCP Compute). All use the same metadata schema:
// expires_at, days_until_expiry, expiring_soon.

// certExpiryViolates returns true when days_until_expiry < 0 (expired) or
// the expiring_soon sentinel is set by the collector (≤30 days).
func certExpiryViolates(a asset.Asset) bool {
	if a.Metadata["expiring_soon"] == "true" {
		return true
	}
	// Also catch already-expired (negative days)
	if d := a.Metadata["days_until_expiry"]; d != "" {
		var days int
		if _, err := fmt.Sscanf(d, "%d", &days); err == nil && days < 0 {
			return true
		}
	}
	return false
}

var k8sCertExpiringSoon = Check{
	ID:          "k8s-cert-expiring-soon",
	Title:       "cert-manager Certificate is expiring within 30 days or already expired",
	Description: "The cert-manager Certificate resource will expire within 30 days (or has already expired). An expired certificate causes TLS errors for clients, service outages, and may block mutual-TLS traffic within the cluster.",
	Remediation: "Check cert-manager logs for renewal failures. Verify the Issuer/ClusterIssuer is healthy, DNS challenges are resolving, and rate limits haven't been hit. For Let's Encrypt: run `kubectl describe certificate <name>` to see the renewal error.",
	Type:        "hygiene",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_certificate",
	Violates:    certExpiryViolates,
}

var acmCertExpiringSoon = Check{
	ID:          "acm-cert-expiring-soon",
	Title:       "AWS ACM certificate is expiring within 30 days or already expired",
	Description: "An ACM certificate will expire within 30 days. ACM auto-renews certificates attached to AWS resources (ALBs, CloudFront), but certificates used in non-AWS contexts require manual renewal.",
	Remediation: "If attached to an AWS resource: verify ACM auto-renewal is not blocked (check certificate status and pending validation). If exported to an EC2 instance or on-prem: renew and redeploy manually before expiry.",
	Type:        "hygiene",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "acm_certificate",
	Violates:    certExpiryViolates,
}

var gcpSSLCertExpiringSoon = Check{
	ID:          "gcp-ssl-cert-expiring-soon",
	Title:       "GCP SSL certificate is expiring within 30 days or already expired",
	Description: "A GCP Compute SSL certificate will expire within 30 days. Expired certificates cause TLS errors on GCP Load Balancers and API Gateways using this certificate.",
	Remediation: "For MANAGED certificates: verify the domain DNS is resolving to the load balancer IP and the provisioning state is ACTIVE. For SELF_MANAGED: generate a new certificate and update the load balancer target HTTPS proxy.",
	Type:        "hygiene",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_ssl_certificate",
	Violates:    certExpiryViolates,
}

// --- AWS audit controls ---

var awsCloudTrailNotLogging = Check{
	ID:          "aws-cloudtrail-not-logging",
	Title:       "CloudTrail trail is not currently logging",
	Description: "The CloudTrail trail exists but IsLogging is false, meaning no API calls are being recorded. Any actions taken while logging is disabled will leave no audit trail — a critical control failure for incident response and compliance.",
	Remediation: "Enable logging: `aws cloudtrail start-logging --name <trail-arn>`. Investigate why logging was disabled — it may indicate unauthorized access attempting to cover tracks.",
	Type:        "hygiene",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_cloudtrail",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["is_logging"] == "false"
	},
}

var awsCloudTrailNoValidation = Check{
	ID:          "aws-cloudtrail-no-log-validation",
	Title:       "CloudTrail log file integrity validation is disabled",
	Description: "LogFileValidationEnabled is false. Without log file validation, an attacker who gains S3 write access can modify or delete CloudTrail logs and those changes cannot be detected forensically.",
	Remediation: "Enable log file validation: `aws cloudtrail update-trail --name <name> --enable-log-file-validation`. This creates a digest file for each log delivery that can be used to verify integrity.",
	Type:        "hygiene",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_cloudtrail",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["log_file_validation"] == "false"
	},
}
