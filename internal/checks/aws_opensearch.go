package checks

// aws_opensearch.go — Amazon OpenSearch Service domain posture (AWS FSBP
// ES.1-8, Opensearch.1-8/10). The opensearch API describes legacy
// Elasticsearch domains and OpenSearch domains alike, and Security Hub grades
// the same field on both under two control families, so each check covers
// both rows for one domain: one finding per root cause, whatever the engine.

import (
	"slices"
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsOpenSearchChecks() []Check {
	return []Check{
		awsOpenSearchDomainPublic,
		awsOpenSearchNotEncryptedAtRest,
		awsOpenSearchNoNodeToNodeEncryption,
		awsOpenSearchErrorLogsDisabled,
		awsOpenSearchAuditLogsDisabled,
		awsOpenSearchTooFewDataNodes,
		awsOpenSearchTooFewDedicatedMasters,
		awsOpenSearchNoFineGrainedAccessControl,
		awsOpenSearchWeakTLSPolicy,
		awsOpenSearchSoftwareUpdateAvailable,
	}
}

var awsOpenSearchDomainPublic = Check{
	ID:          "aws-opensearch-domain-public",
	Title:       "OpenSearch domain has a public endpoint",
	Description: "The domain was created with a public endpoint rather than inside a VPC, so its HTTPS endpoint is reachable from the whole internet and only the access policy (and fine-grained access control, when on) stands between a caller and the indices. Confirmed: the access policy grants the data-plane actions (es:ESHttp*) to everyone (Principal \"*\", or an Allow with NotPrincipal) with no condition that restricts the caller, and fine-grained access control does not authenticate the caller, so anyone can read and write every index. Otherwise the endpoint is public but still credential-gated. FSBP ES.2 / Opensearch.2.",
	Remediation: "A domain cannot be moved into a VPC in place. Immediately: replace the access policy statement granting Principal \"*\" (or the Allow with NotPrincipal) with one naming specific IAM principals (console: OpenSearch Service > Domains > DOMAIN > Security configuration > Access policy; CLI: `aws opensearch update-domain-config --domain-name DOMAIN --access-policies file://policy.json`) and enable fine-grained access control. Then create a VPC domain (`aws opensearch create-domain ... --vpc-options SubnetIds=...,SecurityGroupIds=...`), restore a manual snapshot into it, and delete the public domain.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates:    func(a asset.Asset) bool { return a.Metadata["in_vpc"] == "false" },
	SeverityFor: tieredExposureSeverity(finding.SeverityCritical, finding.SeverityMedium),
	TitleFor: tieredExposureTitle(
		"OpenSearch domain is publicly readable and writable",
		"OpenSearch domain has a public endpoint"),
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"access_policy_public":        a.Metadata["access_policy_public"],
			"fine_grained_access_control": a.Metadata["fine_grained_access_control"],
		}
	},
}

var awsOpenSearchNotEncryptedAtRest = Check{
	ID:          "aws-opensearch-not-encrypted-at-rest",
	Title:       "OpenSearch domain is not encrypted at rest",
	Description: "Encryption at rest is off, so the domain's indices, logs, swap files and automated snapshots sit on disk unencrypted. FSBP ES.1 / Opensearch.1.",
	Remediation: "Console: OpenSearch Service > Domains > DOMAIN > Actions > Edit security configuration > Enable encryption of data at rest. CLI: `aws opensearch update-domain-config --domain-name DOMAIN --encryption-at-rest-options Enabled=true,KmsKeyId=KEY`. Domains on Elasticsearch older than 5.1 or on t2 instances must be upgraded or recreated first.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates:    func(a asset.Asset) bool { return a.Metadata["encryption_at_rest"] == "false" },
}

var awsOpenSearchNoNodeToNodeEncryption = Check{
	ID:          "aws-opensearch-no-node-to-node-encryption",
	Title:       "OpenSearch domain does not encrypt traffic between nodes",
	Description: "Node-to-node encryption is off, so shard replication and queries between the domain's nodes cross the network in clear text inside AWS's network. FSBP ES.3 / Opensearch.3.",
	Remediation: "Console: Domains > DOMAIN > Actions > Edit security configuration > Node-to-node encryption. CLI: `aws opensearch update-domain-config --domain-name DOMAIN --node-to-node-encryption-options Enabled=true` (Elasticsearch 6.0 or later; older domains must be upgraded first).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates:    func(a asset.Asset) bool { return a.Metadata["node_to_node_encryption"] == "false" },
}

var awsOpenSearchErrorLogsDisabled = Check{
	ID:          "aws-opensearch-error-logs-disabled",
	Title:       "OpenSearch domain does not publish error logs to CloudWatch",
	Description: "The domain does not publish its error (application) logs to CloudWatch Logs, so errors and warnings from the engine, including failed requests that can signal probing, are not retained. FSBP ES.4 / Opensearch.4.",
	Remediation: "Console: Domains > DOMAIN > Logs > Error logs > Enable, choosing a log group. CLI: `aws opensearch update-domain-config --domain-name DOMAIN --log-publishing-options 'ES_APPLICATION_LOGS={CloudWatchLogsLogGroupArn=LOG_GROUP_ARN,Enabled=true}'` (the log group's resource policy must allow es.amazonaws.com to write).",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates:    func(a asset.Asset) bool { return a.Metadata["error_logs_enabled"] == "false" },
}

var awsOpenSearchAuditLogsDisabled = Check{
	ID:          "aws-opensearch-audit-logs-disabled",
	Title:       "OpenSearch domain does not publish audit logs",
	Description: "Fine-grained access control is on but audit logs are not published to CloudWatch Logs, so authentication failures, privilege changes and index access leave no record. FSBP ES.5 / Opensearch.5. A domain without fine-grained access control cannot publish audit logs at all; aws-opensearch-no-fine-grained-access-control reports that domain instead.",
	Remediation: "Console: Domains > DOMAIN > Logs > Audit logs > Enable, then choose the audit categories in OpenSearch Dashboards (Security > Audit logs). CLI: `aws opensearch update-domain-config --domain-name DOMAIN --log-publishing-options 'AUDIT_LOGS={CloudWatchLogsLogGroupArn=LOG_GROUP_ARN,Enabled=true}'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["audit_logs_enabled"] == "false" && a.Metadata["fine_grained_access_control"] == "true"
	},
}

// openSearchMinNodes is the FSBP ES.6/ES.7/Opensearch.6/Opensearch.11 floor
// for data nodes and dedicated master nodes alike.
const openSearchMinNodes = 3

var awsOpenSearchTooFewDataNodes = Check{
	ID:          "aws-opensearch-too-few-data-nodes",
	Title:       "OpenSearch domain has fewer than three data nodes or no zone awareness",
	Description: "The domain runs fewer than three data nodes, or zone awareness is off, so losing one node or one Availability Zone can make the domain unavailable or lose unreplicated shards. FSBP ES.6 / Opensearch.6 require at least three data nodes and zone awareness.",
	Remediation: "Console: Domains > DOMAIN > Actions > Edit cluster configuration > Data nodes: 3 or more (a multiple of the zone count) and Multi-AZ. CLI: `aws opensearch update-domain-config --domain-name DOMAIN --cluster-config InstanceCount=3,ZoneAwarenessEnabled=true,ZoneAwarenessConfig={AvailabilityZoneCount=3}`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates: func(a asset.Asset) bool {
		if n, err := strconv.Atoi(a.Metadata["instance_count"]); err == nil && n < openSearchMinNodes {
			return true
		}
		return a.Metadata["zone_awareness"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"instance_count": a.Metadata["instance_count"], "zone_awareness": a.Metadata["zone_awareness"]}
	},
}

var awsOpenSearchTooFewDedicatedMasters = Check{
	ID:          "aws-opensearch-too-few-dedicated-masters",
	Title:       "OpenSearch domain has fewer than three dedicated master nodes",
	Description: "The domain has no dedicated master nodes, or fewer than three, so cluster management runs on data nodes (or on a master set that loses quorum with one failure) and a blue/green deployment or node loss can stall the cluster. FSBP ES.7 (and Opensearch.11).",
	Remediation: "Console: Domains > DOMAIN > Actions > Edit cluster configuration > Dedicated master nodes: enable, 3 nodes. CLI: `aws opensearch update-domain-config --domain-name DOMAIN --cluster-config DedicatedMasterEnabled=true,DedicatedMasterCount=3,DedicatedMasterType=TYPE`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["dedicated_master_enabled"] == "false" {
			return true
		}
		n, err := strconv.Atoi(a.Metadata["dedicated_master_count"])
		return a.Metadata["dedicated_master_enabled"] == "true" && err == nil && n < openSearchMinNodes
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"dedicated_master_enabled": a.Metadata["dedicated_master_enabled"], "dedicated_master_count": a.Metadata["dedicated_master_count"]}
	},
}

var awsOpenSearchNoFineGrainedAccessControl = Check{
	ID:          "aws-opensearch-no-fine-grained-access-control",
	Title:       "OpenSearch domain does not use fine-grained access control",
	Description: "Fine-grained access control is off, so the domain authorizes requests only at the domain level through its access policy: anyone the policy admits can read and write every index, with no index-, document- or field-level roles, and audit logging cannot be enabled. FSBP Opensearch.7 (and the prerequisite of ES.5 / Opensearch.5 audit logs).",
	Remediation: "Console: Domains > DOMAIN > Actions > Edit security configuration > Enable fine-grained access control and set a master user (IAM ARN preferred). CLI: `aws opensearch update-domain-config --domain-name DOMAIN --advanced-security-options 'Enabled=true,MasterUserOptions={MasterUserARN=ROLE_ARN}'` (requires HTTPS, node-to-node encryption and encryption at rest).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates:    func(a asset.Asset) bool { return a.Metadata["fine_grained_access_control"] == "false" },
}

// openSearchCurrentTLSPolicies are the endpoint TLS policies FSBP ES.8 /
// Opensearch.8 accept: the latest general policy, and the FIPS policy, which
// is stricter still (TLS 1.2+, a FIPS-only cipher subset).
var openSearchCurrentTLSPolicies = []string{
	"Policy-Min-TLS-1-2-PFS-2023-10",
	"Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08",
}

var awsOpenSearchWeakTLSPolicy = Check{
	ID:          "aws-opensearch-weak-tls-policy",
	Title:       "OpenSearch domain does not require HTTPS with the latest TLS policy",
	Description: "The domain endpoint either accepts plain HTTP (EnforceHTTPS off) or negotiates with an older TLS security policy than Policy-Min-TLS-1-2-PFS-2023-10, which still allows TLS 1.0/1.1 or ciphers without forward secrecy. FSBP ES.8 / Opensearch.8.",
	Remediation: "Console: Domains > DOMAIN > Actions > Edit security configuration (or Edit domain > Network) > Require HTTPS, TLS security policy Policy-Min-TLS-1-2-PFS-2023-10. CLI: `aws opensearch update-domain-config --domain-name DOMAIN --domain-endpoint-options EnforceHTTPS=true,TLSSecurityPolicy=Policy-Min-TLS-1-2-PFS-2023-10`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["enforce_https"] == "false" {
			return true
		}
		p, ok := a.Metadata["tls_security_policy"]
		return ok && a.Metadata["enforce_https"] == "true" && !slices.Contains(openSearchCurrentTLSPolicies, p)
	},
	TableProbes: openSearchCurrentTLSPolicies,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"enforce_https": a.Metadata["enforce_https"], "tls_security_policy": a.Metadata["tls_security_policy"]}
	},
}

var awsOpenSearchSoftwareUpdateAvailable = Check{
	ID:          "aws-opensearch-software-update-available",
	Title:       "OpenSearch domain has a service software update waiting",
	Description: "A service software update (platform fixes, including security patches) is available for the domain but not installed. AWS installs required updates automatically after about two weeks; optional ones wait for an operator. FSBP Opensearch.10.",
	Remediation: "Console: Domains > DOMAIN > Actions > Update (schedule for the off-peak window). CLI: `aws opensearch start-service-software-update --domain-name DOMAIN --schedule-at OFF_PEAK_WINDOW`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "opensearch_domain",
	Violates:    func(a asset.Asset) bool { return a.Metadata["service_software_update_available"] == "true" },
}
