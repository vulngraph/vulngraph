package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Systems Manager and Route 53 posture (AWS FSBP SSM.2/.3/.4/.6/.7,
// Route53.2): compliance stamped on ec2_instance, ssm_document sharing, the
// regional SSM service settings on aws_region_settings, and hosted-zone query
// logging on dns_zone (collect/aws/ssm_documents.go, ssm_compliance.go,
// route53.go).

var awsEC2SSMPatchNonCompliant = Check{
	ID:          "aws-ec2-ssm-patch-noncompliant",
	Title:       "EC2 instance is not patch-compliant in Systems Manager",
	Description: "Patch Manager reports the instance NON_COMPLIANT with its patch baseline: patches the baseline requires are missing or failed to install. Only instances Patch Manager covers are graded. Medium: the missing patches' own CVEs are reported as vulnerability findings where package inventory is available; this is the patch process itself falling behind.",
	Remediation: "Console: Systems Manager → Patch Manager → Compliance reporting → the instance → see missing patches, then run AWS-RunPatchBaseline with Operation=Install (or let the maintenance window do so). CLI: `aws ssm send-command --document-name AWS-RunPatchBaseline --targets Key=InstanceIds,Values=INSTANCE_ID --parameters Operation=Install`.",
	Type:        "hygiene",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ssm_patch_compliance"] == "NON_COMPLIANT" },
}

var awsEC2SSMAssociationNonCompliant = Check{
	ID:          "aws-ec2-ssm-association-noncompliant",
	Title:       "EC2 instance is not association-compliant in Systems Manager",
	Description: "A State Manager association targeting the instance last ran NON_COMPLIANT, so the configuration it enforces (agent updates, inventory, hardening documents) is not in place on this instance.",
	Remediation: "Console: Systems Manager → State Manager → the association → Execution history → the failed target, fix the cause and re-apply: `aws ssm start-associations-once --association-ids ASSOCIATION_ID`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ssm_association_compliance"] == "NON_COMPLIANT" },
}

var awsSSMDocumentPublic = Check{
	ID:          "aws-ssm-document-public",
	Title:       "Systems Manager document is shared publicly",
	Description: "The account-owned SSM document is shared with all AWS accounts, so anyone can read its content — scripts, parameters, and often hostnames, account IDs or embedded credentials — and run it in their own account.",
	Remediation: "`aws ssm modify-document-permission --name NAME --permission-type Share --account-ids-to-remove All`, then share with specific accounts if needed. Console: Systems Manager → Documents → Owned by me → the document → Permissions → Private. Block new public sharing with the regional setting (aws-ssm-document-public-sharing-not-blocked).",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "ssm_document",
	Violates:    func(a asset.Asset) bool { return a.Metadata["publicly_shared"] == "true" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"shared_account_count": a.Metadata["shared_account_count"]}
	},
}

var awsSSMDocumentPublicSharingNotBlocked = Check{
	ID:          "aws-ssm-document-public-sharing-not-blocked",
	Title:       "Systems Manager document public sharing is not blocked in this region",
	Description: "The region's block-public-sharing setting for SSM documents is off (public-sharing-permission Enable), so any owned document can be made public in one call. A document already public is reported by aws-ssm-document-public; this is the guardrail.",
	Remediation: "`aws ssm update-service-setting --setting-id /ssm/documents/console/public-sharing-permission --setting-value Disable --region REGION`. Console: Systems Manager → Documents → Preferences → Block public sharing.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ssm_document_public_sharing"] == "Enable" },
}

// ssmAutomationLogToCloudWatch is the only log destination SSM Automation offers.
const ssmAutomationLogToCloudWatch = "CloudWatch"

var awsSSMAutomationLoggingDisabled = Check{
	ID:          "aws-ssm-automation-logging-disabled",
	Title:       "Systems Manager Automation does not log to CloudWatch in this region",
	Description: "The region's Automation script-output destination is not CloudWatch Logs, so the output of scripts that runbooks execute (aws:executeScript) is not retained for review.",
	Remediation: "`aws ssm update-service-setting --setting-id /ssm/automation/customer-script-log-destination --setting-value CloudWatch --region REGION`. Console: Systems Manager → Automation → Preferences → Send output to CloudWatch Logs.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	// Read only when present: an unread setting is absent, while an empty value
	// is an observed "logs nowhere".
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["ssm_automation_log_destination"]
		return ok && v != ssmAutomationLogToCloudWatch
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"ssm_automation_log_destination": a.Metadata["ssm_automation_log_destination"]}
	},
}

var awsRoute53ZoneQueryLoggingDisabled = Check{
	ID:          "aws-route53-zone-query-logging-disabled",
	Title:       "Route 53 public hosted zone does not log DNS queries",
	Description: "The public hosted zone has no query logging configuration, so the DNS queries Route 53 answers for it (who looked up which name, from which resolver) are not recorded. Audit hygiene; private zones are not graded.",
	Remediation: "Create a CloudWatch Logs group in us-east-1 with a resource policy allowing route53.amazonaws.com, then `aws route53 create-query-logging-config --hosted-zone-id ZONE_ID --cloud-watch-logs-log-group-arn LOG_GROUP_ARN`. Console: Route 53 → Hosted zones → the zone → Configure query logging.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "dns_zone",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["private_zone"] == "false" && a.Metadata["query_logging"] == "false"
	},
}

func awsSSMChecks() []Check {
	return []Check{
		awsEC2SSMPatchNonCompliant,
		awsEC2SSMAssociationNonCompliant,
		awsSSMDocumentPublic,
		awsSSMDocumentPublicSharingNotBlocked,
		awsSSMAutomationLoggingDisabled,
		awsRoute53ZoneQueryLoggingDisabled,
	}
}
