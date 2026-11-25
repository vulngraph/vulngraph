package checks

// aws_detection.go — regional detection services on aws_region_settings: AWS
// Config (CIS AWS 4.3, FSBP Config.1), Security Hub (CIS 5.16), IAM Access
// Analyzer (CIS 2.18), Macie (CIS 3.1.3, FSBP Macie.1/2), GuardDuty (FSBP
// GuardDuty.1, 5-13) and Inspector (FSBP Inspector.1-4).
//
// One finding per region per service setting, never per resource. Severity
// is posture: a detection service being off removes a safety net but exposes
// nothing, so these are Low (Config, Security Hub, Access Analyzer,
// GuardDuty) or Info (paid add-on plans and scanners teams often decline on
// purpose). A plan or scan type is recorded only while its service is on
// (internal/collect/aws/region_detection.go), so a disabled service is one
// finding, not one per plan.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsDetectionChecks() []Check {
	return []Check{
		awsConfigRecorderOff,
		awsConfigNotServiceLinkedRole,
		awsSecurityHubDisabled,
		awsAccessAnalyzerDisabled,
		awsMacieDisabled,
		awsMacieAutomatedDiscoveryOff,
		awsGuardDutyDisabled,
		awsGuardDutyS3ProtectionOff,
		awsGuardDutyEKSAuditLogsOff,
		awsGuardDutyLambdaProtectionOff,
		awsGuardDutyMalwareProtectionOff,
		awsGuardDutyRDSProtectionOff,
		awsGuardDutyRuntimeMonitoringOff,
		awsGuardDutyEKSRuntimeOff,
		awsGuardDutyECSRuntimeOff,
		awsGuardDutyEC2RuntimeOff,
		awsInspectorDisabled,
		awsInspectorEC2ScanOff,
		awsInspectorECRScanOff,
		awsInspectorLambdaScanOff,
		awsInspectorLambdaCodeScanOff,
	}
}

// configRecorderGaps lists why the region's AWS Config recorder does not
// record everything. Nil when it does or nothing was read.
func configRecorderGaps(a asset.Asset) []string {
	if a.Metadata["config_recorder"] == "absent" {
		return []string{"no configuration recorder"}
	}
	var out []string
	if a.Metadata["config_recording"] == "false" {
		out = append(out, "recorder stopped")
	}
	if a.Metadata["config_all_supported"] == "false" {
		out = append(out, "records only some resource types")
	}
	if a.Metadata["config_delivery_channel"] == "false" {
		out = append(out, "no delivery channel")
	}
	if a.Metadata["config_last_status"] == "Failure" {
		out = append(out, "last recording attempt failed")
	}
	return out
}

var awsConfigRecorderOff = Check{
	ID:    "aws-config-recorder-off",
	Title: "AWS Config is not recording every resource in this region",
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["config_recorder"] == "absent" {
			return "AWS Config is not enabled in this region"
		}
		return "AWS Config is not recording every resource in this region"
	},
	Description: "AWS Config in this region has no recorder, a stopped one, one that records only some resource types, no delivery channel, or one whose last recording failed. Without it there is no configuration history to answer what a resource looked like before an incident or who changed it, and AWS Config rules and Security Hub controls that depend on it cannot evaluate. A recorder another service created for itself (Security Hub's service-linked one) does not count: it gives the account no history. Global resource types (IAM) are not required here, since AWS recommends recording them in one region only.",
	Remediation: "Console: AWS Config → Settings → Edit → Record all current and future resource types, with a delivery channel to an S3 bucket. CLI: `aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig --recording-group allSupported=true --region REGION`, `aws configservice put-delivery-channel --delivery-channel name=default,s3BucketName=BUCKET --region REGION`, then `aws configservice start-configuration-recorder --configuration-recorder-name default --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return len(configRecorderGaps(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"gaps": strings.Join(configRecorderGaps(a), "; ")}
	},
}

var awsConfigNotServiceLinkedRole = Check{
	ID:          "aws-config-not-service-linked-role",
	Title:       "AWS Config recorder does not use the service-linked role",
	Description: "The region's configuration recorder records with a custom IAM role instead of AWSServiceRoleForConfig. A custom role can lack permissions AWS adds to the service-linked role for new resource types, so those resources silently go unrecorded (FSBP Config.1). Info: Control Tower and many landing zones use their own role deliberately.",
	Remediation: "Console: AWS Config → Settings → Edit → AWS Config role → Use an existing AWS Config service-linked role. CLI: `aws iam create-service-linked-role --aws-service-name config.amazonaws.com` (once per account), then `aws configservice put-configuration-recorder --configuration-recorder name=RECORDER,roleARN=arn:aws:iam::ACCOUNT:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig --region REGION` keeping its recording group.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["config_recorder"] == "present" && a.Metadata["config_service_linked_role"] == "false"
	},
}

var awsSecurityHubDisabled = Check{
	ID:          "aws-securityhub-disabled",
	Title:       "Security Hub is not enabled in this region",
	Description: "AWS Security Hub is off in this region, so its security standards are not evaluated there and findings from GuardDuty, Inspector, Macie and partner tools are not aggregated for the region (CIS AWS 5.16). Posture only: graph evaluates these benchmarks itself, but the account's own AWS-native view has a gap.",
	Remediation: "Console: Security Hub → Go to Security Hub → Enable Security Hub (or enable it for every account and region from the delegated administrator with central configuration). CLI: `aws securityhub enable-security-hub --enable-default-standards --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["securityhub_enabled"] == "false" },
}

var awsAccessAnalyzerDisabled = Check{
	ID:          "aws-access-analyzer-disabled",
	Title:       "IAM Access Analyzer has no active analyzer in this region",
	Description: "No active external-access analyzer (account or organization zone of trust) exists in this region, so resource policies that grant access to other accounts or to the public are not continuously analysed by AWS here (CIS AWS 2.18). An organization analyzer in a delegated administrator account does not appear in member accounts; the benchmark asks for one per account and region.",
	Remediation: "Console: IAM → Access analyzer → Create analyzer (zone of trust: current account, or the organization from the delegated administrator). CLI: `aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["access_analyzer_active"] == "false" },
}

var awsMacieDisabled = Check{
	ID:          "aws-macie-disabled",
	Title:       "Amazon Macie is not enabled in this region",
	Description: "Amazon Macie is not enabled (or is paused) in this region, so S3 buckets here are not inventoried for sensitive data (FSBP Macie.1, CIS AWS 3.1.3). Info: Macie is a paid service many teams cover with another data-classification tool.",
	Remediation: "Console: Amazon Macie → Get started → Enable Macie (a paused session: Settings → Re-enable Macie). CLI: `aws macie2 enable-macie --region REGION` (or `aws macie2 update-macie-session --status ENABLED` for a paused one).",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates: func(a asset.Asset) bool {
		switch a.Metadata["macie_status"] {
		case "NOT_ENABLED", "PAUSED":
			return true
		}
		return false
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"macie_status": a.Metadata["macie_status"]}
	},
}

var awsMacieAutomatedDiscoveryOff = Check{
	ID:          "aws-macie-automated-discovery-off",
	Title:       "Macie automated sensitive data discovery is off",
	Description: "Macie is enabled in this region but automated sensitive data discovery is not, so buckets are sampled for sensitive data only by classification jobs someone schedules (FSBP Macie.2).",
	Remediation: "Console: Amazon Macie → Automated sensitive data discovery → Enable. CLI: `aws macie2 update-automated-discovery-configuration --status ENABLED --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["macie_automated_discovery"] == "DISABLED" },
}
