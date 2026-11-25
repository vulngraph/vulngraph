package checks

// aws_threat_detection.go — GuardDuty (FSBP GuardDuty.1, 5-13) and Inspector
// (FSBP Inspector.1-4) per region, on aws_region_settings. See
// aws_detection.go for the severity posture and the step-aside rule: plan
// and scan-type keys exist only while the service itself is on.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// guardDutyPlanDescription is the shared description for one protection plan.
func guardDutyPlanDescription(plan, watches string) string {
	return "GuardDuty is enabled in this region but " + plan + " is off, so GuardDuty does not analyse " + watches +
		" for threats here. Info: each protection plan is billed separately and is only worth it where those workloads run."
}

// guardDutyPlanRemediation gives the console and CLI steps for one feature.
func guardDutyPlanRemediation(consolePath, feature string) string {
	return "Console: GuardDuty → " + consolePath + " → Enable (from the delegated administrator, for every member account). " +
		"CLI: `aws guardduty update-detector --detector-id DETECTOR_ID --features '" + feature + "' --region REGION`."
}

var awsGuardDutyDisabled = Check{
	ID:          "aws-guardduty-disabled",
	Title:       "GuardDuty is not enabled in this region",
	Description: "This region has no GuardDuty detector, or a suspended one, so CloudTrail, VPC flow and DNS activity here is not analysed for threats such as credential exfiltration, crypto-mining or reconnaissance (FSBP GuardDuty.1). An attacker who notices can operate in unwatched regions. Posture only: it exposes nothing by itself.",
	Remediation: "Console: GuardDuty → Get started → Enable GuardDuty (or enable it for every account and region from the delegated administrator). CLI: `aws guardduty create-detector --enable --region REGION`, or for a suspended detector `aws guardduty update-detector --detector-id DETECTOR_ID --enable --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["guardduty_enabled"] == "false" },
}

var awsGuardDutyS3ProtectionOff = Check{
	ID:          "aws-guardduty-s3-protection-off",
	Title:       "GuardDuty S3 Protection is off",
	Description: guardDutyPlanDescription("S3 Protection", "S3 object-level API activity"),
	Remediation: guardDutyPlanRemediation("Protection plans → S3 Protection", `[{"Name":"S3_DATA_EVENTS","Status":"ENABLED"}]`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["guardduty_s3_protection"] == "false" },
}

var awsGuardDutyEKSAuditLogsOff = Check{
	ID:          "aws-guardduty-eks-audit-logs-off",
	Title:       "GuardDuty EKS Audit Log Monitoring is off",
	Description: guardDutyPlanDescription("EKS Audit Log Monitoring", "Kubernetes audit logs of EKS clusters"),
	Remediation: guardDutyPlanRemediation("Protection plans → EKS Protection", `[{"Name":"EKS_AUDIT_LOGS","Status":"ENABLED"}]`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["guardduty_eks_audit_logs"] == "false" },
}

var awsGuardDutyLambdaProtectionOff = Check{
	ID:          "aws-guardduty-lambda-protection-off",
	Title:       "GuardDuty Lambda Protection is off",
	Description: guardDutyPlanDescription("Lambda Protection", "network activity of Lambda functions"),
	Remediation: guardDutyPlanRemediation("Protection plans → Lambda Protection", `[{"Name":"LAMBDA_NETWORK_LOGS","Status":"ENABLED"}]`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["guardduty_lambda_protection"] == "false" },
}

var awsGuardDutyMalwareProtectionOff = Check{
	ID:          "aws-guardduty-malware-protection-off",
	Title:       "GuardDuty Malware Protection for EC2 is off",
	Description: guardDutyPlanDescription("Malware Protection for EC2", "the EBS volumes of instances it suspects"),
	Remediation: guardDutyPlanRemediation("Protection plans → Malware Protection for EC2", `[{"Name":"EBS_MALWARE_PROTECTION","Status":"ENABLED"}]`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["guardduty_malware_protection"] == "false" },
}

var awsGuardDutyRDSProtectionOff = Check{
	ID:          "aws-guardduty-rds-protection-off",
	Title:       "GuardDuty RDS Protection is off",
	Description: guardDutyPlanDescription("RDS Protection", "Aurora login activity"),
	Remediation: guardDutyPlanRemediation("Protection plans → RDS Protection", `[{"Name":"RDS_LOGIN_EVENTS","Status":"ENABLED"}]`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["guardduty_rds_protection"] == "false" },
}

var awsGuardDutyRuntimeMonitoringOff = Check{
	ID:          "aws-guardduty-runtime-monitoring-off",
	Title:       "GuardDuty Runtime Monitoring is off",
	Description: guardDutyPlanDescription("Runtime Monitoring", "process, file and network events on EKS, ECS and EC2 workloads"),
	Remediation: guardDutyPlanRemediation("Runtime Monitoring → Configuration", `[{"Name":"RUNTIME_MONITORING","Status":"ENABLED"}]`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["guardduty_runtime_monitoring"] == "false" },
}

var awsGuardDutyEKSRuntimeOff = Check{
	ID:          "aws-guardduty-eks-runtime-off",
	Title:       "GuardDuty EKS Runtime Monitoring agent is not managed",
	Description: guardDutyPlanDescription("automated agent management for EKS", "runtime events in EKS clusters that run no agent"),
	Remediation: guardDutyPlanRemediation("Runtime Monitoring → Configuration → Amazon EKS → Automated agent configuration",
		`[{"Name":"RUNTIME_MONITORING","Status":"ENABLED","AdditionalConfiguration":[{"Name":"EKS_ADDON_MANAGEMENT","Status":"ENABLED"}]}]`),
	Type:      "hygiene",
	Severity:  finding.SeverityInfo,
	Provider:  asset.ProviderAWS,
	AssetType: "aws_region_settings",
	Violates:  func(a asset.Asset) bool { return a.Metadata["guardduty_eks_runtime"] == "false" },
}

var awsGuardDutyECSRuntimeOff = Check{
	ID:          "aws-guardduty-ecs-runtime-off",
	Title:       "GuardDuty ECS Fargate Runtime Monitoring agent is not managed",
	Description: guardDutyPlanDescription("automated agent management for ECS on Fargate", "runtime events in Fargate tasks"),
	Remediation: guardDutyPlanRemediation("Runtime Monitoring → Configuration → AWS Fargate (ECS only) → Automated agent configuration",
		`[{"Name":"RUNTIME_MONITORING","Status":"ENABLED","AdditionalConfiguration":[{"Name":"ECS_FARGATE_AGENT_MANAGEMENT","Status":"ENABLED"}]}]`),
	Type:      "hygiene",
	Severity:  finding.SeverityInfo,
	Provider:  asset.ProviderAWS,
	AssetType: "aws_region_settings",
	Violates:  func(a asset.Asset) bool { return a.Metadata["guardduty_ecs_runtime"] == "false" },
}

var awsGuardDutyEC2RuntimeOff = Check{
	ID:          "aws-guardduty-ec2-runtime-off",
	Title:       "GuardDuty EC2 Runtime Monitoring agent is not managed",
	Description: guardDutyPlanDescription("automated agent management for EC2", "runtime events on EC2 instances that run no agent"),
	Remediation: guardDutyPlanRemediation("Runtime Monitoring → Configuration → Amazon EC2 → Automated agent configuration",
		`[{"Name":"RUNTIME_MONITORING","Status":"ENABLED","AdditionalConfiguration":[{"Name":"EC2_AGENT_MANAGEMENT","Status":"ENABLED"}]}]`),
	Type:      "hygiene",
	Severity:  finding.SeverityInfo,
	Provider:  asset.ProviderAWS,
	AssetType: "aws_region_settings",
	Violates:  func(a asset.Asset) bool { return a.Metadata["guardduty_ec2_runtime"] == "false" },
}

// inspectorScanOff is a scan-type status that is not scanning: off, or
// being switched off or suspended.
func inspectorScanOff(status string) bool {
	switch status {
	case "DISABLED", "DISABLING", "SUSPENDED", "SUSPENDING":
		return true
	}
	return false
}

// inspectorScanDescription is the shared description for one scan type.
func inspectorScanDescription(what string) string {
	return "Amazon Inspector is on in this region but does not scan " + what +
		", so their known vulnerabilities are not reported by AWS here. Info: Inspector is billed per resource, and graph reports image and package CVEs itself."
}

var awsInspectorDisabled = Check{
	ID:          "aws-inspector-disabled",
	Title:       "Amazon Inspector is not enabled in this region",
	Description: "Amazon Inspector is not scanning anything in this region (FSBP Inspector.1-4): no EC2, ECR or Lambda vulnerability scanning by AWS. Info: Inspector is a paid scanner, and graph reports image and package CVEs itself.",
	Remediation: "Console: Amazon Inspector → Get started → Activate Inspector (or activate it for the organization from the delegated administrator). CLI: `aws inspector2 enable --resource-types EC2 ECR LAMBDA LAMBDA_CODE --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return inspectorScanOff(a.Metadata["inspector_status"]) },
}

var awsInspectorEC2ScanOff = Check{
	ID:          "aws-inspector-ec2-scan-off",
	Title:       "Amazon Inspector EC2 scanning is off",
	Description: inspectorScanDescription("EC2 instances"),
	Remediation: "Console: Amazon Inspector → Account management → select the account → Activate → Amazon EC2 scanning. CLI: `aws inspector2 enable --resource-types EC2 --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return inspectorScanOff(a.Metadata["inspector_ec2"]) },
}

var awsInspectorECRScanOff = Check{
	ID:          "aws-inspector-ecr-scan-off",
	Title:       "Amazon Inspector ECR scanning is off",
	Description: inspectorScanDescription("ECR container images"),
	Remediation: "Console: Amazon Inspector → Account management → select the account → Activate → Amazon ECR scanning. CLI: `aws inspector2 enable --resource-types ECR --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return inspectorScanOff(a.Metadata["inspector_ecr"]) },
}

var awsInspectorLambdaScanOff = Check{
	ID:          "aws-inspector-lambda-scan-off",
	Title:       "Amazon Inspector Lambda standard scanning is off",
	Description: inspectorScanDescription("Lambda function dependencies"),
	Remediation: "Console: Amazon Inspector → Account management → select the account → Activate → AWS Lambda standard scanning. CLI: `aws inspector2 enable --resource-types LAMBDA --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return inspectorScanOff(a.Metadata["inspector_lambda"]) },
}

var awsInspectorLambdaCodeScanOff = Check{
	ID:          "aws-inspector-lambda-code-scan-off",
	Title:       "Amazon Inspector Lambda code scanning is off",
	Description: inspectorScanDescription("Lambda function code"),
	Remediation: "Console: Amazon Inspector → Account management → select the account → Activate → AWS Lambda code scanning. CLI: `aws inspector2 enable --resource-types LAMBDA_CODE --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return inspectorScanOff(a.Metadata["inspector_lambda_code"]) },
}
