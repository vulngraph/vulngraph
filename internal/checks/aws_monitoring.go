package checks

// aws_monitoring.go — CIS AWS Foundations 5.1–5.15: a CloudWatch alarm, with
// a subscribed SNS topic, on a metric filter for each listed event pattern.
//
// The collector walks the chain once for all fifteen patterns
// (internal/collect/aws/cloudwatch_alarms.go) and writes one cw_alarm_<x>
// key per pattern to aws_account_settings: "false" only when every read
// succeeded and no complete chain exists. Each check is one account-wide
// finding. With no trail whose log group could hold the filters
// (cw_alarm_monitoring_trail=false) the fifteen step aside for the one
// aws-cloudwatch-no-cis-monitoring-trail finding, which itself steps aside
// for aws-cloudtrail-no-multiregion-trail when the trail is the gap.
//
// Info: alerting on these events is detective hygiene that many teams
// deliberately do in a SIEM or EventBridge instead; it is never the page band.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsMonitoringChecks() []Check {
	return []Check{
		awsCWNoCISMonitoringTrail,
		awsCWAlarmUnauthorizedAPICalls,
		awsCWAlarmConsoleLoginNoMFA,
		awsCWAlarmRootUsage,
		awsCWAlarmIAMPolicyChanges,
		awsCWAlarmCloudTrailChanges,
		awsCWAlarmConsoleAuthFailures,
		awsCWAlarmKMSKeyDisableOrDeletion,
		awsCWAlarmS3BucketPolicyChanges,
		awsCWAlarmConfigChanges,
		awsCWAlarmSecurityGroupChanges,
		awsCWAlarmNACLChanges,
		awsCWAlarmNetworkGatewayChanges,
		awsCWAlarmRouteTableChanges,
		awsCWAlarmVPCChanges,
		awsCWAlarmOrganizationsChanges,
	}
}

// cisAlarmDescription is the shared description for one monitoring pattern.
func cisAlarmDescription(events string) string {
	return "No metric filter on the CloudWatch Logs group of a multi-region trail (one that records all management events) matches " +
		events + " with a CloudWatch alarm on its metric that notifies an SNS topic with a confirmed subscriber, so nobody is told when it happens. " +
		"The events are still recorded in CloudTrail; this is an alerting gap. Info: many teams alert from a SIEM or EventBridge rule instead — " +
		"if yours does, this finding documents that choice."
}

// cisAlarmRemediation gives the console and CLI steps for one pattern.
func cisAlarmRemediation(name, pattern string) string {
	return "Console: CloudWatch → Log groups → the multi-region trail's log group → Metric filters → Create metric filter with the pattern below, then " +
		"Create alarm on the metric (threshold >= 1) with an SNS topic that has a confirmed subscriber. CLI: " +
		"`aws logs put-metric-filter --log-group-name TRAIL_LOG_GROUP --filter-name " + name + " --metric-transformations " +
		"metricName=" + name + ",metricNamespace=CISBenchmark,metricValue=1 --filter-pattern '" + pattern + "'` then " +
		"`aws cloudwatch put-metric-alarm --alarm-name " + name + " --metric-name " + name + " --namespace CISBenchmark --statistic Sum " +
		"--period 300 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions SNS_TOPIC_ARN` " +
		"and `aws sns subscribe --topic-arn SNS_TOPIC_ARN --protocol email --notification-endpoint SECURITY_EMAIL`."
}

// cisAlarmEvidence names the log groups the chain was evaluated against.
func cisAlarmEvidence(a asset.Asset) map[string]string {
	if g := a.Metadata["cw_alarm_log_groups"]; g != "" {
		return map[string]string{"trail_log_groups": g}
	}
	return map[string]string{"trail_log_groups": "none: no multi-region trail recording all management events delivers to CloudWatch Logs"}
}

var awsCWNoCISMonitoringTrail = Check{
	ID:          "aws-cloudwatch-no-cis-monitoring-trail",
	Title:       "No multi-region trail delivers to CloudWatch Logs for alerting",
	Description: "No multi-region trail that is logging and records all management events delivers to a CloudWatch Logs group in this account, so none of the CIS AWS 5.1–5.15 metric-filter alarms (root usage, IAM policy, CloudTrail, network and Organizations changes, …) can exist. This one finding stands for all fifteen; once a trail delivers to CloudWatch Logs each missing alarm is reported on its own. A missing or stopped multi-region trail is reported by aws-cloudtrail-no-multiregion-trail instead. Info: alerting is often done from a SIEM or EventBridge instead.",
	Remediation: "Console: CloudTrail → Trails → the multi-region trail → CloudWatch Logs → Edit → Enabled, with a new or existing log group and an IAM role CloudTrail can write with. CLI: `aws cloudtrail update-trail --name TRAIL --cloud-watch-logs-log-group-arn LOG_GROUP_ARN --cloud-watch-logs-role-arn ROLE_ARN`. Then add the CIS metric filters and alarms to that log group.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_monitoring_trail"] == "false" &&
			a.Metadata["cloudtrail_multi_region_logging"] != "false" &&
			a.Metadata["cloudtrail_multi_region_mgmt_all"] != "false"
	},
}

var awsCWAlarmUnauthorizedAPICalls = Check{
	ID:          "aws-cloudwatch-alarm-unauthorized-api-calls",
	Title:       "No CloudWatch alarm on unauthorized API calls",
	Description: cisAlarmDescription("unauthorized API calls (AccessDenied and UnauthorizedOperation errors)"),
	Remediation: cisAlarmRemediation("UnauthorizedAPICalls", `{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_unauthorized_api_calls"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmConsoleLoginNoMFA = Check{
	ID:          "aws-cloudwatch-alarm-console-login-no-mfa",
	Title:       "No CloudWatch alarm on console sign-in without MFA",
	Description: cisAlarmDescription("console sign-ins without MFA"),
	Remediation: cisAlarmRemediation("ConsoleSigninWithoutMFA", `{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_console_login_no_mfa"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmRootUsage = Check{
	ID:          "aws-cloudwatch-alarm-root-usage",
	Title:       "No CloudWatch alarm on root account usage",
	Description: cisAlarmDescription("use of the root user"),
	Remediation: cisAlarmRemediation("RootAccountUsage", `{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_root_usage"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmIAMPolicyChanges = Check{
	ID:          "aws-cloudwatch-alarm-iam-policy-changes",
	Title:       "No CloudWatch alarm on IAM policy changes",
	Description: cisAlarmDescription("IAM policy creation, deletion, versioning, attachment and inline-policy changes"),
	Remediation: cisAlarmRemediation("IAMPolicyChanges", `{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_iam_policy_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmCloudTrailChanges = Check{
	ID:          "aws-cloudwatch-alarm-cloudtrail-changes",
	Title:       "No CloudWatch alarm on CloudTrail configuration changes",
	Description: cisAlarmDescription("trail creation, update, deletion and logging start/stop"),
	Remediation: cisAlarmRemediation("CloudTrailChanges", `{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_cloudtrail_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmConsoleAuthFailures = Check{
	ID:          "aws-cloudwatch-alarm-console-auth-failures",
	Title:       "No CloudWatch alarm on console authentication failures",
	Description: cisAlarmDescription("failed console sign-ins"),
	Remediation: cisAlarmRemediation("ConsoleAuthenticationFailures", `{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_console_auth_failures"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmKMSKeyDisableOrDeletion = Check{
	ID:          "aws-cloudwatch-alarm-kms-disable-or-delete",
	Title:       "No CloudWatch alarm on disabling or deleting KMS keys",
	Description: cisAlarmDescription("customer-managed KMS keys being disabled or scheduled for deletion"),
	Remediation: cisAlarmRemediation("DisableOrDeleteCMK", `{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_kms_key_disable_or_deletion"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmS3BucketPolicyChanges = Check{
	ID:          "aws-cloudwatch-alarm-s3-bucket-policy-changes",
	Title:       "No CloudWatch alarm on S3 bucket policy changes",
	Description: cisAlarmDescription("S3 bucket ACL, policy, CORS, lifecycle and replication changes"),
	Remediation: cisAlarmRemediation("S3BucketPolicyChanges", `{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_s3_bucket_policy_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmConfigChanges = Check{
	ID:          "aws-cloudwatch-alarm-config-changes",
	Title:       "No CloudWatch alarm on AWS Config changes",
	Description: cisAlarmDescription("AWS Config recorder and delivery-channel changes"),
	Remediation: cisAlarmRemediation("AWSConfigChanges", `{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_config_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmSecurityGroupChanges = Check{
	ID:          "aws-cloudwatch-alarm-security-group-changes",
	Title:       "No CloudWatch alarm on security group changes",
	Description: cisAlarmDescription("security group creation, deletion and rule changes"),
	Remediation: cisAlarmRemediation("SecurityGroupChanges", `{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_security_group_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmNACLChanges = Check{
	ID:          "aws-cloudwatch-alarm-nacl-changes",
	Title:       "No CloudWatch alarm on network ACL changes",
	Description: cisAlarmDescription("network ACL and ACL entry creation, deletion, replacement and re-association"),
	Remediation: cisAlarmRemediation("NACLChanges", `{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_nacl_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmNetworkGatewayChanges = Check{
	ID:          "aws-cloudwatch-alarm-network-gateway-changes",
	Title:       "No CloudWatch alarm on network gateway changes",
	Description: cisAlarmDescription("internet and customer gateway creation, deletion, attachment and detachment"),
	Remediation: cisAlarmRemediation("NetworkGatewayChanges", `{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_network_gateway_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmRouteTableChanges = Check{
	ID:          "aws-cloudwatch-alarm-route-table-changes",
	Title:       "No CloudWatch alarm on route table changes",
	Description: cisAlarmDescription("route and route table creation, replacement, deletion and association changes"),
	Remediation: cisAlarmRemediation("RouteTableChanges", `{ ($.eventSource = ec2.amazonaws.com) && (($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_route_table_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmVPCChanges = Check{
	ID:          "aws-cloudwatch-alarm-vpc-changes",
	Title:       "No CloudWatch alarm on VPC changes",
	Description: cisAlarmDescription("VPC creation, deletion, attribute changes, peering and ClassicLink changes"),
	Remediation: cisAlarmRemediation("VPCChanges", `{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_vpc_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}

var awsCWAlarmOrganizationsChanges = Check{
	ID:          "aws-cloudwatch-alarm-organizations-changes",
	Title:       "No CloudWatch alarm on AWS Organizations changes",
	Description: cisAlarmDescription("AWS Organizations account, OU, policy and handshake changes"),
	Remediation: cisAlarmRemediation("OrganizationsChanges", `{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }`),
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cw_alarm_organizations_changes"] == "false" && a.Metadata["cw_alarm_monitoring_trail"] != "false"
	},
	EvidenceFor: cisAlarmEvidence,
}
