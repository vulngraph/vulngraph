package checks

// aws_logging.go — AWS logging controls beyond the trail itself: S3
// object-level data events (CIS AWS 4.8/4.9), VPC flow logs (CIS 4.7, FSBP
// EC2.6), and access logs on the web front ends (CIS 4.10, FSBP ELB.5,
// APIGateway.9) and Network Firewall (NetworkFirewall.2). They grade the keys
// the network collectors write (elb_detail.go, apigateway_stages.go,
// networkfirewall.go); stage execution logging (APIGateway.1) is
// aws-apigateway-stage-execution-logging-disabled's finding.
//
// Missing logs never expose anything; they decide whether an incident can be
// reconstructed. All of these are Low or Info posture.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsLoggingChecks() []Check {
	return []Check{
		awsCloudTrailNoS3WriteEvents,
		awsCloudTrailNoS3ReadEvents,
		awsVPCFlowLogsDisabled,
		awsALBAccessLogsDisabled,
		awsAPIGatewayAccessLoggingOff,
		awsNetworkFirewallLoggingOff,
	}
}

var awsCloudTrailNoS3WriteEvents = Check{
	ID:          "aws-cloudtrail-no-s3-write-events",
	Title:       "No CloudTrail trail logs S3 object-level writes",
	Description: "No logging multi-region trail records S3 data events for writes (PutObject, DeleteObject, …) on every bucket, so who changed or deleted an object cannot be reconstructed — the record ransomware investigations need (CIS AWS 4.8). Management events alone show bucket configuration changes, not object activity. With no multi-region trail logging at all, aws-cloudtrail-no-multiregion-trail is the one finding. Low: data events cost money, and buckets with nothing sensitive rarely warrant them.",
	Remediation: "Console: CloudTrail → Trails → the multi-region trail → Data events → Edit → add S3, all current and future buckets, Write events. CLI: `aws cloudtrail put-event-selectors --trail-name TRAIL --advanced-event-selectors '[{\"Name\":\"S3 writes\",\"FieldSelectors\":[{\"Field\":\"eventCategory\",\"Equals\":[\"Data\"]},{\"Field\":\"resources.type\",\"Equals\":[\"AWS::S3::Object\"]},{\"Field\":\"readOnly\",\"Equals\":[\"false\"]}]},{\"Name\":\"Management\",\"FieldSelectors\":[{\"Field\":\"eventCategory\",\"Equals\":[\"Management\"]}]}]'` (keep the trail's other selectors in the list). Data events are billed per event; exclude the trail's own log bucket.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cloudtrail_s3_write_events"] == "false" && a.Metadata["cloudtrail_multi_region_logging"] != "false"
	},
}

var awsCloudTrailNoS3ReadEvents = Check{
	ID:          "aws-cloudtrail-no-s3-read-events",
	Title:       "No CloudTrail trail logs S3 object-level reads",
	Description: "No logging multi-region trail records S3 data events for reads (GetObject, …) on every bucket, so data exfiltration from a bucket leaves no record of which objects were read or by whom (CIS AWS 4.9). With no multi-region trail logging at all, aws-cloudtrail-no-multiregion-trail is the one finding. Info: read events are high-volume and billed per event; most teams enable them only for buckets holding sensitive data.",
	Remediation: "Console: CloudTrail → Trails → the multi-region trail → Data events → Edit → add S3, all current and future buckets, Read events. CLI: `aws cloudtrail put-event-selectors --trail-name TRAIL --advanced-event-selectors '[{\"Name\":\"S3 reads\",\"FieldSelectors\":[{\"Field\":\"eventCategory\",\"Equals\":[\"Data\"]},{\"Field\":\"resources.type\",\"Equals\":[\"AWS::S3::Object\"]},{\"Field\":\"readOnly\",\"Equals\":[\"true\"]}]},{\"Name\":\"Management\",\"FieldSelectors\":[{\"Field\":\"eventCategory\",\"Equals\":[\"Management\"]}]}]'` (keep the trail's other selectors in the list). Exclude the trail's own log bucket.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cloudtrail_s3_read_events"] == "false" && a.Metadata["cloudtrail_multi_region_logging"] != "false"
	},
}

var awsVPCFlowLogsDisabled = Check{
	ID:          "aws-vpc-flow-logs-disabled",
	Title:       "VPC has no flow log",
	Description: "The VPC has no active VPC-level flow log capturing rejected (or all) traffic, so connection attempts into and out of it — scanning, lateral movement, exfiltration — leave no network record (CIS AWS 4.7, FSBP EC2.6). Subnet- or interface-level flow logs leave the rest of the VPC unlogged. A default VPC with no network interfaces is skipped: nothing runs in it to log.",
	Remediation: "Console: VPC → Your VPCs → the VPC → Flow logs → Create flow log (filter Reject or All, destination CloudWatch Logs or S3). CLI: `aws ec2 create-flow-logs --resource-type VPC --resource-ids VPC_ID --traffic-type REJECT --log-destination-type s3 --log-destination arn:aws:s3:::BUCKET`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "vpc",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["flow_logs_enabled"] != "false" {
			return false
		}
		return a.Metadata["is_default"] != "true" || a.Metadata["in_use"] != "false"
	},
}

var awsALBAccessLogsDisabled = Check{
	ID:          "aws-alb-access-logs-disabled",
	Title:       "Load balancer access logging is off",
	Description: "The Application or Classic Load Balancer does not write access logs, so the requests it served — client IPs, paths, response codes — cannot be reviewed after an incident on whatever it fronts (CIS AWS 4.10, FSBP ELB.5).",
	Remediation: "Console: EC2 → Load balancers → the balancer → Attributes → Edit → Monitoring → Access logs on, with an S3 bucket whose policy allows the regional ELB account to write. CLI (ALB): `aws elbv2 modify-load-balancer-attributes --load-balancer-arn LB_ARN --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=BUCKET`; (Classic): `aws elb modify-load-balancer-attributes --load-balancer-name NAME --load-balancer-attributes '{\"AccessLog\":{\"Enabled\":true,\"S3BucketName\":\"BUCKET\",\"EmitInterval\":60}}'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "load_balancer",
	// access_logs_s3_enabled is written for ALBs (elb_detail.go) and Classic
	// balancers (elb_classic.go) only, and is absent when the read failed.
	Violates: func(a asset.Asset) bool { return a.Metadata["access_logs_s3_enabled"] == "false" },
}

var awsAPIGatewayAccessLoggingOff = Check{
	ID:          "aws-apigateway-access-logging-off",
	Title:       "API Gateway stage has no access logging",
	Description: "The deployed API stage has no access-log destination, so who called the API — caller IP, identity, route, status — is not recorded (CIS AWS 4.10 for every stage, FSBP APIGateway.9 for HTTP and WebSocket stages).",
	Remediation: "Console: API Gateway → the API → Stages → the stage → Logs and tracing (REST) or Logging (HTTP/WebSocket) → Edit → Custom access logging on, with a CloudWatch Logs group ARN and a log format. CLI (REST): `aws apigateway update-stage --rest-api-id API_ID --stage-name STAGE --patch-operations op=replace,path=/accessLogSettings/destinationArn,value=LOG_GROUP_ARN op=replace,path=/accessLogSettings/format,value='$context.requestId $context.identity.sourceIp $context.routeKey $context.status'`; (HTTP/WebSocket): `aws apigatewayv2 update-stage --api-id API_ID --stage-name STAGE --access-log-settings DestinationArn=LOG_GROUP_ARN,Format='$context.requestId $context.identity.sourceIp $context.routeKey $context.status'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "api_gateway_stage",
	// access_log_destination is "" when access logging is off and absent when
	// the stage was not read (apigateway_stages.go).
	Violates: func(a asset.Asset) bool { return observedNone(a, "access_log_destination") },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"stage_name": a.Metadata["stage_name"], "api_type": a.Metadata["api_type"]}
	},
}

var awsNetworkFirewallLoggingOff = Check{
	ID:          "aws-network-firewall-logging-off",
	Title:       "Network Firewall logging is off",
	Description: "The firewall delivers no log type (flow, alert or TLS) anywhere, so traffic it dropped or alerted on cannot be reviewed (FSBP NetworkFirewall.2).",
	Remediation: "Console: VPC → Network Firewall → Firewalls → the firewall → Firewall details → Logging → Edit → Alert and Flow logs to CloudWatch Logs, S3 or Firehose. CLI: `aws network-firewall update-logging-configuration --firewall-arn FIREWALL_ARN --logging-configuration '{\"LogDestinationConfigs\":[{\"LogType\":\"ALERT\",\"LogDestinationType\":\"CloudWatchLogs\",\"LogDestination\":{\"logGroup\":\"LOG_GROUP\"}}]}'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "network_firewall",
	// The three keys are written together from one DescribeLoggingConfiguration
	// read (networkfirewall.go); any absent key means the read failed.
	Violates: func(a asset.Asset) bool {
		return a.Metadata["logging_flow"] == "false" && a.Metadata["logging_alert"] == "false" && a.Metadata["logging_tls"] == "false"
	},
}
