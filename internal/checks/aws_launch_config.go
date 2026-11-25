package checks

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Launch-path posture: the templates, launch configurations, Spot Fleet
// requests and Auto Scaling groups that decide how future instances start,
// plus per-instance ENI settings. Benchmarks: AWS FSBP EC2.25/170/173/180/181,
// AutoScaling.1/2/3/5/6/9.
//
// A template is not a running instance: the live instances it launched are
// graded by the instance checks (aws-ec2-imdsv2-not-required,
// aws-ec2-public-ip). So template findings are Low, raised to Medium when an
// Auto Scaling group launches from the template and keeps producing
// instances with the setting.

// launchSeverity grades a template-level finding by whether an Auto Scaling
// group uses the template. An unread usage count stays at Low.
func launchSeverity(a asset.Asset) finding.Severity {
	if countAbove(a, "auto_scaling_group_count") {
		return finding.SeverityMedium
	}
	return finding.SeverityLow
}

var awsEC2LaunchTemplatePublicIP = Check{
	ID:          "aws-ec2-launch-template-public-ip",
	Title:       "Launch template assigns public IP addresses",
	Description: "The template's default version sets AssociatePublicIpAddress on a network interface, so every instance launched from it gets an internet-routable address and is reachable from the internet wherever its security groups allow. Medium when an Auto Scaling group launches from the template, Low otherwise.",
	Remediation: "Create a template version without a public IP and make it the default; reach instances through a load balancer, NAT gateway or SSM Session Manager. Console: EC2 > Launch templates > Modify template > Network settings > Auto-assign public IP: Disable. CLI: `aws ec2 create-launch-template-version --launch-template-id LT_ID --source-version 1 --launch-template-data '{\"NetworkInterfaces\":[{\"DeviceIndex\":0,\"AssociatePublicIpAddress\":false}]}'` then `aws ec2 modify-launch-template --launch-template-id LT_ID --default-version N`.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "launch_template",
	Violates:    func(a asset.Asset) bool { return countAbove(a, "public_ip_interfaces") },
	SeverityFor: launchSeverity,
}

var awsEC2LaunchTemplateIMDSv1 = Check{
	ID:          "aws-ec2-launch-template-imdsv1",
	Title:       "Launch template allows IMDSv1",
	Description: "The template's default version sets HttpTokens=optional, so instances launched from it answer IMDSv1 requests: a server-side request forgery in any workload on them can read the instance role's credentials. A template that leaves the setting unset takes the account or AMI default and is not reported (AWS FSBP EC2.170 fails only an explicit optional); a disabled metadata endpoint is exempt. Medium when an Auto Scaling group launches from the template, Low otherwise.",
	Remediation: "Create a template version requiring IMDSv2 and make it the default. Console: EC2 > Launch templates > Modify template > Advanced details > Metadata version: V2 only. CLI: `aws ec2 create-launch-template-version --launch-template-id LT_ID --source-version N --launch-template-data '{\"MetadataOptions\":{\"HttpTokens\":\"required\"}}'` then `aws ec2 modify-launch-template --launch-template-id LT_ID --default-version M`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "launch_template",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["http_tokens"] == "optional" && a.Metadata["http_endpoint"] != "disabled"
	},
	SeverityFor: launchSeverity,
}

var awsEC2LaunchTemplateUnencryptedEBS = Check{
	ID:          "aws-ec2-launch-template-unencrypted-ebs",
	Title:       "Launch template creates unencrypted EBS volumes",
	Description: "The template's default version sets Encrypted=false on an EBS block device, so instances launched from it can write data to unencrypted volumes. A mapping that omits the flag inherits the snapshot's encryption or the region's EBS default and is not reported.",
	Remediation: "Create a template version with Encrypted=true on every EBS mapping (or remove the explicit false and turn on EBS encryption by default), and make it the default. CLI: `aws ec2 create-launch-template-version --launch-template-id LT_ID --source-version N --launch-template-data '{\"BlockDeviceMappings\":[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"Encrypted\":true}}]}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "launch_template",
	Violates:    func(a asset.Asset) bool { return countAbove(a, "unencrypted_ebs_volumes") },
}

var awsEC2SpotFleetUnencryptedEBS = Check{
	ID:          "aws-ec2-spot-fleet-unencrypted-ebs",
	Title:       "Spot Fleet request launches unencrypted EBS volumes",
	Description: "A launch specification in the live Spot Fleet request sets Encrypted=false on an EBS block device. Requests that launch from launch templates are graded through the template instead.",
	Remediation: "Spot Fleet launch specifications cannot be edited: cancel the request and create a new one with encrypted volumes, ideally from a launch template. CLI: `aws ec2 cancel-spot-fleet-requests --spot-fleet-request-ids SFR_ID --no-terminate-instances`, then `aws ec2 request-spot-fleet --spot-fleet-request-config file://config.json`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "spot_fleet_request",
	Violates:    func(a asset.Asset) bool { return countAbove(a, "unencrypted_ebs_volumes") },
}

var awsEC2ENISourceDestCheckDisabled = Check{
	ID:          "aws-ec2-eni-source-dest-check-disabled",
	Title:       "EC2 network interface has source/destination checking disabled",
	Description: "An interface attached to the instance accepts and forwards traffic not addressed to it. That is required for a NAT or routing appliance and nothing else: on an ordinary instance it lets the host relay or spoof traffic between networks. Interfaces not attached to an instance carry no traffic and are not graded.",
	Remediation: "Re-enable the check unless the instance is a deliberate router (prefer a NAT gateway to a NAT instance). Console: EC2 > Network interfaces > Actions > Change source/dest. check. CLI: `aws ec2 modify-network-interface-attribute --network-interface-id ENI_ID --source-dest-check`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["source_dest_check_disabled_enis"]
		return ok && v != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"source_dest_check_disabled_enis": a.Metadata["source_dest_check_disabled_enis"]}
	},
}

var awsASGNoELBHealthCheck = Check{
	ID:          "aws-asg-no-elb-health-check",
	Title:       "Load-balanced Auto Scaling group ignores load balancer health checks",
	Description: "The group sits behind a load balancer but replaces instances only on EC2 status checks, so an instance whose application is failing the load balancer's health check stays in service. Resilience only.",
	Remediation: "Turn on ELB health checks. Console: EC2 > Auto Scaling groups > Edit > Health checks > Turn on Elastic Load Balancing health checks. CLI: `aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --health-check-type ELB --health-check-grace-period 300`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "autoscaling_group",
	Violates: func(a asset.Asset) bool {
		hc := a.Metadata["health_check_type"]
		return a.Metadata["load_balanced"] == "true" && hc != "" && !strings.Contains(strings.ToUpper(hc), "ELB")
	},
}

var awsASGSingleAZ = Check{
	ID:          "aws-asg-single-az",
	Title:       "Auto Scaling group uses a single Availability Zone",
	Description: "The group launches into one Availability Zone, so a zone outage leaves it unable to replace capacity. Resilience only; batch groups may be single-zone by design.",
	Remediation: "Add subnets in a second zone. Console: EC2 > Auto Scaling groups > Edit > Network. CLI: `aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --vpc-zone-identifier SUBNET_A,SUBNET_B`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "autoscaling_group",
	Violates:    func(a asset.Asset) bool { return singleAZ(a, "availability_zone_count") },
}

var awsASGLaunchConfigIMDSv1 = Check{
	ID:          "aws-asg-launch-config-imdsv1",
	Title:       "Auto Scaling launch configuration allows IMDSv1",
	Description: "The launch configuration sets HttpTokens=optional or sets no metadata options at all (AWS FSBP AutoScaling.3 fails both), so its instances answer IMDSv1 and a server-side request forgery can read their role credentials. A disabled metadata endpoint is exempt. Medium when a group launches from the configuration, Low otherwise.",
	Remediation: "Launch configurations are immutable: create a launch template requiring IMDSv2 and move the group to it. Console: EC2 > Auto Scaling groups > Edit > Switch to launch template. CLI: `aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --launch-template LaunchTemplateId=LT_ID,Version='$Default'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "autoscaling_launch_configuration",
	Violates: func(a asset.Asset) bool {
		return (a.Metadata["http_tokens"] == "optional" || observedNone(a, "http_tokens")) && a.Metadata["http_endpoint"] != "disabled"
	},
	SeverityFor: launchSeverity,
}

var awsASGLaunchConfigPublicIP = Check{
	ID:          "aws-asg-launch-config-public-ip",
	Title:       "Auto Scaling launch configuration assigns public IP addresses",
	Description: "The launch configuration sets AssociatePublicIpAddress, so every instance it launches gets an internet-routable address. Medium when a group launches from the configuration, Low otherwise.",
	Remediation: "Create a launch template without public IPs and move the group to it; front the instances with a load balancer. CLI: `aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --launch-template LaunchTemplateId=LT_ID,Version='$Default'`.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "autoscaling_launch_configuration",
	Violates:    func(a asset.Asset) bool { return a.Metadata["associate_public_ip"] == "true" },
	SeverityFor: launchSeverity,
}

var awsASGSingleInstanceType = Check{
	ID:          "aws-asg-single-instance-type",
	Title:       "Auto Scaling group uses a single instance type",
	Description: "The group can launch only one instance type, so it cannot scale out when that type runs short of capacity in its zones. Availability preference only.",
	Remediation: "Use a mixed instances policy with several types or attribute-based instance selection. Console: EC2 > Auto Scaling groups > Edit > Instance type requirements. CLI: `aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --mixed-instances-policy file://policy.json`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "autoscaling_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["multiple_instance_types"] == "false" },
}

var awsASGUsesLaunchConfiguration = Check{
	ID:          "aws-asg-uses-launch-configuration",
	Title:       "Auto Scaling group launches from a launch configuration",
	Description: "The group uses a launch configuration rather than a launch template. Launch configurations are deprecated, cannot be versioned, and do not support current instance features (newer instance types, IMDSv2 defaults); AWS no longer adds capabilities to them.",
	Remediation: "Copy the configuration to a launch template and switch the group. Console: EC2 > Launch configurations > Copy to launch template, then edit the group. CLI: `aws autoscaling update-auto-scaling-group --auto-scaling-group-name NAME --launch-template LaunchTemplateId=LT_ID,Version='$Default'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "autoscaling_group",
	Violates:    func(a asset.Asset) bool { return a.Metadata["launch_source"] == "launch_configuration" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"launch_configuration_name": a.Metadata["launch_configuration_name"]}
	},
}

func awsLaunchConfigChecks() []Check {
	return []Check{
		awsEC2LaunchTemplatePublicIP,
		awsEC2LaunchTemplateIMDSv1,
		awsEC2LaunchTemplateUnencryptedEBS,
		awsEC2SpotFleetUnencryptedEBS,
		awsEC2ENISourceDestCheckDisabled,
		awsASGNoELBHealthCheck,
		awsASGSingleAZ,
		awsASGLaunchConfigIMDSv1,
		awsASGLaunchConfigPublicIP,
		awsASGSingleInstanceType,
		awsASGUsesLaunchConfiguration,
	}
}
