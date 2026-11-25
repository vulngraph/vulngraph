package checks

// aws_ec2_posture.go — EC2 instance, EBS snapshot/volume and security-group
// hygiene conditions: instance profile on an internet-facing instance, instance
// age, unencrypted snapshots, volumes without snapshots, launch-wizard groups
// and groups with many rules.

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsEC2PostureChecks() []Check {
	return []Check{
		awsEC2InternetFacingWithProfile,
		awsEC2InstanceTooOld,
		awsEBSSnapshotUnencrypted,
		awsEBSVolumeNoSnapshot,
		awsSGLaunchWizard,
		awsSGManyRules,
	}
}

const (
	maxEC2InstanceAgeDays  = 180
	maxSGRulesPerDirection = 50
	launchWizardPrefix     = "launch-wizard"
)

var awsEC2InternetFacingWithProfile = Check{
	ID:          "aws-ec2-internet-facing-with-instance-profile",
	Title:       "Internet-facing EC2 instance has an IAM instance profile",
	Description: "The instance has a public IPv4 address and an IAM role attached through an instance profile. Any remote-code-execution or server-side request forgery flaw in a service on it hands an internet attacker the role's temporary credentials from the metadata service, so the blast radius is whatever that role may do. Graded Medium: the combination is common and sometimes intended, and the role's permissions decide the real impact.",
	Remediation: "Drop the public address and front the instance with a load balancer, or scope the role to the minimum it needs and require IMDSv2. Console: EC2 > Instances > select > Actions > Security > Modify IAM role (or Networking > Manage IP addresses). CLI: `aws ec2 disassociate-iam-instance-profile --association-id ASSOC_ID` (find it with `aws ec2 describe-iam-instance-profile-associations --filters Name=instance-id,Values=INSTANCE_ID`).",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		return a.PublicIP != "" && a.Metadata["iam_instance_profile"] != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_ip": a.PublicIP, "iam_instance_profile": a.Metadata["iam_instance_profile"]}
	},
}

// ec2AgeDays returns the whole days since launch for a running instance; ok is
// false when the instance is not running or its launch time was not read.
func ec2AgeDays(a asset.Asset, now time.Time) (int, bool) {
	if a.Metadata["state"] != "running" {
		return 0, false
	}
	launched, err := time.Parse(time.RFC3339, a.Metadata["launched_at"])
	if err != nil {
		return 0, false
	}
	return int(math.Floor(now.Sub(launched).Hours() / 24)), true
}

var awsEC2InstanceTooOld = Check{
	ID:          "aws-ec2-instance-too-old",
	Title:       "EC2 instance has been running for more than 180 days",
	Description: "The instance has run without being replaced for over " + strconv.Itoa(maxEC2InstanceAgeDays) + " days. Long-lived instances accumulate unpatched packages, configuration drift and stale credentials; replacing them from a current image keeps the fleet reproducible. Only running instances are graded, by whole days since the last launch.",
	Remediation: "Rebuild the instance from a current AMI and replace it, ideally through an Auto Scaling group instance refresh. Console: EC2 > Auto Scaling groups > select > Instance refresh > Start. CLI: `aws autoscaling start-instance-refresh --auto-scaling-group-name ASG_NAME`; for a standalone instance launch a replacement and run `aws ec2 terminate-instances --instance-ids INSTANCE_ID`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates: func(a asset.Asset) bool {
		days, ok := ec2AgeDays(a, time.Now())
		return ok && days > maxEC2InstanceAgeDays
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		days, _ := ec2AgeDays(a, time.Now())
		return map[string]string{"age_days": strconv.Itoa(days), "launched_at": a.Metadata["launched_at"]}
	},
}

var awsEBSSnapshotUnencrypted = Check{
	ID:          "aws-ebs-snapshot-unencrypted",
	Title:       "EBS snapshot is not encrypted",
	Description: "The snapshot is stored unencrypted, so anyone granted ec2:CreateVolume or snapshot sharing can read the disk contents without needing access to a KMS key, and the key policy cannot be used to revoke access. Snapshots of encrypted volumes are always encrypted, so this means the source volume was unencrypted or the snapshot was copied without encryption.",
	Remediation: "Copy the snapshot with encryption on, then delete the unencrypted original. Console: EC2 > Snapshots > select > Actions > Copy snapshot > Encrypt this snapshot. CLI: `aws ec2 copy-snapshot --source-region REGION --source-snapshot-id SNAP_ID --encrypted --kms-key-id KEY_ID` then `aws ec2 delete-snapshot --snapshot-id SNAP_ID`. Turn on EBS encryption by default (`aws ec2 enable-ebs-encryption-by-default`) so new snapshots are encrypted.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ebs_snapshot",
	Violates:    func(a asset.Asset) bool { return a.Metadata["encrypted"] == "false" },
}

var awsEBSVolumeNoSnapshot = Check{
	ID:          "aws-ebs-volume-no-snapshot",
	Title:       "EBS volume has no snapshot",
	Description: "No snapshot of this volume exists among the account's own snapshots in its region, so a deleted volume, a failed disk or a ransomware event leaves no point-in-time copy to restore from. Volumes that hold only disposable data may be exempt by decision.",
	Remediation: "Snapshot the volume and schedule regular snapshots. Console: EC2 > Volumes > select > Actions > Create snapshot; automate with Data Lifecycle Manager (EC2 > Lifecycle Manager). CLI: `aws ec2 create-snapshot --volume-id VOLUME_ID --description \"baseline\"`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "ebs_volume",
	Violates:    func(a asset.Asset) bool { return a.Metadata["has_snapshot"] == "false" },
}

var awsSGLaunchWizard = Check{
	ID:          "aws-sg-launch-wizard",
	Title:       "Security group was created by the EC2 launch wizard",
	Description: "The group's name starts with the \"launch-wizard\" prefix the console wizard generates. Wizard groups are created ad hoc, often with SSH open to the creating user's address or wider, and are then reused or forgotten. A group someone named and scoped deliberately is easier to review and own.",
	Remediation: "Replace it with a purpose-named group scoped to the workload, move the resources over, and delete the wizard group. Console: EC2 > Security Groups > Create security group, then EC2 > Instances > Actions > Security > Change security groups. CLI: `aws ec2 modify-instance-attribute --instance-id INSTANCE_ID --groups NEW_SG_ID` then `aws ec2 delete-security-group --group-id OLD_SG_ID`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	Violates:    func(a asset.Asset) bool { return strings.Contains(a.Name, launchWizardPrefix) },
}

var awsSGManyRules = Check{
	ID:          "aws-sg-many-rules",
	Title:       "Security group has more than 50 inbound or outbound rules",
	Description: "The group has over " + strconv.Itoa(maxSGRulesPerDirection) + " inbound or over " + strconv.Itoa(maxSGRulesPerDirection) + " outbound rules (each direction counted separately). Large rule sets are hard to review, hide overly broad entries and approach the per-group quota, which makes later changes fail at the worst time.",
	Remediation: "Consolidate rules with CIDR ranges or managed prefix lists and split the group by workload. Console: VPC > Security groups > select > Edit inbound rules. CLI: `aws ec2 create-managed-prefix-list --prefix-list-name NAME --address-family IPv4 --max-entries 100 --entries Cidr=CIDR` then reference it from the group with `aws ec2 authorize-security-group-ingress --group-id SG_ID --ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,PrefixListIds=[{PrefixListId=PL_ID}]'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		in, inOK := sgRuleCount(a, "ingress_rules")
		out, outOK := sgRuleCount(a, "egress_rules")
		return (inOK && in > maxSGRulesPerDirection) || (outOK && out > maxSGRulesPerDirection)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"ingress_rules": a.Metadata["ingress_rules"], "egress_rules": a.Metadata["egress_rules"]}
	},
}
