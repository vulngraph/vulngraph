package checks

// aws_account_settings.go — account-wide and region-wide AWS settings (CIS AWS
// Foundations 2.3/2.8/2.9/3.1.4/4.1/6.1.1, FSBP Account.1/IAM.7/S3.1/
// CloudTrail.1/EC2.7/EC2.172/EC2.182) plus the per-trail CloudTrail settings.
//
// A setting that governs the whole account is ONE finding, on the
// aws_account_settings (or per-region aws_region_settings) asset the collector
// assembles (internal/collect/aws/account_settings.go, region_settings.go) —
// never one per resource it happens to cover. Every key is written only from a
// successful read, so each predicate fires on an explicit bad value only.

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsAccountSettingsChecks() []Check {
	return []Check{
		awsIAMWeakPasswordPolicy,
		awsAccountNoSecurityContact,
		awsS3AccountBPADisabled,
		awsCloudTrailNoMultiRegionTrail,
		awsCloudTrailNoKMS,
		awsCloudTrailNoCloudWatchLogs,
		awsEBSDefaultEncryptionDisabled,
		awsEBSSnapshotBPADisabled,
		awsVPCBlockPublicAccessOff,
	}
}

// Password-policy thresholds: CIS 2.8 (length 14) and 2.9 (remember 24).
const (
	passwordMinLength       = 14
	passwordReusePrevention = 24
)

// passwordPolicyWeaknesses lists what the account password policy fails: CIS
// 2.8 and 2.9, and FSBP IAM.7's character-class defaults. One check, because
// one update-account-password-policy call fixes every item. Nil when the policy
// is strong or was not read.
func passwordPolicyWeaknesses(a asset.Asset) []string {
	switch a.Metadata["password_policy"] {
	case "absent":
		return []string{"no password policy (AWS default: 8 characters, no reuse prevention)"}
	case "present":
	default:
		return nil
	}
	var out []string
	if n, err := strconv.Atoi(a.Metadata["password_min_length"]); err == nil && n < passwordMinLength {
		out = append(out, "minimum length "+strconv.Itoa(n)+" < 14")
	}
	if n, err := strconv.Atoi(a.Metadata["password_reuse_prevention"]); err == nil && n < passwordReusePrevention {
		out = append(out, "remembers "+strconv.Itoa(n)+" previous passwords < 24")
	}
	// Literal lookups, not a table: the required-key scanner must see each key
	// so an unread policy is never taken for a strong one.
	if a.Metadata["password_require_uppercase"] == "false" {
		out = append(out, "does not require uppercase")
	}
	if a.Metadata["password_require_lowercase"] == "false" {
		out = append(out, "does not require lowercase")
	}
	if a.Metadata["password_require_numbers"] == "false" {
		out = append(out, "does not require numbers")
	}
	if a.Metadata["password_require_symbols"] == "false" {
		out = append(out, "does not require symbols")
	}
	return out
}

var awsIAMWeakPasswordPolicy = Check{
	ID:          "aws-iam-weak-password-policy",
	Title:       "IAM account password policy is weak or missing",
	Description: "The account's IAM password policy is missing, or allows passwords shorter than 14 characters, remembers fewer than 24 previous passwords, or does not require upper- and lowercase letters, numbers and symbols. It governs every IAM user console password in the account. Low severity: it matters only for IAM users with console passwords, which accounts using IAM Identity Center rarely have.",
	Remediation: "`aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols`. Prefer federated sign-in (IAM Identity Center) over IAM user passwords.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates:    func(a asset.Asset) bool { return len(passwordPolicyWeaknesses(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"weaknesses": strings.Join(passwordPolicyWeaknesses(a), "; ")}
	},
}

var awsAccountNoSecurityContact = Check{
	ID:          "aws-account-no-security-contact",
	Title:       "AWS account has no security alternate contact",
	Description: "No SECURITY alternate contact is registered on the account, so AWS security notifications (abuse reports, compromised-credential notices) go only to the root email address, which is often an unmonitored distribution list.",
	Remediation: "`aws account put-alternate-contact --alternate-contact-type SECURITY --email-address SEC@EXAMPLE.COM --name NAME --phone-number PHONE --title TITLE`, or set it for every member account from the Organizations management account.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["security_contact"] == "false" },
}

var awsS3AccountBPADisabled = Check{
	ID:          "aws-s3-account-bpa-disabled",
	Title:       "S3 account-level Block Public Access is not fully enabled",
	Description: "Not all four S3 Block Public Access settings are on at the account level, so whether each bucket can be made public depends on that bucket's own settings. The account-level block is the one switch that keeps every current and future bucket private; per-bucket exposure is reported by aws-s3-public-bucket.",
	Remediation: "If no bucket needs to be public: `aws s3control put-public-access-block --account-id ACCOUNT --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`. Serve intentionally public content through CloudFront with origin access control instead of a public bucket.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["s3_bpa_all_enabled"] == "false" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{}
		for _, k := range []string{"s3_bpa_block_public_acls", "s3_bpa_ignore_public_acls", "s3_bpa_block_public_policy", "s3_bpa_restrict_public_buckets"} {
			if v, ok := a.Metadata[k]; ok {
				ev[k] = v
			}
		}
		return ev
	},
}

var awsCloudTrailNoMultiRegionTrail = Check{
	ID:    "aws-cloudtrail-no-multiregion-trail",
	Title: "No multi-region CloudTrail trail is logging",
	TitleFor: func(a asset.Asset) string {
		switch {
		case a.Metadata["cloudtrail_trail_count"] == "0":
			return "AWS account has no CloudTrail trail"
		case a.Metadata["cloudtrail_multi_region_logging"] == "false":
			return "No multi-region CloudTrail trail is logging"
		}
		return "No multi-region CloudTrail trail records all management events"
	},
	Description: "The account has no CloudTrail trail that covers every region, is currently logging (including organization trails) and records both read and write management events (CIS AWS 4.1, FSBP CloudTrail.1). API activity is then retained only in the 90-day CloudTrail event history, and activity in uncovered regions, by global services, or of the unrecorded kind may not be retained at all — investigators lose the record of what an intruder did. A logging multi-region trail that misses only read or only write management events is graded Low.",
	Remediation: "Create a multi-region trail (or an organization trail from the management account): `aws cloudtrail create-trail --name org-trail --s3-bucket-name BUCKET --is-multi-region-trail --enable-log-file-validation` then `aws cloudtrail start-logging --name org-trail`. For a trail that misses read or write management events: Console → CloudTrail → Trails → the trail → Management events → Edit → API activity Read and Write; CLI `aws cloudtrail put-event-selectors --trail-name TRAIL --event-selectors '[{\"ReadWriteType\":\"All\",\"IncludeManagementEvents\":true}]'` (keep its data-event selectors).",
	Type:        "hygiene",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_account_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cloudtrail_multi_region_logging"] == "false" || a.Metadata["cloudtrail_multi_region_mgmt_all"] == "false"
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["cloudtrail_multi_region_logging"] == "false" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"trail_count": a.Metadata["cloudtrail_trail_count"]}
	},
}

var awsCloudTrailNoKMS = Check{
	ID:          "aws-cloudtrail-no-kms-encryption",
	Title:       "CloudTrail trail logs are not encrypted with a KMS key",
	Description: "The trail delivers logs encrypted only with S3-managed keys (no KmsKeyId). With a customer KMS key, reading the logs needs kms:Decrypt as well as S3 read access, which keeps audit logs out of reach of anyone holding only broad S3 permissions.",
	Remediation: "Create a KMS key whose policy allows cloudtrail.amazonaws.com to encrypt, then `aws cloudtrail update-trail --name TRAIL --kms-key-id KEY_ARN`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_cloudtrail",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "kms_key_id") },
}

var awsCloudTrailNoCloudWatchLogs = Check{
	ID:          "aws-cloudtrail-no-cloudwatch-logs",
	Title:       "CloudTrail trail does not deliver to CloudWatch Logs",
	Description: "The trail has no CloudWatch Logs log group, so its events cannot drive metric filters and alarms (the CIS monitoring controls). The trail still records to S3; this is a real-time-alerting gap, not missing audit data.",
	Remediation: "`aws cloudtrail update-trail --name TRAIL --cloud-watch-logs-log-group-arn LOG_GROUP_ARN --cloud-watch-logs-role-arn ROLE_ARN`, with a role that lets CloudTrail write to the log group.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_cloudtrail",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "cloudwatch_log_group") },
}

var awsEBSDefaultEncryptionDisabled = Check{
	ID:          "aws-ebs-default-encryption-disabled",
	Title:       "EBS encryption by default is off in this region",
	Description: "New EBS volumes and snapshot copies in this region are not encrypted unless each launch asks for it. Existing unencrypted volumes are reported by aws-ebs-unencrypted; this is the regional default that keeps new ones from joining them.",
	Remediation: "`aws ec2 enable-ebs-encryption-by-default --region REGION` (optionally `aws ec2 modify-ebs-default-kms-key-id`). It applies to new volumes only.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["ebs_encryption_by_default"] == "false" },
}

var awsEBSSnapshotBPADisabled = Check{
	ID:          "aws-ebs-snapshot-bpa-disabled",
	Title:       "EBS snapshot Block Public Access does not block all sharing",
	Description: "EBS snapshot Block Public Access in this region is not set to block-all-sharing, so a snapshot (a full disk image) can be shared publicly (unblocked), or snapshots already public stay public (block-new-sharing). A publicly shared snapshot is reported by aws-ebs-snapshot-public; this is the guardrail.",
	Remediation: "`aws ec2 enable-snapshot-block-public-access --state block-all-sharing --region REGION`, after confirming no snapshot must stay public.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates: func(a asset.Asset) bool {
		switch a.Metadata["snapshot_block_public_access"] {
		case "unblocked", "block-new-sharing":
			return true
		}
		return false
	},
	// block-new-sharing still stops new public shares; only existing ones remain.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["snapshot_block_public_access"] == "block-new-sharing" {
			return finding.SeverityLow
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"state": a.Metadata["snapshot_block_public_access"]}
	},
}

var awsVPCBlockPublicAccessOff = Check{
	ID:          "aws-vpc-block-public-access-off",
	Title:       "VPC Block Public Access is off in this region",
	Description: "VPC Block Public Access is not blocking internet gateway traffic in this region, so internet exposure is decided per security group, route table and public IP. Info only: turning it on cuts off every internet-facing workload not explicitly excluded, so it suits regions that should hold no internet-facing resources.",
	Remediation: "For a region that must have no internet ingress: `aws ec2 modify-vpc-block-public-access-options --internet-gateway-block-mode block-ingress --region REGION`, with exclusions for VPCs or subnets that legitimately face the internet.",
	Type:        "exposure",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_region_settings",
	Violates:    func(a asset.Asset) bool { return a.Metadata["vpc_block_public_access"] == "off" },
}
