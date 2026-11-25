package checks

// aws_s3.go — S3 bucket exposure split by what it grants (FSBP S3.2/S3.3),
// the bucket-level Block Public Access (S3.8), ACL use (S3.12) and lifecycle
// rules (S3.13). aws-s3-public-bucket (cis.go) keeps the effective-block
// tiers and steps aside for the two grant checks.

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsS3Checks() []Check {
	return []Check{
		awsS3PublicRead,
		awsS3PublicWrite,
		awsS3BucketBPAIncomplete,
		awsS3ACLsInUse,
		awsS3NoLifecycle,
		awsS3AccessPointBPAIncomplete,
		awsS3MRAPBPAIncomplete,
		awsS3DirectoryBucketNoLifecycle,
	}
}

var awsS3AccessPointBPAIncomplete = Check{
	ID:          "aws-s3-access-point-bpa-incomplete",
	Title:       "S3 access point does not block public access",
	Description: "Not all four Block Public Access settings are on for this access point, so a public access point policy is not stopped at the access point. Access through an access point still needs the bucket's policy to delegate to it, and an account or bucket block can still neutralize it, so a public access point policy here is the possible tier (Medium), not proof of exposure; with no public policy it is a missing guardrail (Low). FSBP S3.19.",
	Remediation: "Block Public Access cannot be changed on an existing access point. Create a replacement with all four settings on — Console: S3 → Access Points → Create access point → keep \"Block all public access\" checked; CLI: `aws s3control create-access-point --account-id ACCOUNT --name NAME --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true` — move clients to it, then `aws s3control delete-access-point --account-id ACCOUNT --name OLD`.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_access_point",
	Violates:    func(a asset.Asset) bool { return a.Metadata["bpa_all_enabled"] == "false" },
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["policy_public"] == "true" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["policy_public"] == "true" {
			return "S3 access point has a public policy and does not block public access"
		}
		return "S3 access point does not block public access"
	},
}

var awsS3MRAPBPAIncomplete = Check{
	ID:          "aws-s3-mrap-bpa-incomplete",
	Title:       "S3 Multi-Region Access Point does not block public access",
	Description: "Not all four Block Public Access settings are on for this Multi-Region Access Point, so its policy can grant public access across every bucket it fronts. The setting is fixed when the access point is created. FSBP S3.24.",
	Remediation: "Create a replacement Multi-Region Access Point with all four settings on — Console: S3 → Multi-Region Access Points → Create → keep \"Block all public access\" checked; CLI: `aws s3control create-multi-region-access-point --account-id ACCOUNT --details '{\"Name\":\"NAME\",\"PublicAccessBlock\":{\"BlockPublicAcls\":true,\"IgnorePublicAcls\":true,\"BlockPublicPolicy\":true,\"RestrictPublicBuckets\":true},\"Regions\":[{\"Bucket\":\"BUCKET\"}]}' --region us-west-2` — move clients, then delete the old one.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_multi_region_access_point",
	Violates:    func(a asset.Asset) bool { return a.Metadata["bpa_all_enabled"] == "false" },
}

var awsS3DirectoryBucketNoLifecycle = Check{
	ID:          "aws-s3-directory-bucket-no-lifecycle",
	Title:       "S3 directory bucket has no lifecycle rules",
	Description: "The S3 Express One Zone directory bucket has no enabled lifecycle rule, so objects and incomplete multipart uploads are kept until someone deletes them. FSBP S3.25.",
	Remediation: "Console: S3 → Directory buckets → the bucket → Management → Create lifecycle rule. CLI: `aws s3api put-bucket-lifecycle-configuration --bucket BUCKET--AZ--x-s3 --lifecycle-configuration file://lifecycle.json --region REGION`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_directory_bucket",
	Violates:    func(a asset.Asset) bool { return a.Metadata["lifecycle_rules_enabled"] == "0" },
}

// supersededChecks maps a check to the check whose findings it took over on
// the same resource. A suppression on the old finding is carried to the new
// one (internal/jobs carrySuppressions), so a decision already made — an
// intentionally public website bucket — survives the split instead of
// returning as a fresh Critical.
var supersededChecks = map[string]string{
	"aws-s3-public-read":  "aws-s3-public-bucket",
	"aws-s3-public-write": "aws-s3-public-bucket",
}

// SupersededCheck returns the check whose findings checkID took over on the
// same resource, or "".
func SupersededCheck(checkID string) string { return supersededChecks[checkID] }

// s3PublicDataGrant reports a bucket whose public read or write grant is
// reported by aws-s3-public-read / aws-s3-public-write.
func s3PublicDataGrant(a asset.Asset) bool {
	return a.Metadata["public_read"] == "true" || a.Metadata["public_write"] == "true"
}

var awsS3PublicRead = Check{
	ID:          "aws-s3-public-read",
	Title:       "S3 bucket is publicly readable",
	Description: "Anyone on the internet can list or download this bucket's objects: a bucket policy grants s3:GetObject / s3:ListBucket (or s3:*) to everyone (Principal \"*\", or an Allow with NotPrincipal) with no condition that restricts the caller, or the ACL grants READ to AllUsers or AuthenticatedUsers, and no Block Public Access setting neutralizes it. FSBP S3.2, CIS AWS 3.1.4.",
	Remediation: "Console: S3 → the bucket → Permissions → turn on Block public access (all four settings), then remove the statements granting Principal \"*\" (or the Allow with NotPrincipal) from the bucket policy and the AllUsers/AuthenticatedUsers grants from the ACL. CLI: `aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`. If the content must be public, serve it through CloudFront with origin access control instead. Review CloudTrail data events / server access logs for what was read.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_read"] == "true" },
}

var awsS3PublicWrite = Check{
	ID:          "aws-s3-public-write",
	Title:       "S3 bucket is publicly writable",
	Description: "Anyone on the internet can create, overwrite or delete objects in this bucket, or rewrite its policy or ACL: a bucket policy grants s3:PutObject / s3:DeleteObject / s3:PutBucketPolicy and similar to everyone (Principal \"*\", or an Allow with NotPrincipal) with no condition that restricts the caller, or the ACL grants WRITE, WRITE_ACP or FULL_CONTROL to AllUsers or AuthenticatedUsers. A writable bucket hosts malware under your name, poisons whatever reads from it, and can be emptied. FSBP S3.3.",
	Remediation: "Console: S3 → the bucket → Permissions → turn on Block public access (all four settings), then remove the write statements granting Principal \"*\" (or the Allow with NotPrincipal) from the bucket policy and the public grants from the ACL. CLI: `aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`, then `aws s3api put-bucket-acl --bucket BUCKET --acl private`. Audit recent PutObject/DeleteObject events for objects that were planted or removed.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_write"] == "true" },
}

var awsS3BucketBPAIncomplete = Check{
	ID:          "aws-s3-bucket-bpa-incomplete",
	Title:       "S3 bucket's own Block Public Access is not fully enabled",
	Description: "The account-level Block Public Access currently covers this bucket, but the bucket's own four Block Public Access settings are not all on. Should the account block be relaxed — for one bucket that needs it, or by a mistaken change — nothing on this bucket stops a public policy or ACL. Buckets whose effective block is incomplete are reported by aws-s3-public-bucket instead. FSBP S3.8.",
	Remediation: "Console: S3 → the bucket → Permissions → Block public access (bucket settings) → Edit → enable all four. CLI: `aws s3api put-public-access-block --bucket BUCKET --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["bucket_bpa_all_enabled"] == "false" && a.Metadata["bpa_all_enabled"] == "true"
	},
}

var awsS3ACLsInUse = Check{
	ID:          "aws-s3-acls-in-use",
	Title:       "S3 bucket grants access through its ACL",
	Description: "Object Ownership is not set to BucketOwnerEnforced and the bucket ACL grants access to someone other than the bucket owner (another account, a canonical user or a group such as the log-delivery group). ACL grants sit outside IAM and bucket policies, so they are easy to miss in an access review. Public ACL grants are reported by aws-s3-public-read / aws-s3-public-write. FSBP S3.12.",
	Remediation: "Move the access to the bucket policy, then Console: S3 → the bucket → Permissions → Object Ownership → Edit → ACLs disabled (Bucket owner enforced). CLI: `aws s3api put-bucket-ownership-controls --bucket BUCKET --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["acl_non_owner_grants"])
		return err == nil && n > 0 && !s3PublicDataGrant(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"acl_non_owner_grants": a.Metadata["acl_non_owner_grants"], "object_ownership": a.Metadata["object_ownership"]}
	},
}

var awsS3NoLifecycle = Check{
	ID:          "aws-s3-no-lifecycle",
	Title:       "S3 bucket has no lifecycle rules",
	Description: "The bucket has no enabled lifecycle rule, so objects, noncurrent versions and incomplete multipart uploads are kept indefinitely: data that should have expired stays exposed to whoever gains access, and storage grows unchecked. FSBP S3.13.",
	Remediation: "Console: S3 → the bucket → Management → Create lifecycle rule (e.g. expire noncurrent versions after N days and abort incomplete multipart uploads after 7). CLI: `aws s3api put-bucket-lifecycle-configuration --bucket BUCKET --lifecycle-configuration file://lifecycle.json`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "s3_bucket",
	Violates:    func(a asset.Asset) bool { return a.Metadata["lifecycle_rules_enabled"] == "0" },
}
