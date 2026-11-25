package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// awsCloudTrailBucketNoAccessLogging reads s3_bucket_logging, which the AWS
// collector joins onto the trail from its destination bucket
// (internal/collect/aws/cloudtrail_bucket.go). The key is absent when the bucket
// is outside the sweep's inventory (an organization trail delivering to a
// log-archive account) or its logging state was unreadable, so those trails
// stay silent rather than reading as unlogged.
//
// Graded above the bucket's own aws-s3-access-logging-disabled (Low): on the
// trail's bucket, the missing access log is the record of who read or deleted
// the audit trail itself (CIS AWS v7.0.0 4.4).
var awsCloudTrailBucketNoAccessLogging = Check{
	ID:          "aws-cloudtrail-bucket-no-access-logging",
	Title:       "CloudTrail log bucket has S3 server access logging disabled",
	Description: "The S3 bucket this trail delivers to does not have server access logging enabled. CloudTrail records API calls, but reads, overwrites and deletions of the log objects themselves are data events it does not capture by default — without access logging on the bucket there is no record of who read, tampered with or removed the audit trail. CIS AWS Foundations v7.0.0 4.4 requires access logging on the CloudTrail bucket.",
	Remediation: "Enable server access logging on the trail's bucket, delivering to a separate, locked-down log bucket: `aws s3api put-bucket-logging --bucket TRAIL_BUCKET --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"ACCESS_LOG_BUCKET\",\"TargetPrefix\":\"cloudtrail/\"}}'`. Alternatively enable CloudTrail S3 data events for the bucket.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_cloudtrail",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["s3_bucket_logging"] == "disabled"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"s3_bucket": a.Metadata["s3_bucket"]}
	},
}
