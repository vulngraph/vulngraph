package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// GCS bucket guardrail posture. Its own file rather than another block in
// cspm_expanded.go, which is near the 800-line ceiling.

// gcpGCSPublicAccessNotPrevented reads effective prevention, including the
// organization policy inherited by a bucket. The bucket's raw "inherited"
// setting alone establishes neither enforcement nor its absence.
//
// Missing prevention is a low-severity guardrail finding, distinct from the
// public-bucket check's observed exposure.
//
// An unreadable effective policy leaves the evidence key absent, so the check
// stays unevaluated and cannot close a prior finding as fixed.
var gcpGCSPublicAccessNotPrevented = Check{
	ID:          "gcp-gcs-public-access-not-prevented",
	Title:       "GCS bucket has no effective public access prevention",
	Description: "Public access prevention is not enforced on this bucket or through its effective project, folder and organization policy. Public IAM or ACL grants are therefore not blocked by this guardrail. This is a missing protection, not evidence that the bucket is currently public.",
	Remediation: "Enforce prevention on the bucket: `gcloud storage buckets update gs://BUCKET --public-access-prevention`, or apply the `constraints/storage.publicAccessPrevention` organization policy at the appropriate project, folder or organization.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcs_bucket",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["public_access_prevention_effective"] == "not_enforced"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"public_access_prevention":           a.Metadata["public_access_prevention"],
			"public_access_prevention_effective": a.Metadata["public_access_prevention_effective"],
			"uniform_bucket_access":              a.Metadata["uniform_access"],
			"currently_public":                   a.Metadata["public"],
		}
	},
}
