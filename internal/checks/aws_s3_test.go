package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestAwsS3ChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-s3-public-read", check: awsS3PublicRead,
			violating: map[string]string{"public_read": "true"},
			compliant: map[string]string{"public_read": "false"},
			unknown:   map[string]string{"public_access": "confirmed"},
		},
		{
			name: "aws-s3-public-write", check: awsS3PublicWrite,
			violating: map[string]string{"public_write": "true"},
			compliant: map[string]string{"public_write": "false"},
			unknown:   map[string]string{"public_access": "confirmed"},
		},
		{
			name: "aws-s3-bucket-bpa-incomplete", check: awsS3BucketBPAIncomplete,
			violating: map[string]string{"bucket_bpa_all_enabled": "false", "bpa_all_enabled": "true"},
			compliant: map[string]string{"bucket_bpa_all_enabled": "true", "bpa_all_enabled": "true"},
			unknown:   map[string]string{"bpa_all_enabled": "true"},
		},
		{
			name: "aws-s3-acls-in-use", check: awsS3ACLsInUse,
			violating: map[string]string{"acl_non_owner_grants": "2", "object_ownership": ""},
			compliant: map[string]string{"acl_non_owner_grants": "0", "object_ownership": "BucketOwnerEnforced"},
			unknown:   map[string]string{"object_ownership": ""},
		},
		{
			name: "aws-s3-no-lifecycle", check: awsS3NoLifecycle,
			violating: map[string]string{"lifecycle_rules_enabled": "0"},
			compliant: map[string]string{"lifecycle_rules_enabled": "2"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-s3-access-point-bpa-incomplete", check: awsS3AccessPointBPAIncomplete,
			violating: map[string]string{"bpa_all_enabled": "false"},
			compliant: map[string]string{"bpa_all_enabled": "true"},
			unknown:   map[string]string{"network_origin": "Internet"},
		},
		{
			name: "aws-s3-mrap-bpa-incomplete", check: awsS3MRAPBPAIncomplete,
			violating: map[string]string{"bpa_all_enabled": "false"},
			compliant: map[string]string{"bpa_all_enabled": "true"},
			unknown:   map[string]string{"status": "READY"},
		},
		{
			name: "aws-s3-directory-bucket-no-lifecycle", check: awsS3DirectoryBucketNoLifecycle,
			violating: map[string]string{"lifecycle_rules_enabled": "0"},
			compliant: map[string]string{"lifecycle_rules_enabled": "1"},
			unknown:   map[string]string{},
		},
	})
}

// One public bucket is one finding per kind of grant: the public-bucket
// check steps aside for the read/write checks, and keeps firing for the
// guardrail tiers and for a public grant of neither kind.
func TestS3PublicFindingsOncePerRootCause(t *testing.T) {
	reg := NewRegistry()
	reg.Register(awsS3PublicBucket, awsS3PublicRead, awsS3PublicWrite, awsS3BucketBPAIncomplete, awsS3ACLsInUse)
	fired := func(md map[string]string) map[string]finding.Severity {
		out := map[string]finding.Severity{}
		for _, f := range reg.Run([]asset.Asset{{ID: "b", Type: "s3_bucket", Provider: asset.ProviderAWS, Metadata: md}}, time.Now()) {
			out[f.CheckID] = f.Severity
		}
		return out
	}
	require.Equal(t, map[string]finding.Severity{"aws-s3-public-read": finding.SeverityCritical},
		fired(map[string]string{"public": "true", "public_access": "confirmed", "bpa_all_enabled": "false", "bucket_bpa_all_enabled": "false", "public_read": "true", "public_write": "false", "acl_non_owner_grants": "1"}))
	require.Equal(t, map[string]finding.Severity{"aws-s3-public-read": finding.SeverityCritical, "aws-s3-public-write": finding.SeverityCritical},
		fired(map[string]string{"public": "true", "public_access": "confirmed", "bpa_all_enabled": "false", "public_read": "true", "public_write": "true"}))
	// AWS says public, but the grant is metadata only.
	require.Equal(t, map[string]finding.Severity{"aws-s3-public-bucket": finding.SeverityHigh},
		fired(map[string]string{"public": "true", "public_access": "confirmed", "bpa_all_enabled": "false", "public_read": "false", "public_write": "false"}))
	// No block anywhere, nothing granted: the possible tier.
	require.Equal(t, map[string]finding.Severity{"aws-s3-public-bucket": finding.SeverityLow},
		fired(map[string]string{"public": "true", "public_access": "possible", "bpa_all_enabled": "false", "bucket_bpa_all_enabled": "false", "public_read": "false", "public_write": "false"}))
	// The account block covers the bucket; only its own block is missing.
	require.Equal(t, map[string]finding.Severity{"aws-s3-bucket-bpa-incomplete": finding.SeverityLow},
		fired(map[string]string{"public": "false", "public_access": "none", "bpa_all_enabled": "true", "bucket_bpa_all_enabled": "false", "public_read": "false", "public_write": "false"}))
}

func TestSupersededChecksAreRegistered(t *testing.T) {
	reg := Default()
	for next, prev := range supersededChecks {
		_, ok := reg.ByID(next)
		require.True(t, ok, next)
		_, ok = reg.ByID(prev)
		require.True(t, ok, "%s supersedes %s, which must stay registered", next, prev)
	}
}

func TestS3AccessPointPublicPolicyTier(t *testing.T) {
	ap := asset.Asset{Type: "s3_access_point", Provider: asset.ProviderAWS, Metadata: map[string]string{"bpa_all_enabled": "false", "policy_public": "true"}}
	require.Equal(t, finding.SeverityMedium, awsS3AccessPointBPAIncomplete.SeverityFor(ap))
	ap.Metadata["policy_public"] = "false"
	require.Equal(t, finding.SeverityLow, awsS3AccessPointBPAIncomplete.SeverityFor(ap))
}
