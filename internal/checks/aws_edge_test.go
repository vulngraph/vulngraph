package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func cfDist(md map[string]string) asset.Asset {
	return asset.Asset{ID: "arn:aws:cloudfront::1:distribution/E1", Type: cloudfrontAsset, Provider: asset.ProviderAWS, Metadata: md}
}

func TestCloudFrontGrading(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		md    map[string]string
		fires bool
		want  finding.Severity
	}{
		{"dangling origin on a live distribution is High", awsCloudFrontDanglingS3Origin,
			map[string]string{"s3_origin_buckets_missing": "b", "enabled": "true"}, true, finding.SeverityHigh},
		{"dangling origin on a disabled distribution is Low", awsCloudFrontDanglingS3Origin,
			map[string]string{"s3_origin_buckets_missing": "b", "enabled": "false"}, true, finding.SeverityLow},
		{"TLS 1.0 viewer policy is Medium", awsCloudFrontWeakViewerTLS,
			map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1_2016"}, true, finding.SeverityMedium},
		{"TLS 1.2 2019 policy is Low", awsCloudFrontWeakViewerTLS,
			map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1.2_2019"}, true, finding.SeverityLow},
		{"a newer policy than the recommended one passes", awsCloudFrontWeakViewerTLS,
			map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1.3_2025"}, false, ""},
		{"the default certificate steps aside to aws-cloudfront-default-certificate", awsCloudFrontWeakViewerTLS,
			map[string]string{"default_certificate": "true", "minimum_protocol_version": "TLSv1"}, false, ""},
		{"vip on the default certificate is not graded", awsCloudFrontDedicatedIPSSL,
			map[string]string{"default_certificate": "true", "ssl_support_method": "vip"}, false, ""},
		{"no root object with an S3 origin is Low", awsCloudFrontNoDefaultRootObject,
			map[string]string{"default_root_object": "", "has_s3_origin": "true"}, true, finding.SeverityLow},
		{"no root object in front of an application is not graded", awsCloudFrontNoDefaultRootObject,
			map[string]string{"default_root_object": "", "has_s3_origin": "false"}, false, ""},
		{"an origin bucket owned by another account is Medium", awsCloudFrontDanglingS3Origin,
			map[string]string{"s3_origin_buckets_missing": "", "s3_origin_buckets_foreign": "claimed", "enabled": "true"}, true, finding.SeverityMedium},
		{"a missing origin bucket stays High", awsCloudFrontDanglingS3Origin,
			map[string]string{"s3_origin_buckets_missing": "gone", "s3_origin_buckets_foreign": "claimed", "enabled": "true"}, true, finding.SeverityHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, ok := tt.check.eval(cfDist(tt.md), time.Time{})
			require.Equal(t, tt.fires, ok)
			if ok {
				require.Equal(t, tt.want, f.Severity)
			}
		})
	}
}

// An unread viewer policy must hold an open weak-TLS finding open: the weak
// list lives outside the predicate, so only TableProbes make it evaluable-aware.
func TestCloudFrontWeakTLSUnreadIsNotEvaluable(t *testing.T) {
	c, ok := Default().ByID("aws-cloudfront-weak-viewer-tls")
	require.True(t, ok)
	require.False(t, c.Evaluable(cfDist(map[string]string{"default_certificate": "false"})))
	require.True(t, c.Evaluable(cfDist(map[string]string{"default_certificate": "false", "minimum_protocol_version": "TLSv1.2_2021"})))
}

// WAF.3/.7 are Classic controls: a v2 rule group is graded only for metrics.
func TestWAFClassicRuleGroupCheckIgnoresV2(t *testing.T) {
	g := asset.Asset{Type: "waf_rule_group", Provider: asset.ProviderAWS, Metadata: map[string]string{"classic": "false", "rule_count": "0"}}
	require.False(t, awsWAFClassicRuleGroupEmpty.Violates(g))
}
