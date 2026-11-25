package aws

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestStampTrailBucketLogging(t *testing.T) {
	trail := func(id, bucket string) asset.Asset {
		return asset.Asset{ID: id, Type: "aws_cloudtrail", Metadata: map[string]string{"s3_bucket": bucket}}
	}
	bucket := func(name string, meta map[string]string) asset.Asset {
		return asset.Asset{ID: name, Name: name, Type: "s3_bucket", Metadata: meta}
	}
	assets := []asset.Asset{
		trail("t-off", "logs-off"),
		trail("t-on", "logs-on"),
		trail("t-unread", "logs-unread"),
		trail("t-cross-account", "org-log-archive"),
		bucket("logs-off", map[string]string{"logging": "disabled"}),
		bucket("logs-on", map[string]string{"logging": "enabled"}),
		bucket("logs-unread", map[string]string{}), // GetBucketLogging failed
	}
	stampTrailBucketLogging(assets)

	got := map[string]map[string]string{}
	for _, a := range assets {
		got[a.ID] = a.Metadata
	}
	require.Equal(t, "disabled", got["t-off"]["s3_bucket_logging"])
	require.Equal(t, "enabled", got["t-on"]["s3_bucket_logging"])
	require.NotContains(t, got["t-unread"], "s3_bucket_logging", "an unread bucket setting is unknown, not disabled")
	require.NotContains(t, got["t-cross-account"], "s3_bucket_logging", "a bucket outside this sweep's inventory is unknown")
	require.NotContains(t, got["logs-off"], "s3_bucket_logging", "only trails are stamped")
}

func TestStampTrailBucketMFADelete(t *testing.T) {
	trail := func(id, bucket string) asset.Asset {
		return asset.Asset{ID: id, Type: "aws_cloudtrail", Metadata: map[string]string{"s3_bucket": bucket}}
	}
	bucket := func(name string, meta map[string]string) asset.Asset {
		return asset.Asset{ID: name, Name: name, Type: "s3_bucket", Metadata: meta}
	}
	assets := []asset.Asset{
		trail("t-off", "logs-off"),
		trail("t-on", "logs-on"),
		trail("t-unread", "logs-unread"),
		trail("t-cross-account", "org-log-archive"),
		bucket("logs-off", map[string]string{"mfa_delete": "Disabled"}),
		bucket("logs-on", map[string]string{"mfa_delete": "Enabled"}),
		bucket("logs-unread", map[string]string{}),
	}
	stampTrailBucketMFADelete(assets)

	got := map[string]map[string]string{}
	for _, a := range assets {
		got[a.ID] = a.Metadata
	}
	require.Equal(t, "Disabled", got["t-off"]["s3_bucket_mfa_delete"])
	require.Equal(t, "Enabled", got["t-on"]["s3_bucket_mfa_delete"])
	require.NotContains(t, got["t-unread"], "s3_bucket_mfa_delete", "an unread bucket setting is unknown, not disabled")
	require.NotContains(t, got["t-cross-account"], "s3_bucket_mfa_delete", "a bucket outside this sweep's inventory is unknown")
	require.NotContains(t, got["logs-off"], "s3_bucket_mfa_delete", "only trails are stamped")
}
