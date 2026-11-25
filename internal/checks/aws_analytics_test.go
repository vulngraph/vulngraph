package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAwsAnalyticsChecksNeverFireOnAbsentData(t *testing.T) {
	runAbsentDataRows(t, []absentDataRow{
		{
			name: "aws-sqs-not-encrypted", check: awsSQSNotEncrypted,
			violating: map[string]string{"sse": "none"},
			compliant: map[string]string{"sse": "sqs"},
			unknown:   map[string]string{"public_access": "none"},
		},
		{
			name: "aws-kinesis-stream-not-encrypted", check: awsKinesisStreamNotEncrypted,
			violating: map[string]string{"encryption_type": "NONE"},
			compliant: map[string]string{"encryption_type": "KMS"},
			unknown:   map[string]string{"stream_status": "ACTIVE"},
		},
		{
			name: "aws-kinesis-stream-short-retention", check: awsKinesisStreamShortRetention,
			violating: map[string]string{"retention_hours": "24"},
			compliant: map[string]string{"retention_hours": "168"},
			unknown:   map[string]string{"stream_status": "ACTIVE"},
		},
		{
			name: "aws-firehose-not-encrypted", check: awsFirehoseNotEncrypted,
			violating: map[string]string{"source_type": "DirectPut", "sse_status": "DISABLED"},
			compliant: map[string]string{"source_type": "DirectPut", "sse_status": "ENABLED"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-glue-ml-transform-not-encrypted", check: awsGlueMLTransformNotEncrypted,
			violating: map[string]string{"user_data_encryption": "DISABLED"},
			compliant: map[string]string{"user_data_encryption": "SSE-KMS"},
			unknown:   map[string]string{},
		},
		{
			name: "aws-glue-job-unsupported-version", check: awsGlueJobUnsupportedVersion,
			violating: map[string]string{"command": "glueetl", "glue_version": "2.0"},
			compliant: map[string]string{"command": "glueetl", "glue_version": "4.0"},
			unknown:   map[string]string{"command": "glueetl"},
		},
		{
			name: "aws-athena-workgroup-no-metrics", check: awsAthenaWorkgroupNoMetrics,
			violating: map[string]string{"cloudwatch_metrics_enabled": "false"},
			compliant: map[string]string{"cloudwatch_metrics_enabled": "true"},
			unknown:   map[string]string{"state": "ENABLED"},
		},
	})
}

func TestGlueJobVersionGate(t *testing.T) {
	job := func(cmd, version string) asset.Asset {
		return asset.Asset{Type: "glue_job", Provider: asset.ProviderAWS, Metadata: map[string]string{"command": cmd, "glue_version": version}}
	}
	for _, tt := range []struct {
		cmd, version string
		want         bool
	}{
		{"glueetl", "", true}, // unset runs on the 0.9 default
		{"glueetl", "0.9", true},
		{"glueetl", "1.0", true},
		{"glueetl", "2.0", true},
		{"glueetl", "3.0", false},
		{"glueetl", "5.0", false},
		{"pythonshell", "1.0", false},  // Glue.4 grades Spark jobs only
		{"glueetl", "garbage", false},  // unparsable is not a known-old version
		{"gluestreaming", "2.0", true}, // streaming jobs are Spark too
	} {
		require.Equal(t, tt.want, awsGlueJobUnsupportedVersion.Violates(job(tt.cmd, tt.version)), "%s %q", tt.cmd, tt.version)
	}
}

func TestFirehoseGradesOnlyDirectPut(t *testing.T) {
	stream := func(source, sse string) asset.Asset {
		return asset.Asset{Type: "firehose_delivery_stream", Provider: asset.ProviderAWS, Metadata: map[string]string{"source_type": source, "sse_status": sse}}
	}
	require.True(t, awsFirehoseNotEncrypted.Violates(stream("DirectPut", "ENABLING_FAILED")))
	require.False(t, awsFirehoseNotEncrypted.Violates(stream("DirectPut", "ENABLING")))
	// The record lives in the source stream; its own encryption is graded there.
	require.False(t, awsFirehoseNotEncrypted.Violates(stream("KinesisStreamAsSource", "DISABLED")))
	require.False(t, awsFirehoseNotEncrypted.Violates(stream("MSKAsSource", "DISABLED")))
}

func TestAthenaPrimaryWorkgroupGradedOnlyWhenUsed(t *testing.T) {
	wg := func(name string, md map[string]string) asset.Asset {
		return asset.Asset{Name: name, Type: "athena_workgroup", Provider: asset.ProviderAWS, Metadata: md}
	}
	off := map[string]string{"cloudwatch_metrics_enabled": "false"}
	require.True(t, awsAthenaWorkgroupNoMetrics.Violates(wg("analytics", off)))
	require.False(t, awsAthenaWorkgroupNoMetrics.Violates(wg("primary", off)), "unread history is not evidence the stock workgroup is used")
	require.False(t, awsAthenaWorkgroupNoMetrics.Violates(wg("primary", map[string]string{"cloudwatch_metrics_enabled": "false", "has_query_history": "false"})))
	require.True(t, awsAthenaWorkgroupNoMetrics.Violates(wg("primary", map[string]string{"cloudwatch_metrics_enabled": "false", "has_query_history": "true"})))
}

// An unread queue/topic policy must hold an open public-policy finding open:
// with no probe for the confirmed tier the predicate's silence on an absent
// public_access would count as an observation and close it as fixed.
func TestQueueTopicPolicyChecksNotEvaluableWithoutPolicy(t *testing.T) {
	reg := Default()
	for id, typ := range map[string]string{"aws-sqs-queue-policy-public": "sqs_queue", "aws-sns-topic-policy-public": "sns_topic"} {
		c, ok := reg.ByID(id)
		require.True(t, ok)
		unread := asset.Asset{Type: typ, Provider: asset.ProviderAWS, Metadata: map[string]string{}}
		require.False(t, c.Evaluable(unread), id)
		read := asset.Asset{Type: typ, Provider: asset.ProviderAWS, Metadata: map[string]string{"public_access": asset.PublicAccessNone}}
		require.True(t, c.Evaluable(read), id)
	}
}
