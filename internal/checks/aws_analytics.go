package checks

// aws_analytics.go — streaming, messaging and analytics posture: SQS and
// Kinesis encryption at rest, Kinesis retention, Data Firehose SSE, Glue job
// versions and ML transform encryption, Athena workgroup metrics (FSBP SQS.1,
// Kinesis.1/3, DataFirehose.1, Glue.3/4, Athena.4). None of these is an
// exposure on its own — whoever can read the data still needs IAM access —
// so they sit at Low.

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsAnalyticsChecks() []Check {
	return []Check{
		awsSQSNotEncrypted,
		awsKinesisStreamNotEncrypted,
		awsKinesisStreamShortRetention,
		awsFirehoseNotEncrypted,
		awsGlueMLTransformNotEncrypted,
		awsGlueJobUnsupportedVersion,
		awsAthenaWorkgroupNoMetrics,
	}
}

var awsSQSNotEncrypted = Check{
	ID:          "aws-sqs-not-encrypted",
	Title:       "SQS queue is not encrypted at rest",
	Description: "The queue has neither SSE-SQS nor SSE-KMS server-side encryption, so messages are stored unencrypted on the service's disks. FSBP SQS.1.",
	Remediation: "Console: SQS → the queue → Edit → Encryption → enable server-side encryption (SSE-SQS, or SSE-KMS with a customer managed key). CLI: `aws sqs set-queue-attributes --queue-url URL --attributes SqsManagedSseEnabled=true` (or `KmsMasterKeyId=KEY_ARN`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "sqs_queue",
	Violates:    func(a asset.Asset) bool { return a.Metadata["sse"] == "none" },
}

var awsKinesisStreamNotEncrypted = Check{
	ID:          "aws-kinesis-stream-not-encrypted",
	Title:       "Kinesis data stream is not encrypted at rest",
	Description: "Server-side encryption is off (EncryptionType NONE), so records are stored unencrypted for the stream's whole retention period. FSBP Kinesis.1.",
	Remediation: "Console: Kinesis → Data streams → the stream → Configuration → Encryption → Edit → enable server-side encryption. CLI: `aws kinesis start-stream-encryption --stream-name NAME --encryption-type KMS --key-id alias/aws/kinesis`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "kinesis_stream",
	Violates:    func(a asset.Asset) bool { return a.Metadata["encryption_type"] == "NONE" },
}

// kinesisMinRetentionHours is FSBP Kinesis.3's default minimum (seven days).
const kinesisMinRetentionHours = 168

var awsKinesisStreamShortRetention = Check{
	ID:          "aws-kinesis-stream-short-retention",
	Title:       "Kinesis data stream retains records for less than 7 days",
	Description: "The stream keeps records for fewer than 168 hours, so a consumer outage or a bad deploy longer than that loses data that can no longer be replayed. FSBP Kinesis.3.",
	Remediation: "Console: Kinesis → the stream → Configuration → Data retention → Edit. CLI: `aws kinesis increase-stream-retention-period --stream-name NAME --retention-period-hours 168`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "kinesis_stream",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["retention_hours"])
		return err == nil && n < kinesisMinRetentionHours
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"retention_hours": a.Metadata["retention_hours"]}
	},
}

var awsFirehoseNotEncrypted = Check{
	ID:          "aws-firehose-not-encrypted",
	Title:       "Data Firehose stream is not encrypted at rest",
	Description: "Server-side encryption is not enabled on this Direct PUT delivery stream, so buffered records are stored unencrypted before delivery. Streams fed by a Kinesis data stream or MSK do not store records themselves and are graded on their source instead (aws-kinesis-stream-not-encrypted). FSBP DataFirehose.1.",
	Remediation: "Console: Amazon Data Firehose → the stream → Configuration → Server-side encryption → Edit → enable. CLI: `aws firehose start-delivery-stream-encryption --delivery-stream-name NAME --delivery-stream-encryption-configuration-input KeyType=AWS_OWNED_CMK`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "firehose_delivery_stream",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["source_type"] != "DirectPut" {
			return false
		}
		switch a.Metadata["sse_status"] {
		case "DISABLED", "ENABLING_FAILED":
			return true
		}
		return false
	},
}

var awsGlueMLTransformNotEncrypted = Check{
	ID:          "aws-glue-ml-transform-not-encrypted",
	Title:       "Glue machine learning transform is not encrypted at rest",
	Description: "The transform's user data (labels and training data Glue keeps for it) is not encrypted with KMS. FSBP Glue.3.",
	Remediation: "Console: AWS Glue → Data Integration and ETL → Record matching (ML transforms) → the transform → Edit → Security configuration → enable user data encryption with a KMS key. CLI: `aws glue update-ml-transform --transform-id ID --transform-encryption 'MlUserDataEncryption={MlUserDataEncryptionMode=SSE-KMS,KmsKeyId=KEY_ARN}'` (or recreate the transform with it).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "glue_ml_transform",
	Violates:    func(a asset.Asset) bool { return a.Metadata["user_data_encryption"] == "DISABLED" },
}

// glueMinSupportedVersion is FSBP Glue.4's fixed minimumSupportedGlueVersion.
const glueMinSupportedVersion = 3.0

// glueVersionUnsupported reports a Spark job version below the minimum. An
// unset version runs on Glue's default 0.9, which the control fails too.
func glueVersionUnsupported(v string) bool {
	if v == "" {
		return true
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	return err == nil && f < glueMinSupportedVersion
}

// glueSparkCommand reports a Glue for Spark job: batch ETL (glueetl) or Spark
// streaming (gluestreaming). Python shell and Ray jobs version separately.
func glueSparkCommand(command string) bool {
	return command == "glueetl" || command == "gluestreaming"
}

var awsGlueJobUnsupportedVersion = Check{
	ID:          "aws-glue-job-unsupported-version",
	Title:       "Glue Spark job runs on an unsupported Glue version",
	Description: "This Glue for Spark job (glueetl batch or gluestreaming) runs on a Glue version earlier than 3.0 — or sets none, so it runs on the 0.9 default. Those versions are past end of support and no longer receive the Spark, Python and connector security fixes later versions carry. FSBP Glue.4.",
	Remediation: "Console: AWS Glue → ETL jobs → the job → Job details → Glue version → 4.0 or later, then test the script (see AWS's Glue 4.0/5.0 migration guides). CLI: `aws glue update-job --job-name NAME --job-update '{\"GlueVersion\":\"5.0\",\"Role\":\"ROLE\",\"Command\":{...}}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "glue_job",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["glue_version"]
		return ok && glueSparkCommand(a.Metadata["command"]) && glueVersionUnsupported(v)
	},
	TableProbes: []string{"2.0", "glueetl"},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"glue_version": a.Metadata["glue_version"]}
	},
}

var awsAthenaWorkgroupNoMetrics = Check{
	ID:          "aws-athena-workgroup-no-metrics",
	Title:       "Athena workgroup does not publish query metrics to CloudWatch",
	Description: "The workgroup does not publish query metrics to CloudWatch, so query volume, failures and data scanned leave no monitored record. The stock primary workgroup is graded only once a query has run in it, so an account that never uses Athena is not reported in every region. FSBP Athena.4.",
	Remediation: "Console: Athena → Workgroups → the workgroup → Edit → Settings → enable \"Publish query metrics to AWS CloudWatch\". CLI: `aws athena update-work-group --work-group NAME --configuration-updates PublishCloudWatchMetricsEnabled=true`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "athena_workgroup",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["cloudwatch_metrics_enabled"] == "false" &&
			(a.Name != "primary" || a.Metadata["has_query_history"] == "true")
	},
}
