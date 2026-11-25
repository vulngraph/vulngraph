package checks

// aws_msk.go — Amazon MSK cluster and MSK Connect connector posture (FSBP
// MSK.1, MSK.3-6) from kafka:ListClustersV2 and kafkaconnect:ListConnectors.
// Serverless clusters always use IAM authentication and TLS and cannot be
// made public, so the collector writes none of the graded keys for them.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsMSKChecks() []Check {
	return []Check{
		awsMSKInClusterPlaintext,
		awsMSKPublicAccess,
		awsMSKUnauthenticatedAccess,
		awsMSKConnectorPlaintext,
		awsMSKConnectorNoLogging,
	}
}

var awsMSKInClusterPlaintext = Check{
	ID:          "aws-msk-in-cluster-plaintext",
	Title:       "MSK cluster brokers replicate in plaintext",
	Description: "Encryption in transit within the cluster is off, so replication traffic between brokers — every message on every topic — crosses the VPC unencrypted. FSBP MSK.1.",
	Remediation: "In-cluster encryption is fixed at creation. Console: MSK → Create cluster with \"Encrypt data in transit within the cluster\" enabled, then mirror topics to it (MirrorMaker 2 / MSK Replicator) and move clients. CLI: `aws kafka create-cluster-v2 --cluster-name NEW --provisioned '{\"EncryptionInfo\":{\"EncryptionInTransit\":{\"InCluster\":true,\"ClientBroker\":\"TLS\"}},...}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "msk_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["in_cluster_encryption"] == "false" },
}

// mskPublic reports brokers with an observed public-access type other than
// DISABLED (SERVICE_PROVIDED_EIPS today).
func mskPublic(a asset.Asset) bool {
	v := a.Metadata["public_access_type"]
	return v != "" && v != "DISABLED"
}

var awsMSKPublicAccess = Check{
	ID:          "aws-msk-public-access",
	Title:       "MSK cluster brokers are publicly accessible",
	Description: "Public access is turned on, so the brokers have public IP addresses and accept connections from the internet. AWS only allows this with client authentication (IAM, SASL/SCRAM or mutual TLS) in place, so it is reachability behind credentials, graded Medium; brokers that are public AND allow unauthenticated clients let anyone on the internet read and write every topic, graded Critical. FSBP MSK.4.",
	Remediation: "Console: MSK → the cluster → Properties → Network settings → Edit public access → Off, and reach the brokers through the VPC, VPC peering or PrivateLink. CLI: `aws kafka update-connectivity --cluster-arn ARN --current-version VERSION --connectivity-info '{\"PublicAccess\":{\"Type\":\"DISABLED\"}}'`.",
	Type:        "exposure",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "msk_cluster",
	Violates:    mskPublic,
	SeverityFor: tieredExposureSeverity(finding.SeverityCritical, finding.SeverityMedium),
	TitleFor: tieredExposureTitle(
		"MSK cluster brokers are public and accept unauthenticated clients",
		"MSK cluster brokers are publicly accessible"),
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"public_access_type":     a.Metadata["public_access_type"],
			"unauthenticated_access": a.Metadata["unauthenticated_access"],
		}
	},
}

// awsMSKUnauthenticatedAccess does not step aside for aws-msk-public-access:
// AWS refuses public access while unauthenticated access is on, so on a live
// cluster the two describe different settings, each its own fix.
var awsMSKUnauthenticatedAccess = Check{
	ID:          "aws-msk-unauthenticated-access",
	Title:       "MSK cluster allows unauthenticated clients",
	Description: "Unauthenticated access is enabled (or no client authentication mechanism is configured), so any client that can reach the brokers can produce, consume and delete on every topic without credentials or ACLs that identify it. FSBP MSK.6.",
	Remediation: "Console: MSK → the cluster → Properties → Security settings → Edit → enable IAM role-based authentication (or SASL/SCRAM or TLS client authentication), move clients to it, then turn Unauthenticated access off. CLI: `aws kafka update-security --cluster-arn ARN --current-version VERSION --client-authentication '{\"Sasl\":{\"Iam\":{\"Enabled\":true}},\"Unauthenticated\":{\"Enabled\":false}}'`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "msk_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["unauthenticated_access"] == "true" },
}

var awsMSKConnectorPlaintext = Check{
	ID:          "aws-msk-connector-plaintext",
	Title:       "MSK Connect connector talks to its cluster in plaintext",
	Description: "The connector's encryption in transit to the Kafka cluster is PLAINTEXT, so the records it copies cross the network unencrypted. FSBP MSK.3.",
	Remediation: "Encryption is fixed at creation. Console: MSK → MSK Connect → Create connector with \"Encryption in transit\" TLS (the cluster must offer a TLS listener), then delete the old connector. CLI: `aws kafkaconnect create-connector ... --kafka-cluster-encryption-in-transit encryptionType=TLS`, then `aws kafkaconnect delete-connector --connector-arn ARN`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "msk_connector",
	Violates:    func(a asset.Asset) bool { return a.Metadata["encryption_in_transit_type"] == "PLAINTEXT" },
}

var awsMSKConnectorNoLogging = Check{
	ID:          "aws-msk-connector-no-logging",
	Title:       "MSK Connect connector has no log delivery",
	Description: "No worker log destination (CloudWatch Logs, S3 or Firehose) is enabled, so connector failures and the data movement it performs leave no record. FSBP MSK.5.",
	Remediation: "Log delivery is fixed at creation. Console: MSK → MSK Connect → Create connector with a log delivery destination, then delete the old connector. CLI: `aws kafkaconnect create-connector ... --log-delivery 'workerLogDelivery={cloudWatchLogs={enabled=true,logGroup=GROUP}}'`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "msk_connector",
	Violates:    func(a asset.Asset) bool { return a.Metadata["log_delivery_enabled"] == "false" },
}
