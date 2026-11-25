package checks

// aws_redshift.go — Amazon Redshift provisioned-cluster and Redshift
// Serverless posture (FSBP Redshift.1/2/3/4/6/7/8/10/15/18,
// RedshiftServerless.1/2/3/5/6). Exposure is graded the way
// aws-rds-publicly-accessible grades a database: a publicly accessible
// warehouse is internet-resolvable but still needs credentials, so it is the
// possible tier; the rest is hardening and operational hygiene at Low.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func awsRedshiftChecks() []Check {
	return []Check{
		awsRedshiftPubliclyAccessible,
		awsRedshiftPortWorldOpen,
		awsRedshiftNoTLS,
		awsRedshiftSnapshotRetentionShort,
		awsRedshiftAuditLoggingDisabled,
		awsRedshiftVersionUpgradeDisabled,
		awsRedshiftNoEnhancedVPCRouting,
		awsRedshiftDefaultAdminUsername,
		awsRedshiftNotEncrypted,
		awsRedshiftNoMultiAZ,
		awsRedshiftServerlessNoEnhancedVPCRouting,
		awsRedshiftServerlessNoTLS,
		awsRedshiftServerlessPubliclyAccessible,
		awsRedshiftServerlessDefaultAdminUsername,
		awsRedshiftServerlessNoLogExports,
	}
}

// redshiftDefaultPort is the port every Redshift cluster and workgroup is
// created on unless set otherwise.
const redshiftDefaultPort = "5439"

// redshiftPublicSeverity mirrors aws-rds-publicly-accessible: Low, Medium on
// the well-known default port automated scanners enumerate first.
func redshiftPublicSeverity(a asset.Asset) finding.Severity {
	if a.Metadata["port"] == redshiftDefaultPort {
		return finding.SeverityMedium
	}
	return finding.SeverityLow
}

var awsRedshiftPubliclyAccessible = Check{
	ID:          "aws-redshift-publicly-accessible",
	Title:       "Redshift cluster is publicly accessible",
	Description: "The cluster has PubliclyAccessible=true, so its endpoint resolves to a public IP. Connecting still needs database credentials and a security group that admits the client — network reachability, not unauthenticated exposure — so it is Low, or Medium on the default port 5439. A cluster whose security group also admits the whole internet on its port is reported once, by aws-redshift-port-world-open, at High. FSBP Redshift.1.",
	Remediation: "Console: Amazon Redshift → Clusters → the cluster → Actions → Modify publicly accessible setting → Disable. CLI: `aws redshift modify-cluster --cluster-identifier ID --no-publicly-accessible`. Reach it from inside the VPC (VPN, bastion, Redshift-managed VPC endpoint) instead.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["publicly_accessible"] == "true" && a.Metadata["port_world_open"] != "true"
	},
	SeverityFor: redshiftPublicSeverity,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"port": a.Metadata["port"], "endpoint": a.Metadata["endpoint"]}
	},
}

var awsRedshiftPortWorldOpen = Check{
	ID:          "aws-redshift-port-world-open",
	Title:       "Redshift cluster port is open to the internet",
	Description: "A security group attached to the cluster admits 0.0.0.0/0 or ::/0 on the cluster's port. On a publicly accessible cluster that puts the database listener in front of every password-guessing bot on the internet (High); on a private cluster the rule only reaches from networks routed into the VPC, so it is Low. The group itself may also carry aws-sg-open-high-risk-ports — that finding is about the rule wherever it applies; this one names the warehouse it exposes. FSBP Redshift.15.",
	Remediation: "Console: EC2 → Security Groups → each group in world_open_security_groups → Inbound rules → replace the 0.0.0.0/0 / ::/0 source on the cluster port with the client CIDRs or security groups that need it. CLI: `aws ec2 revoke-security-group-ingress --group-id SG --protocol tcp --port 5439 --cidr 0.0.0.0/0`, then `authorize-security-group-ingress` for the real sources.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["port_world_open"] == "true" },
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["publicly_accessible"] == "true" {
			return finding.SeverityHigh
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["publicly_accessible"] == "true" {
			return "Redshift cluster port is open to the internet"
		}
		return "Private Redshift cluster's security group admits 0.0.0.0/0 on its port"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"port":                       a.Metadata["port"],
			"world_open_security_groups": a.Metadata["world_open_security_groups"],
			"publicly_accessible":        a.Metadata["publicly_accessible"],
		}
	},
}

var awsRedshiftNoTLS = Check{
	ID:          "aws-redshift-no-tls",
	Title:       "Redshift cluster does not require TLS connections",
	Description: "The cluster's parameter group has require_ssl=false, so clients may connect in plain text and queries, results and credentials cross the network unencrypted. FSBP Redshift.2.",
	Remediation: "Console: Amazon Redshift → Configurations → Workload management → the parameter group (create a custom one if the cluster uses a default group) → Parameters → require_ssl = true, then reboot the cluster. CLI: `aws redshift modify-cluster-parameter-group --parameter-group-name GROUP --parameters ParameterName=require_ssl,ParameterValue=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["require_ssl"] == "false" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"parameter_group": a.Metadata["parameter_group"]}
	},
}

// redshiftMinSnapshotRetentionDays is FSBP Redshift.3's default MinRetentionPeriod.
const redshiftMinSnapshotRetentionDays = 7

var awsRedshiftSnapshotRetentionShort = Check{
	ID:          "aws-redshift-snapshot-retention-short",
	Title:       "Redshift cluster keeps automated snapshots for less than 7 days",
	Description: "Automated snapshots are off (retention 0) or kept for fewer than 7 days, so a dropped table, a bad load or a destructive change noticed late cannot be restored. FSBP Redshift.3.",
	Remediation: "Console: Amazon Redshift → the cluster → Actions → Modify → Backup → Automated snapshot retention period ≥ 7. CLI: `aws redshift modify-cluster --cluster-identifier ID --automated-snapshot-retention-period 7`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["automated_snapshot_retention"])
		return err == nil && n < redshiftMinSnapshotRetentionDays
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["automated_snapshot_retention"] == "0" {
			return "Redshift cluster has automated snapshots disabled"
		}
		return "Redshift cluster keeps automated snapshots for less than 7 days"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"automated_snapshot_retention_days": a.Metadata["automated_snapshot_retention"]}
	},
}

var awsRedshiftAuditLoggingDisabled = Check{
	ID:          "aws-redshift-audit-logging-disabled",
	Title:       "Redshift cluster audit logging is disabled",
	Description: "Database audit logging (connection, user and user-activity logs) is off, so logins and queries leave no durable record outside the cluster's short-lived system tables. FSBP Redshift.4.",
	Remediation: "Console: Amazon Redshift → the cluster → Properties → Database configurations → Edit audit logging → Turn on, to CloudWatch or an S3 bucket. CLI: `aws redshift enable-logging --cluster-identifier ID --log-destination-type cloudwatch --log-exports connectionlog userlog useractivitylog`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["audit_logging_enabled"] == "false" },
}

var awsRedshiftVersionUpgradeDisabled = Check{
	ID:          "aws-redshift-version-upgrade-disabled",
	Title:       "Redshift cluster does not allow automatic version upgrades",
	Description: "AllowVersionUpgrade is off, so engine updates — including security fixes — are applied only when someone upgrades by hand. FSBP Redshift.6.",
	Remediation: "Console: Amazon Redshift → the cluster → Maintenance → Edit → Allow version upgrade. CLI: `aws redshift modify-cluster --cluster-identifier ID --allow-version-upgrade`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["allow_version_upgrade"] == "false" },
}

var awsRedshiftNoEnhancedVPCRouting = Check{
	ID:          "aws-redshift-no-enhanced-vpc-routing",
	Title:       "Redshift cluster does not use enhanced VPC routing",
	Description: "COPY and UNLOAD traffic between the cluster and S3 or other data stores leaves the VPC, so security groups, endpoint policies and VPC flow logs cannot control or record it. FSBP Redshift.7.",
	Remediation: "Console: Amazon Redshift → the cluster → Properties → Network and security → Edit → Enhanced VPC routing → Turn on (add S3 gateway/interface endpoints first). CLI: `aws redshift modify-cluster --cluster-identifier ID --enhanced-vpc-routing`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["enhanced_vpc_routing"] == "false" },
}

var awsRedshiftDefaultAdminUsername = Check{
	ID:          "aws-redshift-default-admin-username",
	Title:       "Redshift cluster uses the default admin username",
	Description: "The cluster's admin user is awsuser, the console default, which hands a password-guessing attack half of the credential. FSBP Redshift.8.",
	Remediation: "The admin username cannot be changed in place. Create a new superuser with a custom name, move automation to it and disable or restrict awsuser; for a clean fix, restore a snapshot into a new cluster with a custom `--master-username` (`aws redshift restore-from-cluster-snapshot` then rename users).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return strings.EqualFold(a.Metadata["master_username"], "awsuser") },
}

var awsRedshiftNotEncrypted = Check{
	ID:          "aws-redshift-not-encrypted",
	Title:       "Redshift cluster is not encrypted at rest",
	Description: "The cluster's data blocks, metadata and snapshots are stored unencrypted, so anyone who obtains a snapshot or the underlying storage reads the warehouse in clear. FSBP Redshift.10.",
	Remediation: "Console: Amazon Redshift → the cluster → Actions → Modify → Database configurations → Encryption → Use AWS KMS (the cluster is migrated in place). CLI: `aws redshift modify-cluster --cluster-identifier ID --encrypted --kms-key-id KEY_ARN`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["encrypted"] == "false" },
}

var awsRedshiftNoMultiAZ = Check{
	ID:          "aws-redshift-no-multi-az",
	Title:       "Redshift cluster is not deployed Multi-AZ",
	Description: "The cluster runs in a single Availability Zone, so an AZ outage takes the warehouse down until it is relocated or restored. Multi-AZ requires RA3 node types. FSBP Redshift.18.",
	Remediation: "Console: Amazon Redshift → the cluster → Actions → Activate Multi-AZ (RA3 only; resize dc2 clusters to RA3 first). CLI: `aws redshift modify-cluster --cluster-identifier ID --multi-az`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_cluster",
	Violates:    func(a asset.Asset) bool { return a.Metadata["multi_az"] == "false" },
}

var awsRedshiftServerlessNoEnhancedVPCRouting = Check{
	ID:          "aws-redshift-serverless-no-enhanced-vpc-routing",
	Title:       "Redshift Serverless workgroup does not use enhanced VPC routing",
	Description: "COPY and UNLOAD traffic from the workgroup leaves the VPC, so security groups, endpoint policies and VPC flow logs cannot control or record it. FSBP RedshiftServerless.1.",
	Remediation: "Console: Amazon Redshift Serverless → Workgroup configuration → the workgroup → Network and security → Edit → Turn on enhanced VPC routing. CLI: `aws redshift-serverless update-workgroup --workgroup-name NAME --enhanced-vpc-routing`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_serverless_workgroup",
	Violates:    func(a asset.Asset) bool { return a.Metadata["enhanced_vpc_routing"] == "false" },
}

var awsRedshiftServerlessNoTLS = Check{
	ID:          "aws-redshift-serverless-no-tls",
	Title:       "Redshift Serverless workgroup does not require TLS connections",
	Description: "The workgroup's require_ssl parameter is false, so clients may connect in plain text. FSBP RedshiftServerless.2.",
	Remediation: "Console: Amazon Redshift Serverless → the workgroup → Data access → Edit → require_ssl = true. CLI: `aws redshift-serverless update-workgroup --workgroup-name NAME --config-parameters parameterKey=require_ssl,parameterValue=true`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_serverless_workgroup",
	Violates:    func(a asset.Asset) bool { return a.Metadata["require_ssl"] == "false" },
}

var awsRedshiftServerlessPubliclyAccessible = Check{
	ID:          "aws-redshift-serverless-publicly-accessible",
	Title:       "Redshift Serverless workgroup is publicly accessible",
	Description: "Public access is on, so Redshift gives the workgroup an Elastic IP reachable from outside the VPC. Connecting still needs credentials and a permissive security group, so it is Low, or Medium on the default port 5439. FSBP RedshiftServerless.3.",
	Remediation: "Console: Amazon Redshift Serverless → the workgroup → Network and security → Edit → turn off Publicly accessible. CLI: `aws redshift-serverless update-workgroup --workgroup-name NAME --no-publicly-accessible`.",
	Type:        "exposure",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_serverless_workgroup",
	Violates:    func(a asset.Asset) bool { return a.Metadata["publicly_accessible"] == "true" },
	SeverityFor: redshiftPublicSeverity,
}

var awsRedshiftServerlessDefaultAdminUsername = Check{
	ID:          "aws-redshift-serverless-default-admin-username",
	Title:       "Redshift Serverless namespace uses the default admin username",
	Description: "The namespace's admin user is admin, the default, which hands a password-guessing attack half of the credential. FSBP RedshiftServerless.5.",
	Remediation: "Console: Amazon Redshift Serverless → the namespace → Actions → Edit admin credentials → set a custom username (and a new password). CLI: `aws redshift-serverless update-namespace --namespace-name NAME --admin-username NEW_NAME --manage-admin-password`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_serverless_namespace",
	Violates:    func(a asset.Asset) bool { return strings.EqualFold(a.Metadata["admin_username"], "admin") },
}

// redshiftServerlessRequiredLogs are the exports FSBP RedshiftServerless.6 requires.
var redshiftServerlessRequiredLogs = []string{"connectionlog", "userlog"}

// redshiftServerlessMissingLogs returns the required exports the namespace
// lacks, or nil when the export list was not read.
func redshiftServerlessMissingLogs(a asset.Asset) []string {
	raw, ok := a.Metadata["log_exports"]
	if !ok {
		return nil
	}
	have := strings.Split(raw, ",")
	var missing []string
	for _, t := range redshiftServerlessRequiredLogs {
		if !slices.Contains(have, t) {
			missing = append(missing, t)
		}
	}
	return missing
}

var awsRedshiftServerlessNoLogExports = Check{
	ID:          "aws-redshift-serverless-no-log-exports",
	Title:       "Redshift Serverless namespace does not export connection and user logs",
	Description: "The namespace does not export both its connection log and user log to CloudWatch Logs, so logins and user changes leave no durable record. FSBP RedshiftServerless.6.",
	Remediation: "Console: Amazon Redshift Serverless → the namespace → Security and encryption → Edit → Audit logging → export Connection log and User log. CLI: `aws redshift-serverless update-namespace --namespace-name NAME --log-exports connectionlog userlog useractivitylog`.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "redshift_serverless_namespace",
	Violates:    func(a asset.Asset) bool { return len(redshiftServerlessMissingLogs(a)) > 0 },
	TableProbes: redshiftServerlessRequiredLogs,
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"missing_log_types": strings.Join(redshiftServerlessMissingLogs(a), ",")}
	},
}
