package checks

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// RDS region-wide event-notification coverage (FSBP RDS.19-22, one finding
// per region on aws_rds_settings) and the instance parameter-group TLS
// settings (FSBP RDS.41 SQL Server, RDS.44 MariaDB). All Low: notifications
// and in-transit enforcement inside a VPC are hygiene, not exposure.

func awsRDSSettingsChecks() []Check {
	return []Check{
		awsRDSClusterEventsNotSubscribed,
		awsRDSInstanceEventsNotSubscribed,
		awsRDSParameterGroupEventsNotSubscribed,
		awsRDSSecurityGroupEventsNotSubscribed,
		awsRDSSQLServerTLSNotEnforced,
		awsRDSMariaDBTLSNotEnforced,
		awsRDSPostgresTLSNotEnforced,
		awsRDSMySQLTLSNotEnforced,
	}
}

// FSBP passes a region with no event subscriptions at all: the controls grade
// the subscriptions that exist. Vulngraph additionally stays silent where the
// region holds no database emitting the events in question.
const rdsEventRemediation = "Console: RDS > Event subscriptions > Create event subscription > an SNS topic, the source type, all sources of that type, and all event categories (or at least the ones listed). CLI: `aws rds create-event-subscription --subscription-name NAME --sns-topic-arn TOPIC --source-type SOURCE_TYPE --event-categories CATEGORIES --enabled`."

var awsRDSClusterEventsNotSubscribed = Check{
	ID:          "aws-rds-cluster-events-not-subscribed",
	Title:       "No RDS event subscription covers critical cluster events",
	Description: "The region has RDS event subscriptions and DB clusters, but no enabled subscription delivers the maintenance and failure events of every cluster (source type db-cluster), so a failover or an outage of a cluster raises no notification. FSBP RDS.19.",
	Remediation: rdsEventRemediation + " Source type: db-cluster; categories: maintenance, failure.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_rds_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["has_event_subscriptions"] == "true" && a.Metadata["has_clusters"] == "true" &&
			a.Metadata["cluster_events_covered"] == "false"
	},
}

var awsRDSInstanceEventsNotSubscribed = Check{
	ID:          "aws-rds-instance-events-not-subscribed",
	Title:       "No RDS event subscription covers critical database instance events",
	Description: "The region has RDS event subscriptions and DB instances, but no enabled subscription delivers the maintenance, configuration change and failure events of every instance (source type db-instance). FSBP RDS.20.",
	Remediation: rdsEventRemediation + " Source type: db-instance; categories: maintenance, configuration change, failure.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_rds_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["has_event_subscriptions"] == "true" && a.Metadata["has_instances"] == "true" &&
			a.Metadata["instance_events_covered"] == "false"
	},
}

// rdsRegionHasDatabases reports a region holding DB instances or clusters.
func rdsRegionHasDatabases(a asset.Asset) bool {
	return a.Metadata["has_instances"] == "true" || a.Metadata["has_clusters"] == "true"
}

var awsRDSParameterGroupEventsNotSubscribed = Check{
	ID:          "aws-rds-parameter-group-events-not-subscribed",
	Title:       "No RDS event subscription covers parameter group changes",
	Description: "The region has RDS event subscriptions and databases, but no enabled subscription delivers configuration-change events for every DB parameter group, so a change that weakens TLS or auditing settings goes unannounced. FSBP RDS.21.",
	Remediation: rdsEventRemediation + " Source type: db-parameter-group; category: configuration change.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_rds_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["has_event_subscriptions"] == "true" && rdsRegionHasDatabases(a) &&
			a.Metadata["parameter_group_events_covered"] == "false"
	},
}

var awsRDSSecurityGroupEventsNotSubscribed = Check{
	ID:          "aws-rds-security-group-events-not-subscribed",
	Title:       "No RDS event subscription covers DB security group events",
	Description: "The region has RDS event subscriptions and databases, but no enabled subscription delivers configuration-change and failure events for every DB security group (source type db-security-group). FSBP RDS.22.",
	Remediation: rdsEventRemediation + " Source type: db-security-group; categories: configuration change, failure.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "aws_rds_settings",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["has_event_subscriptions"] == "true" && rdsRegionHasDatabases(a) &&
			a.Metadata["security_group_events_covered"] == "false"
	},
}

var awsRDSSQLServerTLSNotEnforced = Check{
	ID:          "aws-rds-sqlserver-tls-not-enforced",
	Title:       "RDS for SQL Server instance does not force TLS connections",
	Description: "The instance's DB parameter group leaves rds.force_ssl at 0 (the default), so clients may connect without encryption and send credentials and query results in clear. FSBP RDS.41.",
	Remediation: "Console: RDS > Parameter groups > a custom group for the instance > rds.force_ssl = 1, attach it and reboot. CLI: `aws rds modify-db-parameter-group --db-parameter-group-name GROUP --parameters ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=pending-reboot`, then `aws rds reboot-db-instance --db-instance-identifier ID`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["force_ssl"]
		return ok && strings.HasPrefix(a.Metadata["engine"], "sqlserver") && v != "1"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"rds.force_ssl": a.Metadata["force_ssl"], "db_parameter_group": a.Metadata["db_parameter_group"]}
	},
}

var awsRDSMariaDBTLSNotEnforced = Check{
	ID:          "aws-rds-mariadb-tls-not-enforced",
	Title:       "RDS for MariaDB instance does not require secure transport",
	Description: "The instance's DB parameter group leaves require_secure_transport OFF (the default), or the group is not yet applied (pending reboot), so clients may connect without TLS. FSBP RDS.44 (MariaDB 10.5 and later, where the parameter exists).",
	Remediation: "Console: RDS > Parameter groups > a custom group for the instance > require_secure_transport = ON, attach it and reboot. CLI: `aws rds modify-db-parameter-group --db-parameter-group-name GROUP --parameters ParameterName=require_secure_transport,ParameterValue=1,ApplyMethod=immediate`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["require_secure_transport"]
		if !ok || a.Metadata["engine"] != "mariadb" {
			return false
		}
		on := v == "1" || strings.EqualFold(v, "ON")
		return !on || a.Metadata["parameter_group_in_sync"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"require_secure_transport": a.Metadata["require_secure_transport"],
			"parameter_group_in_sync":  a.Metadata["parameter_group_in_sync"],
		}
	},
}

// rdsStandalone reports an instance outside any DB cluster: RDS.38 and RDS.39
// do not evaluate cluster members.
func rdsStandalone(a asset.Asset) bool {
	id, ok := a.Metadata["db_cluster_id"]
	return ok && id == ""
}

var awsRDSPostgresTLSNotEnforced = Check{
	ID:          "aws-rds-postgres-tls-not-enforced",
	Title:       "RDS for PostgreSQL instance does not force TLS connections",
	Description: "The instance's DB parameter group sets rds.force_ssl to 0, so clients may connect without encryption and send credentials and query results in clear. FSBP RDS.38 (instances outside a DB cluster). An unset value is left unknown: the default is 1 from PostgreSQL 15 and 0 before it.",
	Remediation: "Console: RDS > Parameter groups > a custom group for the instance > rds.force_ssl = 1, attach it. CLI: `aws rds modify-db-parameter-group --db-parameter-group-name GROUP --parameters ParameterName=rds.force_ssl,ParameterValue=1,ApplyMethod=immediate`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["force_ssl"]
		return ok && a.Metadata["engine"] == "postgres" && rdsStandalone(a) && v == "0"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"rds.force_ssl": a.Metadata["force_ssl"], "db_parameter_group": a.Metadata["db_parameter_group"]}
	},
}

var awsRDSMySQLTLSNotEnforced = Check{
	ID:          "aws-rds-mysql-tls-not-enforced",
	Title:       "RDS for MySQL instance does not require secure transport",
	Description: "The instance's DB parameter group sets require_secure_transport to 0 (OFF), so clients may connect without TLS. FSBP RDS.39 (instances outside a DB cluster). An unset value is left unknown: the default differs across MySQL major versions.",
	Remediation: "Console: RDS > Parameter groups > a custom group for the instance > require_secure_transport = 1, attach it. CLI: `aws rds modify-db-parameter-group --db-parameter-group-name GROUP --parameters ParameterName=require_secure_transport,ParameterValue=1,ApplyMethod=immediate`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "rds_instance",
	Violates: func(a asset.Asset) bool {
		v, ok := a.Metadata["require_secure_transport"]
		return ok && a.Metadata["engine"] == "mysql" && rdsStandalone(a) && (v == "0" || strings.EqualFold(v, "OFF"))
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"require_secure_transport": a.Metadata["require_secure_transport"], "db_parameter_group": a.Metadata["db_parameter_group"]}
	},
}
