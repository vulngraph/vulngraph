package checks

// azure_monitor.go — Azure Monitor subscription settings (CIS Azure
// Foundations 6.1.1.1–6.1.1.3, 6.1.2.1–6.1.2.11, 6.1.3.1, 6.1.4) on the
// azure_subscription settings asset (internal/collect/azure/monitor.go,
// resource_logging.go). Logging and alerting gaps are near-universally waived
// in practice, so every check here is Low or Info.

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func azureMonitorChecks() []Check {
	return []Check{
		azureActivityLogNotExported,
		azureActivityLogCategoriesMissing,
		azureActivityLogStorageNoCMK,
		azureActivityLogRetentionShort,
		azureActivityLogAlertsMissing,
		azureNoApplicationInsights,
		azureResourceLoggingDisabled,
	}
}

var azureActivityLogNotExported = Check{
	ID:          "azure-activity-log-not-exported",
	Title:       "Subscription activity log is not exported",
	Description: "No diagnostic setting sends the subscription's activity log anywhere. Azure keeps it for 90 days, after which every record of who created, changed or deleted resources is gone, and it cannot be queried alongside other logs.",
	Remediation: "Monitor → Activity log → Export Activity Logs → Add diagnostic setting: the Administrative, Alert, Policy and Security categories (or allLogs) to a Log Analytics workspace or storage account. CLI: `az monitor diagnostic-settings subscription create`.",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["activity_log_diagnostic_setting_count"] == "0" },
}

// azureActivityLogCategoriesMissing is CIS 6.1.1.2, asked only when some
// setting exports the log — none at all is azure-activity-log-not-exported.
var azureActivityLogCategoriesMissing = Check{
	ID:          "azure-activity-log-categories-missing",
	Title:       "Activity log export misses required categories",
	Description: "The subscription's activity-log diagnostic settings export the log but leave out one or more of the Administrative, Alert, Policy and Security categories, so those events expire after 90 days.",
	Remediation: "Edit the activity-log diagnostic setting (Monitor → Activity log → Export Activity Logs) and tick the listed categories, or use the allLogs category group.",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["activity_log_diagnostic_setting_count"])
		return err == nil && n > 0 && a.Metadata["activity_log_categories_missing"] != ""
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"missing_categories": a.Metadata["activity_log_categories_missing"]}
	},
}

var azureActivityLogStorageNoCMK = Check{
	ID:          "azure-activity-log-storage-no-cmk",
	Title:       "Activity log storage account is not encrypted with a customer-managed key",
	Description: "A storage account receiving the subscription activity log is encrypted with Microsoft-managed keys (CIS 6.1.1.3). A customer-managed key lets the organisation revoke access to the archived audit trail and audit every use of the key.",
	Remediation: "Storage account → Encryption → Customer-managed keys, with a key in a Key Vault that has purge protection on. CLI: `az storage account update --encryption-key-source Microsoft.Keyvault --encryption-key-vault <uri> --encryption-key-name <key>`.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["activity_log_storage_without_cmk"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"storage_accounts": a.Metadata["activity_log_storage_without_cmk"]}
	},
}

// activityLogMinRetentionDays: the activity log's own 90-day window. Exporting
// it only to keep it for less is no gain.
const activityLogMinRetentionDays = 90

// azureActivityLogRetentionShort has no CIS Azure v6 control (earlier CIS
// versions asked for 365 days). It is asked only when the activity log goes to
// Log Analytics alone, and reads the AzureActivity table's total retention.
var azureActivityLogRetentionShort = Check{
	ID:          "azure-activity-log-retention-short",
	Title:       "Exported activity log is kept for less than 90 days",
	Description: "The subscription activity log is exported only to Log Analytics, and the AzureActivity table keeps it (interactive plus archive retention) for less than 90 days — shorter than Azure itself keeps the activity log, so an investigation loses history sooner than with no export at all.",
	Remediation: "Log Analytics workspace → Tables → AzureActivity → Manage table: set total retention to at least 90 days (365 or more for audit needs), or also archive the activity log to a storage account.",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["activity_log_retention_days"])
		return err == nil && n < activityLogMinRetentionDays
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"retention_days": a.Metadata["activity_log_retention_days"]}
	},
}

// cisActivityAlertOperations is the CIS 6.1.2.1–6.1.2.10 operation list with
// the activity-log categories an alert may filter on and still see the event
// (CIS remediates the security-solution alerts with category Security); one
// evaluator matches the collected alerts against it, so a new operation is a
// row here, not a new check.
var cisActivityAlertOperations = []struct {
	control, operation string
	categories         []string
}{
	{"6.1.2.1", "microsoft.authorization/policyassignments/write", []string{"administrative"}},
	{"6.1.2.2", "microsoft.authorization/policyassignments/delete", []string{"administrative"}},
	{"6.1.2.3", "microsoft.network/networksecuritygroups/write", []string{"administrative"}},
	{"6.1.2.4", "microsoft.network/networksecuritygroups/delete", []string{"administrative"}},
	{"6.1.2.5", "microsoft.security/securitysolutions/write", []string{"security", "administrative"}},
	{"6.1.2.6", "microsoft.security/securitysolutions/delete", []string{"security", "administrative"}},
	{"6.1.2.7", "microsoft.sql/servers/firewallrules/write", []string{"administrative"}},
	{"6.1.2.8", "microsoft.sql/servers/firewallrules/delete", []string{"administrative"}},
	{"6.1.2.9", "microsoft.network/publicipaddresses/write", []string{"administrative"}},
	{"6.1.2.10", "microsoft.network/publicipaddresses/delete", []string{"administrative"}},
}

// missingActivityAlerts lists the CIS activity-log alerts the subscription
// lacks. An operation is watched by an alert on it with an accepted category
// or no category filter, or by an alert on a whole accepted category; Service
// Health (6.1.2.11) is its own category. Nil when the alerts were not read.
func missingActivityAlerts(a asset.Asset) []string {
	ops, ok := a.Metadata["activity_alert_operations"]
	if !ok {
		return nil
	}
	have := map[string]bool{}
	for _, op := range strings.Split(ops, ",") {
		have[op] = true
	}
	for _, c := range strings.Split(a.Metadata["activity_alert_whole_categories"], ",") {
		have[c+"|*"] = true
	}
	var missing []string
	for _, row := range cisActivityAlertOperations {
		watched := have["|"+row.operation]
		for _, c := range row.categories {
			watched = watched || have[c+"|"+row.operation] || have[c+"|*"]
		}
		if !watched {
			missing = append(missing, row.control+" "+row.operation)
		}
	}
	if a.Metadata["activity_alert_service_health"] == "false" {
		missing = append(missing, "6.1.2.11 ServiceHealth")
	}
	return missing
}

var azureActivityLogAlertsMissing = Check{
	ID:          "azure-activity-log-alerts-missing",
	Title:       "Activity-log alerts for security-relevant operations are missing",
	Description: "The subscription has no enabled, subscription-wide activity-log alert for some of the operations CIS lists: creating or deleting policy assignments, network security groups, security solutions, SQL firewall rules or public IP addresses, and Service Health events. Changes that open the network or switch off policy then happen without anyone being told. One finding lists every missing alert.",
	Remediation: "Monitor → Alerts → Create → Alert rule, scope the subscription, condition: Activity log signal for each listed operation (or a Service Health alert), with an action group that reaches the security team. CLI: `az monitor activity-log alert create --scope /subscriptions/<id> --condition category=Administrative and operationName=<operation>`.",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return len(missingActivityAlerts(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"missing_alerts": strings.Join(missingActivityAlerts(a), "; ")}
	},
}

// azureNoApplicationInsights is CIS 6.1.3.1, asked only of subscriptions that
// host App Service apps — with nothing to instrument it does not apply.
var azureNoApplicationInsights = Check{
	ID:          "azure-no-application-insights",
	Title:       "Subscription hosts App Service apps but no Application Insights",
	Description: "The subscription runs App Service apps but has no Application Insights component, so application requests, exceptions and dependency calls are not recorded for incident investigation.",
	Remediation: "Create an Application Insights resource (workspace-based) and enable it on the apps (App Service → Application Insights → Turn on). CLI: `az monitor app-insights component create`.",
	Type:        "logging",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates: func(a asset.Asset) bool {
		apps, err := strconv.Atoi(a.Metadata["app_service_count"])
		return err == nil && apps > 0 && a.Metadata["app_insights_component_count"] == "0"
	},
}

// azureResourceLoggingDisabled is CIS 6.1.4 as one subscription-wide finding:
// the fix is a subscription-wide diagnostic-settings policy, not one click per
// resource.
var azureResourceLoggingDisabled = Check{
	ID:          "azure-resource-logging-disabled",
	Title:       "Resources that emit resource logs have no diagnostic setting",
	Description: "Network security groups, application gateways, App Service apps or public IP addresses in the subscription have no diagnostic setting exporting their resource logs, so their data-plane activity is not retained. (Key Vault audit logging is its own check.) One finding lists the resources.",
	Remediation: "Assign the built-in Azure Policy initiative \"Enable allLogs category group resource logging for supported resources\" to the subscription with a Log Analytics destination, or add a diagnostic setting per resource (resource → Diagnostic settings → Add).",
	Type:        "logging",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["resources_without_diagnostic_settings_count"])
		return err == nil && n > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"count":     a.Metadata["resources_without_diagnostic_settings_count"],
			"resources": a.Metadata["resources_without_diagnostic_settings"],
		}
	},
}
