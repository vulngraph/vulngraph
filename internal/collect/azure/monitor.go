package azure

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Azure Monitor subscription settings (CIS Azure 6.1.1.1–6.1.1.3, 6.1.2.x,
// 6.1.3.1): the activity-log diagnostic settings and where they send it,
// activity-log alerts, and Application Insights. All land on the subscription
// settings asset; each read that fails leaves only its own keys absent.

// cisActivityLogCategories are the activity-log categories CIS 6.1.1.2 requires
// a diagnostic setting to capture.
var cisActivityLogCategories = []string{"Administrative", "Alert", "Policy", "Security"}

func collectMonitor(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, sub *settingsAsset) {
	warn := func(read string, err error) {
		log.FromContext(ctx).Warn().Err(err).Str("read", read).Int("status", statusCode(err)).
			Msg("azure monitor read skipped; settings it backs are unknown")
	}
	if settings, err := activityLogDiagnosticSettings(ctx, cred, subscriptionID); err != nil {
		warn("activity log diagnostic settings", err)
	} else {
		sub.set(activityLogSettings(settings))
		if kv, err := activityLogStorageCMK(ctx, cred, settings); err != nil {
			warn("activity log storage encryption", err)
		} else {
			sub.set(kv)
		}
		if kv, err := activityLogRetention(ctx, cred, settings); err != nil {
			warn("activity log workspace retention", err)
		} else {
			sub.set(kv)
		}
	}
	if alerts, err := activityLogAlerts(ctx, cred, subscriptionID); err != nil {
		warn("activity log alerts", err)
	} else {
		sub.set(activityAlertSettings(alerts, subscriptionID))
	}
	if n, err := appInsightsComponents(ctx, cred, subscriptionID); err != nil {
		warn("application insights components", err)
	} else {
		sub.set(map[string]string{"app_insights_component_count": strconv.Itoa(n)})
	}
}

func activityLogDiagnosticSettings(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) ([]*armmonitor.DiagnosticSettingsResource, error) {
	c, err := armmonitor.NewDiagnosticSettingsClient(cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("activityLogDiagnosticSettings: %w", err)
	}
	return listDiagnosticSettings(ctx, c, "/subscriptions/"+subscriptionID)
}

// listDiagnosticSettings reads every diagnostic setting on one resource (or
// the subscription, for the activity log).
func listDiagnosticSettings(ctx context.Context, c *armmonitor.DiagnosticSettingsClient, resourceURI string) ([]*armmonitor.DiagnosticSettingsResource, error) {
	var out []*armmonitor.DiagnosticSettingsResource
	pager := c.NewListPager(resourceURI, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listDiagnosticSettings: %w", err)
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// exportingSettings keeps the diagnostic settings that send at least one
// enabled log category to a destination.
func exportingSettings(settings []*armmonitor.DiagnosticSettingsResource) []*armmonitor.DiagnosticSettings {
	var out []*armmonitor.DiagnosticSettings
	for _, s := range settings {
		if s == nil || s.Properties == nil || !hasDestination(s.Properties) {
			continue
		}
		for _, l := range s.Properties.Logs {
			if l != nil && l.Enabled != nil && *l.Enabled {
				out = append(out, s.Properties)
				break
			}
		}
	}
	return out
}

func hasDestination(p *armmonitor.DiagnosticSettings) bool {
	return strVal(p.WorkspaceID) != "" || strVal(p.StorageAccountID) != "" ||
		strVal(p.EventHubAuthorizationRuleID) != "" || strVal(p.MarketplacePartnerID) != ""
}

// enabledCategories is the union of enabled log categories across settings;
// a category group ("allLogs", "audit") is recorded as "group:<name>".
func enabledCategories(settings []*armmonitor.DiagnosticSettings) map[string]struct{} {
	cats := set()
	for _, p := range settings {
		for _, l := range p.Logs {
			if l == nil || l.Enabled == nil || !*l.Enabled {
				continue
			}
			if c := strVal(l.Category); c != "" {
				cats[strings.ToLower(c)] = struct{}{}
			}
			if g := strVal(l.CategoryGroup); g != "" {
				cats["group:"+strings.ToLower(g)] = struct{}{}
			}
		}
	}
	return cats
}

// activityLogSettings renders CIS 6.1.1.1 (a setting exports the activity log)
// and 6.1.1.2 (the required categories are captured, by name or through the
// allLogs group).
func activityLogSettings(settings []*armmonitor.DiagnosticSettingsResource) map[string]string {
	exporting := exportingSettings(settings)
	cats := enabledCategories(exporting)
	var missing []string
	if _, all := cats["group:alllogs"]; !all {
		for _, c := range cisActivityLogCategories {
			if _, ok := cats[strings.ToLower(c)]; !ok {
				missing = append(missing, c)
			}
		}
	}
	return map[string]string{
		"activity_log_diagnostic_setting_count": strconv.Itoa(len(exporting)),
		"activity_log_categories_missing":       strings.Join(missing, ","),
	}
}

// activityLogStorageCMK renders CIS 6.1.1.3: the storage accounts receiving
// the activity log that are not encrypted with a customer-managed key. One
// GetProperties per destination account (normally one); any failed read
// leaves the key absent.
func activityLogStorageCMK(ctx context.Context, cred azcore.TokenCredential, settings []*armmonitor.DiagnosticSettingsResource) (map[string]string, error) {
	accounts := set()
	for _, p := range exportingSettings(settings) {
		if id := strVal(p.StorageAccountID); id != "" {
			accounts[id] = struct{}{}
		}
	}
	var noCMK []string
	for _, id := range sortedKeys(accounts) {
		c, err := armstorage.NewAccountsClient(subscriptionOf(id), cred, readOnlyARM())
		if err != nil {
			return nil, fmt.Errorf("activityLogStorageCMK: %w", err)
		}
		resp, err := c.GetProperties(ctx, resourceGroup(id), lastSegment(id), nil)
		if err != nil {
			return nil, fmt.Errorf("activityLogStorageCMK: %s: %w", id, err)
		}
		if !storageUsesCMK(resp.Account) {
			noCMK = append(noCMK, lastSegment(id))
		}
	}
	return map[string]string{"activity_log_storage_without_cmk": joinNames(noCMK)}, nil
}

func storageUsesCMK(a armstorage.Account) bool {
	p := a.Properties
	return p != nil && p.Encryption != nil && p.Encryption.KeySource != nil &&
		*p.Encryption.KeySource == armstorage.KeySourceMicrosoftKeyvault
}

// activityLogRetention renders how long the activity log is kept when it goes
// only to Log Analytics: the longest AzureActivity table retention among the
// destination workspaces. A storage account or event hub destination keeps
// the log outside Log Analytics' retention, so then nothing is claimed.
func activityLogRetention(ctx context.Context, cred azcore.TokenCredential, settings []*armmonitor.DiagnosticSettingsResource) (map[string]string, error) {
	workspaces := set()
	for _, p := range exportingSettings(settings) {
		if strVal(p.StorageAccountID) != "" || strVal(p.EventHubAuthorizationRuleID) != "" || strVal(p.MarketplacePartnerID) != "" {
			return nil, nil
		}
		if id := strVal(p.WorkspaceID); id != "" {
			workspaces[id] = struct{}{}
		}
	}
	if len(workspaces) == 0 {
		return nil, nil
	}
	longest := int32(0)
	for _, id := range sortedKeys(workspaces) {
		c, err := armoperationalinsights.NewTablesClient(subscriptionOf(id), cred, readOnlyARM())
		if err != nil {
			return nil, fmt.Errorf("activityLogRetention: %w", err)
		}
		resp, err := c.Get(ctx, resourceGroup(id), lastSegment(id), "AzureActivity", nil)
		if err != nil {
			return nil, fmt.Errorf("activityLogRetention: %s: %w", id, err)
		}
		days := tableRetentionDays(resp.Table)
		if days < 0 {
			return nil, fmt.Errorf("activityLogRetention: %s: no retention in response", id)
		}
		longest = max(longest, days)
	}
	return map[string]string{"activity_log_retention_days": strconv.Itoa(int(longest))}, nil
}

// tableRetentionDays is the table's total retention (interactive + archive),
// or -1 when the response carries none.
func tableRetentionDays(t armoperationalinsights.Table) int32 {
	p := t.Properties
	if p == nil {
		return -1
	}
	if p.TotalRetentionInDays != nil && *p.TotalRetentionInDays > 0 {
		return *p.TotalRetentionInDays
	}
	if p.RetentionInDays != nil && *p.RetentionInDays > 0 {
		return *p.RetentionInDays
	}
	return -1
}

func activityLogAlerts(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) ([]*armmonitor.ActivityLogAlertResource, error) {
	c, err := armmonitor.NewActivityLogAlertsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, fmt.Errorf("activityLogAlerts: %w", err)
	}
	var out []*armmonitor.ActivityLogAlertResource
	pager := c.NewListBySubscriptionIDPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("activityLogAlerts: %w", err)
		}
		out = append(out, page.Value...)
	}
	return out, nil
}

// alertNarrowingFields are condition fields that limit an alert to part of the
// subscription; such an alert does not watch the operation subscription-wide.
var alertNarrowingFields = map[string]bool{"resourcegroup": true, "resourceid": true, "caller": true}

// activityAlertSettings renders the activity-log alerts CIS 6.1.2.x asks for,
// as observed facts the check matches against its operation table: each
// watched operation as "category|operation" (category "" when the alert does
// not filter on one, so it matches any), the categories one alert watches in
// full (no operation filter), and whether a Service Health alert exists. Only
// enabled alerts (an omitted flag is the service default, enabled) whose
// scopes include the subscription count.
func activityAlertSettings(alerts []*armmonitor.ActivityLogAlertResource, subscriptionID string) map[string]string {
	subScope := strings.ToLower("/subscriptions/" + subscriptionID)
	ops := set()
	whole := set()
	serviceHealth := false
	for _, a := range alerts {
		if a == nil || a.Properties == nil || a.Properties.Condition == nil {
			continue
		}
		p := a.Properties
		if p.Enabled != nil && !*p.Enabled {
			continue
		}
		scoped := false
		for _, s := range p.Scopes {
			if s != nil && strings.ToLower(strings.TrimSuffix(*s, "/")) == subScope {
				scoped = true
			}
		}
		if !scoped {
			continue
		}
		category, alertOps, narrowed := alertCondition(p.Condition.AllOf)
		if narrowed {
			continue
		}
		category = strings.ToLower(category)
		switch {
		case category == "servicehealth":
			serviceHealth = true
		case len(alertOps) == 0 && category != "":
			whole[category] = struct{}{}
		default:
			for _, op := range alertOps {
				ops[category+"|"+op] = struct{}{}
			}
		}
	}
	return map[string]string{
		"activity_alert_operations":       strings.Join(sortedKeys(ops), ","),
		"activity_alert_whole_categories": strings.Join(sortedKeys(whole), ","),
		"activity_alert_service_health":   strconv.FormatBool(serviceHealth),
	}
}

// alertCondition flattens an alert's allOf: its category, the (lowercased)
// operation names it matches (equals, containsAny, or anyOf leaves), and
// whether any other leaf narrows it to part of the subscription.
func alertCondition(allOf []*armmonitor.AlertRuleAnyOfOrLeafCondition) (category string, ops []string, narrowed bool) {
	leaf := func(field string, equals *string, containsAny []*string) {
		switch f := strings.ToLower(field); {
		case f == "category":
			category = strVal(equals)
		case f == "operationname":
			if equals != nil {
				ops = append(ops, strings.ToLower(*equals))
			}
			for _, v := range containsAny {
				if v != nil {
					ops = append(ops, strings.ToLower(*v))
				}
			}
		case alertNarrowingFields[f]:
			narrowed = true
		}
	}
	for _, c := range allOf {
		if c == nil {
			continue
		}
		if c.Field != nil {
			leaf(*c.Field, c.Equals, c.ContainsAny)
		}
		for _, l := range c.AnyOf {
			if l != nil && l.Field != nil {
				leaf(*l.Field, l.Equals, l.ContainsAny)
			}
		}
	}
	return category, ops, narrowed
}

// appInsightsComponents counts Application Insights components (CIS 6.1.3.1).
func appInsightsComponents(ctx context.Context, cred azcore.TokenCredential, subscriptionID string) (int, error) {
	c, err := armapplicationinsights.NewComponentsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return 0, fmt.Errorf("appInsightsComponents: %w", err)
	}
	n := 0
	pager := c.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return 0, fmt.Errorf("appInsightsComponents: %w", err)
		}
		n += len(page.Value)
	}
	return n, nil
}

// subscriptionOf extracts the subscription ID from an ARM resource ID.
func subscriptionOf(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "subscriptions") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
