package azure

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

func diagSettings(t *testing.T, raw string) []*armmonitor.DiagnosticSettingsResource {
	t.Helper()
	var l armmonitor.DiagnosticSettingsResourceCollection
	require.NoError(t, json.Unmarshal([]byte(raw), &l))
	return l.Value
}

func TestActivityLogSettings(t *testing.T) {
	partial := diagSettings(t, `{"value":[{"name":"to-law","properties":{
		"workspaceId":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law",
		"logs":[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},
			{"category":"Alert","enabled":false},{"category":"Policy","enabled":true},{"category":"ServiceHealth","enabled":true}]}}]}`)
	md := activityLogSettings(partial)
	require.Equal(t, "1", md["activity_log_diagnostic_setting_count"])
	require.Equal(t, "Alert", md["activity_log_categories_missing"])

	all := diagSettings(t, `{"value":[{"name":"all","properties":{
		"storageAccountId":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st",
		"logs":[{"categoryGroup":"allLogs","enabled":true}]}}]}`)
	require.Equal(t, "", activityLogSettings(all)["activity_log_categories_missing"], "allLogs captures every category")

	none := activityLogSettings(nil)
	require.Equal(t, "0", none["activity_log_diagnostic_setting_count"], "no setting is an observed zero")

	disabledOnly := diagSettings(t, `{"value":[{"name":"off","properties":{"workspaceId":"/w","logs":[{"category":"Administrative","enabled":false}]}}]}`)
	require.Equal(t, "0", activityLogSettings(disabledOnly)["activity_log_diagnostic_setting_count"], "a setting exporting nothing does not count")
}

func TestStorageUsesCMKAndTableRetention(t *testing.T) {
	require.True(t, storageUsesCMK(armstorage.Account{Properties: &armstorage.AccountProperties{
		Encryption: &armstorage.Encryption{KeySource: to.Ptr(armstorage.KeySourceMicrosoftKeyvault)}}}))
	require.False(t, storageUsesCMK(armstorage.Account{Properties: &armstorage.AccountProperties{
		Encryption: &armstorage.Encryption{KeySource: to.Ptr(armstorage.KeySourceMicrosoftStorage)}}}))
	require.False(t, storageUsesCMK(armstorage.Account{}))

	var tbl armoperationalinsights.Table
	require.NoError(t, json.Unmarshal([]byte(`{"name":"AzureActivity","properties":{"retentionInDays":30,"totalRetentionInDays":365,"archiveRetentionInDays":335}}`), &tbl))
	require.Equal(t, int32(365), tableRetentionDays(tbl), "total retention includes the archive tier")
	var plain armoperationalinsights.Table
	require.NoError(t, json.Unmarshal([]byte(`{"name":"AzureActivity","properties":{"retentionInDays":90}}`), &plain))
	require.Equal(t, int32(90), tableRetentionDays(plain))
	require.Equal(t, int32(-1), tableRetentionDays(armoperationalinsights.Table{}))
}

func TestActivityAlertSettings(t *testing.T) {
	var l armmonitor.AlertRuleList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[
		{"name":"policy-write","properties":{"enabled":true,"scopes":["/subscriptions/S1"],"condition":{"allOf":[
			{"field":"category","equals":"Administrative"},
			{"field":"operationName","equals":"Microsoft.Authorization/policyAssignments/write"}]}}},
		{"name":"nsg-anyof","properties":{"scopes":["/subscriptions/s1"],"condition":{"allOf":[
			{"field":"category","equals":"Administrative"},
			{"anyOf":[{"field":"operationName","equals":"Microsoft.Network/networkSecurityGroups/write"},
				{"field":"operationName","equals":"Microsoft.Network/networkSecurityGroups/delete"}]}]}}},
		{"name":"disabled","properties":{"enabled":false,"scopes":["/subscriptions/s1"],"condition":{"allOf":[
			{"field":"category","equals":"Administrative"},{"field":"operationName","equals":"Microsoft.Sql/servers/firewallRules/write"}]}}},
		{"name":"rg-only","properties":{"enabled":true,"scopes":["/subscriptions/s1/resourceGroups/rg"],"condition":{"allOf":[
			{"field":"category","equals":"Administrative"},{"field":"operationName","equals":"Microsoft.Network/publicIPAddresses/write"}]}}},
		{"name":"narrowed","properties":{"enabled":true,"scopes":["/subscriptions/s1"],"condition":{"allOf":[
			{"field":"category","equals":"Administrative"},{"field":"resourceGroup","equals":"rg"},
			{"field":"operationName","equals":"Microsoft.Network/publicIPAddresses/delete"}]}}},
		{"name":"secsol","properties":{"enabled":true,"scopes":["/subscriptions/s1"],"condition":{"allOf":[
			{"field":"category","equals":"Security"},{"field":"operationName","equals":"Microsoft.Security/securitySolutions/write"}]}}},
				{"name":"health","properties":{"enabled":true,"scopes":["/subscriptions/s1"],"condition":{"allOf":[
			{"field":"category","equals":"ServiceHealth"}]}}}]}`), &l))
	md := activityAlertSettings(l.Value, "s1")
	require.Equal(t, "administrative|microsoft.authorization/policyassignments/write,administrative|microsoft.network/networksecuritygroups/delete,"+
		"administrative|microsoft.network/networksecuritygroups/write,security|microsoft.security/securitysolutions/write",
		md["activity_alert_operations"], "disabled, resource-group-scoped and narrowed alerts do not count")
	require.Equal(t, "", md["activity_alert_whole_categories"])
	require.Equal(t, "true", md["activity_alert_service_health"])

	var wide armmonitor.AlertRuleList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[{"name":"everything","properties":{"scopes":["/subscriptions/s1/"],
		"condition":{"allOf":[{"field":"category","equals":"Administrative"}]}}}]}`), &wide))
	md = activityAlertSettings(wide.Value, "s1")
	require.Equal(t, "administrative", md["activity_alert_whole_categories"])
	require.Equal(t, "false", md["activity_alert_service_health"])

	empty := activityAlertSettings(nil, "s1")
	require.Equal(t, "", empty["activity_alert_operations"], "no alerts is an observed none")
}

func TestResourceLoggingSettings(t *testing.T) {
	res := collect.Result{Assets: []asset.Asset{
		{ID: "/nsg/logged", Name: "logged", Type: "security_group"},
		{ID: "/nsg/silent", Name: "silent", Type: "security_group"},
		{ID: "/vm/1", Name: "vm1", Type: "azure_vm"},
	}}
	for _, scope := range []struct {
		s string
		t []string
	}{
		{"s/network:nsgs", []string{"security_group"}},
		{"s/network:loadbalancers", []string{"load_balancer", "azure_app_gateway"}},
		{"s/appservice:webapps", []string{"azure_webapp"}},
		{"s/network:public-ips", []string{"azure_public_ip"}},
	} {
		res.MarkComplete(scope.s, scope.t, 1)
	}
	lister := func(_ context.Context, id string) ([]*armmonitor.DiagnosticSettingsResource, error) {
		if id == "/nsg/logged" {
			return diagSettings(t, `{"value":[{"name":"x","properties":{"workspaceId":"/w","logs":[{"categoryGroup":"allLogs","enabled":true}]}}]}`), nil
		}
		return nil, nil
	}
	md, err := resourceLoggingSettings(context.Background(), lister, res)
	require.NoError(t, err)
	require.Equal(t, "1", md["resources_without_diagnostic_settings_count"])
	require.Equal(t, "security_group:silent", md["resources_without_diagnostic_settings"])

	failing := func(context.Context, string) ([]*armmonitor.DiagnosticSettingsResource, error) {
		return nil, errors.New("throttled")
	}
	_, err = resourceLoggingSettings(context.Background(), failing, res)
	require.Error(t, err, "one failed read fails the rollup: a partial view is not 'every resource logs'")

	_, err = resourceLoggingSettings(context.Background(), lister, collect.Result{Assets: res.Assets})
	require.Error(t, err, "an incompletely listed type leaves the rollup unknown")
}
