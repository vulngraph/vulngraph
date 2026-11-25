package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/stretchr/testify/require"
)

func TestPricingSettings(t *testing.T) {
	// A Microsoft.Security/pricings list (api 2024-01-01) in its wire shape.
	var list armsecurity.PricingList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[
		{"name":"VirtualMachines","properties":{"pricingTier":"Standard","subPlan":"P2","extensions":[
			{"name":"MdeDesignatedSubscription","isEnabled":"False"},
			{"name":"AgentlessVmScanning","isEnabled":"True"},
			{"name":"FileIntegrityMonitoring","isEnabled":"False"}]}},
		{"name":"SqlServers","properties":{"pricingTier":"Free","freeTrialRemainingTime":"PT0S"}},
		{"name":"KeyVaults","properties":{"pricingTier":"Standard","subPlan":"PerKeyVault"}},
		{"name":"Dns","properties":{"pricingTier":"Free","deprecated":true}},
		{"name":"Arm","properties":{"pricingTier":"Free"}}]}`), &list))

	md := pricingSettings(list.Value)
	require.Equal(t, "Free", md["defender_plan_arm"])
	require.Equal(t, "Free", md["defender_plan_sqlservers"])
	require.Equal(t, "Standard", md["defender_plan_keyvaults"])
	require.NotContains(t, md, "defender_plan_containers", "a plan the response omits is not claimed")
	require.NotContains(t, md, "defender_plan_dns", "deprecated and non-CIS plans are skipped")
	require.Equal(t, "Standard", md["defender_servers_tier"])
	require.Equal(t, "P2", md["defender_servers_subplan"])
	require.Equal(t, "true", md["defender_servers_agentless_scanning"])
	require.Equal(t, "false", md["defender_servers_fim"])

	var p1 armsecurity.PricingList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[{"name":"VirtualMachines","properties":{"pricingTier":"Standard","subPlan":"P1"}}]}`), &p1))
	md = pricingSettings(p1.Value)
	require.Equal(t, "unavailable", md["defender_servers_fim"], "Plan 1 has no FIM: still not on")

	var free armsecurity.PricingList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[{"name":"VirtualMachines","properties":{"pricingTier":"Free"}}]}`), &free))
	md = pricingSettings(free.Value)
	require.Equal(t, "Free", md["defender_plan_virtualmachines"])
	require.NotContains(t, md, "defender_servers_fim", "a Free plan has no components to report")
}

func TestContactSettings(t *testing.T) {
	var list armsecurity.ContactList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[{"name":"default","properties":{
		"emails":"sec@contoso.com; soc@contoso.com","isEnabled":true,
		"notificationsByRole":{"state":"On","roles":["Owner","AccountAdmin"]},
		"notificationsSources":[{"sourceType":"Alert","minimalSeverity":"Medium"},{"sourceType":"AttackPath","minimalRiskLevel":"Critical"}]}}]}`), &list))
	md := contactSettings(list.Value)
	require.Equal(t, "sec@contoso.com,soc@contoso.com", md["security_contact_emails"])
	require.Equal(t, "true", md["security_contact_owner_notified"])
	require.Equal(t, "Medium", md["security_contact_alert_min_severity"])
	require.Equal(t, "Critical", md["security_contact_attack_path_min_risk"])

	none := contactSettings(nil)
	require.Equal(t, "", none["security_contact_emails"], "no contact is an observation")
	require.Equal(t, "false", none["security_contact_owner_notified"])

	var disabled armsecurity.ContactList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[{"name":"default","properties":{"emails":"a@b.c","isEnabled":false,
		"notificationsByRole":{"state":"On","roles":["Owner"]}}}]}`), &disabled))
	md = contactSettings(disabled.Value)
	require.Equal(t, "", md["security_contact_emails"], "a disabled contact notifies nobody")
	require.Equal(t, "false", md["security_contact_owner_notified"])
}

func TestWDATPAndServerVASettings(t *testing.T) {
	var s armsecurity.DataExportSettings
	require.NoError(t, json.Unmarshal([]byte(`{"name":"WDATP","kind":"DataExportSettings","properties":{"enabled":true}}`), &s))
	require.Equal(t, "true", wdatpSettings(&s)["defender_wdatp_enabled"])
	require.Nil(t, wdatpSettings(&armsecurity.DataExportSettings{}))

	var l armsecurity.ServerVulnerabilityAssessmentsSettingsList
	require.NoError(t, json.Unmarshal([]byte(`{"value":[{"name":"AzureServersSetting","kind":"AzureServersSetting","properties":{"selectedProvider":"MdeTvm"}}]}`), &l))
	require.Equal(t, "MdeTvm", serverVASettings(l.Value)["defender_servers_va_provider"])
	require.Equal(t, "none", serverVASettings(nil)["defender_servers_va_provider"], "a fully read empty list is an observed none")
}

func TestDisabledDefinitions(t *testing.T) {
	var a armpolicy.Assignment
	require.NoError(t, json.Unmarshal([]byte(`{"name":"SecurityCenterBuiltIn","properties":{
		"policyDefinitionId":"/providers/Microsoft.Authorization/policySetDefinitions/1f3afdf9-d0c9-4c3d-847f-89da613e70a8",
		"parameters":{"systemUpdatesMonitoringEffect":{"value":"Disabled"},"diskEncryptionMonitoringEffect":{"value":"AuditIfNotExists"}},
		"overrides":[{"kind":"policyEffect","value":"Disabled","selectors":[{"kind":"policyDefinitionReferenceId","in":["mfaRef"]}]}]}}`), &a))
	var set armpolicy.SetDefinition
	require.NoError(t, json.Unmarshal([]byte(`{"properties":{"policyDefinitions":[
		{"policyDefinitionReferenceId":"sysRef","policyDefinitionId":"/providers/Microsoft.Authorization/policyDefinitions/86b3d65f-7626-441e-b690-81a8b71cff60",
			"parameters":{"effect":{"value":"[parameters('systemUpdatesMonitoringEffect')]"}}},
		{"policyDefinitionReferenceId":"diskRef","policyDefinitionId":"/providers/Microsoft.Authorization/policyDefinitions/disk",
			"parameters":{"effect":{"value":"[parameters('diskEncryptionMonitoringEffect')]"}}},
		{"policyDefinitionReferenceId":"mfaRef","policyDefinitionId":"/providers/Microsoft.Authorization/policyDefinitions/mfa"}]}}`), &set))
	require.Equal(t, []string{
		"/providers/Microsoft.Authorization/policyDefinitions/86b3d65f-7626-441e-b690-81a8b71cff60",
		"/providers/Microsoft.Authorization/policyDefinitions/mfa",
	}, disabledDefinitions(a.Properties, set.Properties))

	require.True(t, deprecatedPolicy(&armpolicy.DefinitionProperties{Metadata: map[string]any{"deprecated": true}}))
	require.True(t, deprecatedPolicy(&armpolicy.DefinitionProperties{DisplayName: ptr("[Deprecated]: System updates should be installed")}))
	require.False(t, deprecatedPolicy(&armpolicy.DefinitionProperties{DisplayName: ptr("Machines should be configured to periodically check for missing system updates")}))
}

func fakeARM(t *testing.T, responses map[string]fakeResponse) *restClient {
	t.Helper()
	opts := readOnlyARM()
	opts.Transport = &fakeREST{responses: responses}
	opts.Retry = policy.RetryOptions{MaxRetries: -1}
	c, err := newARMRestClient(fakeCred{}, opts)
	require.NoError(t, err)
	return c
}

func TestEASMWorkspaces_UnregisteredProviderIsZero(t *testing.T) {
	ctx := context.Background()
	path := "/subscriptions/s1/providers/Microsoft.Easm/workspaces"
	c := fakeARM(t, map[string]fakeResponse{path: {status: http.StatusConflict,
		body: `{"error":{"code":"MissingSubscriptionRegistration","message":"The subscription is not registered to use namespace 'Microsoft.Easm'."}}`}})
	md, err := easmWorkspaces(ctx, c, "s1")
	require.NoError(t, err)
	require.Equal(t, "0", md["easm_workspace_count"])

	c = fakeARM(t, map[string]fakeResponse{path: {status: http.StatusForbidden, body: `{"error":{"code":"AuthorizationFailed","message":"no"}}`}})
	_, err = easmWorkspaces(ctx, c, "s1")
	require.Error(t, err, "a denied read is unknown, never zero")

	c = fakeARM(t, map[string]fakeResponse{path: {body: `{"value":[{"id":"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Easm/workspaces/w"}]}`}})
	md, err = easmWorkspaces(ctx, c, "s1")
	require.NoError(t, err)
	require.Equal(t, "1", md["easm_workspace_count"])
}
