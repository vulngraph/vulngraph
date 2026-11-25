package azure

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription"
	"github.com/stretchr/testify/require"
)

// Graph conditionalAccessPolicy payloads in the v1.0 wire shape.
const (
	caRequireMFAAll = `{"displayName":"Require MFA for all users","state":"enabled",
		"conditions":{"users":{"includeUsers":["All"],"excludeUsers":["breakglass-id"],"includeGroups":[],"includeRoles":[]},
			"applications":{"includeApplications":["All"],"excludeApplications":[],"includeUserActions":[]},
			"clientAppTypes":["all"],"platforms":null,"locations":null,"signInRiskLevels":[],"userRiskLevels":[]},
		"grantControls":{"operator":"OR","builtInControls":["mfa"],"authenticationStrength":null}}`
	caAdminsStrength = `{"displayName":"Phishing-resistant MFA for admins","state":"enabled",
		"conditions":{"users":{"includeUsers":[],"includeRoles":["62e90394-69f5-4237-9190-012177145e10"]},
			"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},
		"grantControls":{"operator":"OR","builtInControls":[],"authenticationStrength":{"id":"00000000-0000-0000-0000-000000000004"}}}`
	caBlockLegacy = `{"displayName":"Block legacy authentication","state":"enabled",
		"conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},
			"clientAppTypes":["exchangeActiveSync","other"]},
		"grantControls":{"operator":"OR","builtInControls":["block"]}}`
	caReportOnlyRisk = `{"displayName":"Sign-in risk (report-only)","state":"enabledForReportingButNotEnforced",
		"conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},
			"clientAppTypes":["all"],"signInRiskLevels":["high","medium"]},
		"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`
	caWindowsOnly = `{"displayName":"MFA on Windows","state":"enabled",
		"conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]},
			"clientAppTypes":["all"],"platforms":{"includePlatforms":["windows"]}},
		"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`
	caDeviceReg = `{"displayName":"MFA to register devices","state":"enabled",
		"conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":[],"includeUserActions":["urn:user:registerdevice"]},
			"clientAppTypes":["all"]},
		"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`
	caSessionOnly = `{"displayName":"Sign-in frequency","state":"enabled",
		"conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},
		"grantControls":null,"sessionControls":{"signInFrequency":{"value":4,"type":"hours"}}}`
)

func caPolicies(t *testing.T, raw ...string) []caPolicy {
	t.Helper()
	out := make([]caPolicy, 0, len(raw))
	for _, r := range raw {
		var p caPolicy
		require.NoError(t, json.Unmarshal([]byte(r), &p))
		out = append(out, p)
	}
	return out
}

func TestConditionalAccessSettings(t *testing.T) {
	t.Run("full baseline", func(t *testing.T) {
		md := conditionalAccessSettings(caPolicies(t, caRequireMFAAll, caAdminsStrength, caBlockLegacy, caDeviceReg, caSessionOnly))
		require.Equal(t, "5", md["ca_enabled_policy_count"])
		require.Equal(t, "Require MFA for all users", md["ca_mfa_all_users_policies"])
		require.Equal(t, "Phishing-resistant MFA for admins; Require MFA for all users", md["ca_mfa_admins_policies"])
		require.Equal(t, "Block legacy authentication", md["ca_legacy_auth_block_policies"])
		require.Equal(t, "MFA to register devices", md["ca_device_registration_mfa_policies"])
		require.Equal(t, "", md["ca_risk_policies"])
	})
	t.Run("report-only and narrowed policies enforce nothing tenant-wide", func(t *testing.T) {
		md := conditionalAccessSettings(caPolicies(t, caReportOnlyRisk, caWindowsOnly, caSessionOnly))
		require.Equal(t, "2", md["ca_enabled_policy_count"])
		require.Equal(t, "", md["ca_mfa_all_users_policies"], "a platform condition is not a baseline")
		require.Equal(t, "", md["ca_mfa_admins_policies"])
		require.Equal(t, "", md["ca_risk_policies"], "report-only does not enforce")
	})
	t.Run("exclusions beyond break-glass and OR-ed device controls are not a baseline", func(t *testing.T) {
		md := conditionalAccessSettings(caPolicies(t,
			`{"displayName":"MFA except contractors","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeGroups":["contractors"]},
				"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`,
			`{"displayName":"MFA except three","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeUsers":["a","b","c"]},
				"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`,
			`{"displayName":"MFA except an app","state":"enabled","conditions":{"users":{"includeUsers":["All"]},
				"applications":{"includeApplications":["All"],"excludeApplications":["00000002-0000-0ff1-ce00-000000000000"]},"clientAppTypes":["all"]},
				"grantControls":{"operator":"OR","builtInControls":["mfa"]}}`,
			`{"displayName":"MFA or compliant device","state":"enabled","conditions":{"users":{"includeUsers":["All"]},
				"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},"grantControls":{"operator":"OR","builtInControls":["mfa","compliantDevice"]}}`,
			`{"displayName":"Block legacy except group","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeGroups":["svc"]},
				"applications":{"includeApplications":["All"]},"clientAppTypes":["exchangeActiveSync","other"]},"grantControls":{"operator":"OR","builtInControls":["block"]}}`))
		require.Equal(t, "", md["ca_mfa_all_users_policies"])
		require.Equal(t, "", md["ca_legacy_auth_block_policies"])
		require.Contains(t, md["ca_admin_roles_without_mfa"], "Global Administrator")
	})
	t.Run("MFA AND compliant device counts; admin roles are a union", func(t *testing.T) {
		md := conditionalAccessSettings(caPolicies(t,
			`{"displayName":"MFA and compliant","state":"enabled","conditions":{"users":{"includeUsers":["All"],"excludeUsers":["bg1","bg2"]},
				"applications":{"includeApplications":["All"]},"clientAppTypes":["all"]},"grantControls":{"operator":"AND","builtInControls":["mfa","compliantDevice"]}}`))
		require.Equal(t, "MFA and compliant", md["ca_mfa_all_users_policies"], "two excluded users is the break-glass allowance")
		require.Equal(t, "", md["ca_admin_roles_without_mfa"])

		md = conditionalAccessSettings(caPolicies(t, caAdminsStrength))
		require.NotContains(t, md["ca_admin_roles_without_mfa"], "Global Administrator")
		require.Contains(t, md["ca_admin_roles_without_mfa"], "Privileged Role Administrator", "a GA-only policy leaves the other admin roles uncovered")
	})
	t.Run("no policies is an observed none", func(t *testing.T) {
		md := conditionalAccessSettings(nil)
		require.Equal(t, "0", md["ca_enabled_policy_count"])
		require.Contains(t, md, "ca_mfa_all_users_policies")
		require.Equal(t, "", md["ca_legacy_auth_block_policies"])
	})
}

func TestCollectEntra(t *testing.T) {
	ca := `{"value":[` + caRequireMFAAll + `,` + caBlockLegacy + `]}`
	g, f := fakeGraph(map[string]fakeResponse{
		"/v1.0/policies/identitySecurityDefaultsEnforcementPolicy": {body: `{"id":"00000000-0000-0000-0000-000000000005","isEnabled":false}`},
		"/v1.0/identity/conditionalAccess/policies":                {body: ca},
		"/v1.0/policies/deviceRegistrationPolicy":                  {status: http.StatusForbidden, body: `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`},
		"/v1.0/policies/authorizationPolicy": {body: `{"id":"authorizationPolicy","allowInvitesFrom":"everyone",
			"guestUserRoleId":"10dae51f-b6af-4016-8d66-8c2a99b929b3",
			"defaultUserRolePermissions":{"allowedToCreateApps":true,"allowedToCreateSecurityGroups":true,
			"permissionGrantPoliciesAssigned":["ManagePermissionGrantsForSelf.microsoft-user-default-legacy","ManagePermissionGrantsForOwnedResource.DeveloperConsent"]}}`},
		"/v1.0/subscribedSkus": {body: `{"value":[
			{"capabilityStatus":"Enabled","skuPartNumber":"ENTERPRISEPACK","servicePlans":[{"servicePlanName":"AAD_PREMIUM","provisioningStatus":"Success"},{"servicePlanName":"INTUNE_A","provisioningStatus":"Success"}]},
			{"capabilityStatus":"Suspended","skuPartNumber":"EMSPREMIUM","servicePlans":[{"servicePlanName":"AAD_PREMIUM_P2","provisioningStatus":"Success"}]}]}`},
		"/v1.0/roleManagement/directory/roleAssignments": {body: `{"value":[{"principalId":"u1"},{"principalId":"u2"},{"principalId":"u1"}]}`},
		"/v1.0/users": {body: `{"value":[{"id":"u9","userPrincipalName":"gone@contoso.com"}]}`},
		"/v1.0/reports/authenticationMethods/userRegistrationDetails": {body: `{"value":[
			{"id":"u1","userPrincipalName":"admin@contoso.com","userType":"member","isAdmin":true,"isMfaCapable":false,"isMfaRegistered":false},
			{"id":"u2","userPrincipalName":"ok@contoso.com","userType":"member","isAdmin":false,"isMfaCapable":true,"isMfaRegistered":true},
			{"id":"u3","userPrincipalName":"bob@contoso.com","userType":"member","isAdmin":false,"isMfaCapable":false,"isMfaRegistered":true},
			{"id":"u9","userPrincipalName":"gone@contoso.com","userType":"member","isAdmin":false,"isMfaCapable":false},
			{"id":"g1","userPrincipalName":"guest#EXT#@contoso.com","userType":"guest","isAdmin":false,"isMfaCapable":false}]}`},
	})
	tenant := newSettingsAsset()
	facts := collectEntra(context.Background(), g, tenant)
	md := tenant.meta

	require.Equal(t, "false", md["security_defaults_enabled"])
	require.Equal(t, "Require MFA for all users", md["ca_mfa_all_users_policies"])
	require.NotContains(t, md, "device_registration_mfa", "a 403 leaves the setting unknown, never passing")
	require.Equal(t, "everyone", md["guest_invites_from"])
	require.Equal(t, "limited", md["guest_access_level"])
	require.Equal(t, "true", md["users_can_register_apps"])
	require.Equal(t, "microsoft-user-default-legacy", md["user_consent_policies"])
	require.Equal(t, "true", md["entra_p1_licensed"])
	require.Equal(t, "false", md["entra_p2_licensed"], "a suspended SKU grants nothing")
	require.Equal(t, "true", md["intune_licensed"])
	require.Equal(t, "2", md["global_admin_count"])
	require.Equal(t, "u1,u2", md["global_admins"])
	require.Equal(t, "2", md["mfa_not_capable_member_count"], "guests and disabled users are not counted")
	require.Equal(t, "admin@contoso.com, bob@contoso.com", md["mfa_not_capable_members"])
	require.Equal(t, "1", md["mfa_not_capable_admin_count"])
	require.Equal(t, map[string]string{"u9": "gone@contoso.com"}, facts.disabledUsers)
	require.Len(t, facts.mfa, 5)

	for _, u := range f.seen {
		require.Contains(t, u, "https://graph.microsoft.com/v1.0/", "every read goes to Graph v1.0")
	}
}

func TestMFASettings_NeedsBothReads(t *testing.T) {
	require.Nil(t, mfaSettings(entraFacts{mfa: map[string]mfaRecord{}}), "no disabled-user list: unknown")
	require.Nil(t, mfaSettings(entraFacts{disabledUsers: map[string]string{}}), "no registration report: unknown")
	md := mfaSettings(entraFacts{mfa: map[string]mfaRecord{}, disabledUsers: map[string]string{}})
	require.Equal(t, "0", md["mfa_not_capable_member_count"], "an empty report is an observed zero")
}

func TestLicenseSettings_IntuneVariants(t *testing.T) {
	sku := func(plan string) []subscribedSku {
		var s []subscribedSku
		require.NoError(t, json.Unmarshal([]byte(`[{"capabilityStatus":"Enabled","servicePlans":[{"servicePlanName":"`+plan+`","provisioningStatus":"Success"}]}]`), &s))
		return s
	}
	for _, plan := range []string{"INTUNE_A", "INTUNE_EDU", "INTUNE_SMBIZ", "INTUNE_A_VL", "INTUNE_A_GOV"} {
		require.Equal(t, "true", licenseSettings(sku(plan))["intune_licensed"], plan)
	}
	require.Equal(t, "false", licenseSettings(sku("INTUNE_O365"))["intune_licensed"], "basic mobility for Office 365 is not Intune")
}

func TestAuthorizationPolicySettings_OmittedFieldsStayAbsent(t *testing.T) {
	require.Empty(t, authorizationPolicy{}.settings())
	md := authorizationPolicy{GuestUserRoleID: guestRoleMember}.settings()
	require.Equal(t, "member", md["guest_access_level"])
}

func TestTenantDiagCategories(t *testing.T) {
	var settings []tenantDiagSetting
	require.NoError(t, json.Unmarshal([]byte(`[
		{"name":"to-law","properties":{"workspaceId":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law",
			"logs":[{"category":"AuditLogs","enabled":true},{"category":"SignInLogs","enabled":false}]}},
		{"name":"to-storage","properties":{"storageAccountId":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st",
			"logs":[{"category":"SignInLogs","enabled":true}]}},
		{"name":"no-destination","properties":{"logs":[{"category":"MicrosoftGraphActivityLogs","enabled":true}]}}]`), &settings))
	require.Equal(t, "AuditLogs,SignInLogs", entraDiagSettings(settings)["entra_diag_categories"])
	require.Equal(t, "AuditLogs", intuneDiagSettings(settings)["intune_diag_workspace_categories"], "Intune counts Log Analytics destinations only")
	require.Equal(t, "", entraDiagSettings(nil)["entra_diag_categories"], "no settings is an observed none")
}

func TestTenantPolicySettings(t *testing.T) {
	require.Nil(t, tenantPolicySettings(nil))
	md := tenantPolicySettings(&armsubscription.TenantPolicy{BlockSubscriptionsLeavingTenant: to.Ptr(true)})
	require.Equal(t, "true", md["subscriptions_leaving_tenant_blocked"])
	require.Equal(t, "false", md["subscriptions_entering_tenant_blocked"], "unset is the documented default: not blocked")
}

func TestSubscriptionEntraJoins(t *testing.T) {
	const sub = "s1"
	subScope := "/subscriptions/" + sub
	vm := subScope + "/resourceGroups/rg-vm/providers/Microsoft.Compute/virtualMachines/vm1"
	readerDef := subScope + "/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
	ownerDef := subScope + "/providers/Microsoft.Authorization/roleDefinitions/" + ownerRoleGUID
	vmAdminDef := "/providers/Microsoft.Authorization/roleDefinitions/1c0163c0-47e6-4577-8991-ea5c82e286e4"
	l := &rbacListing{
		defs: map[string]roleDef{readerDef: {name: "Reader"}, ownerDef: {name: "Owner"}},
		assignments: []roleAssignment{
			{principalID: "dis", principalType: "User", roleDefID: readerDef, scope: subScope},
			{principalID: "dis-group", principalType: "Group", roleDefID: readerDef, scope: subScope},
			{principalID: "nomfa", principalType: "User", roleDefID: vmAdminDef, scope: subScope + "/resourceGroups/rg-vm"},
			{principalID: "nomfa-other-rg", principalType: "User", roleDefID: ownerDef, scope: subScope + "/resourceGroups/rg-vmx"},
			{principalID: "mfa", principalType: "User", roleDefID: ownerDef, scope: subScope},
			{principalID: "unknown", principalType: "User", roleDefID: ownerDef, scope: subScope},
			{principalID: "dis", principalType: "User", roleDefID: ownerDef, scope: vm},
		},
	}
	f := entraFacts{
		disabledUsers: map[string]string{"dis": "gone@contoso.com", "dis-group": "x"},
		mfa: map[string]mfaRecord{
			"nomfa":          {UserPrincipalName: "ops@contoso.com"},
			"nomfa-other-rg": {UserPrincipalName: "other@contoso.com"},
			"mfa":            {UserPrincipalName: "good@contoso.com", IsMfaCapable: true},
			"dis":            {UserPrincipalName: "gone@contoso.com"},
		},
	}
	md := subscriptionEntraJoins(l, f, []string{vm}, sub)
	require.Equal(t, "2", md["disabled_users_with_roles_count"])
	require.Equal(t, "gone@contoso.com (Owner), gone@contoso.com (Reader)", md["disabled_users_with_roles"])
	require.Equal(t, "1", md["privileged_vm_users_without_mfa_count"],
		"a role on a resource group with no VM, a disabled user, and a user missing from the report are not counted")
	require.Equal(t, "ops@contoso.com (Virtual Machine Administrator Login)", md["privileged_vm_users_without_mfa"])

	require.Nil(t, subscriptionEntraJoins(nil, f, []string{vm}, sub), "no RBAC listing: unknown")
	partial := subscriptionEntraJoins(l, entraFacts{disabledUsers: f.disabledUsers}, []string{vm}, sub)
	require.NotContains(t, partial, "privileged_vm_users_without_mfa_count", "no MFA report: unknown")
	none := subscriptionEntraJoins(l, f, nil, sub)
	require.Equal(t, "0", none["privileged_vm_users_without_mfa_count"], "no VMs: nothing to reach")
}
