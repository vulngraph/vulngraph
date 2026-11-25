package checks

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// allAlertOps is an activity_alert_operations value watching every CIS
// operation.
func allAlertOps() string {
	ops := make([]string, 0, len(cisActivityAlertOperations))
	for _, r := range cisActivityAlertOperations {
		ops = append(ops, r.categories[0]+"|"+r.operation)
	}
	return strings.Join(ops, ",")
}

// The TestChecksNeverFireOnAbsentData contract for the Entra, Defender,
// Monitor and Key Vault checks: the confirmed negative fires, the compliant
// state and absent data (an unreadable Graph or ARM endpoint) stay silent.
func TestAzureSecurityChecksNeverFireOnAbsentData(t *testing.T) {
	tests := []struct {
		check     Check
		violating map[string]string
		compliant map[string]string
		unknown   map[string]string
	}{
		{
			check:     azureEntraNoMFABaseline,
			violating: map[string]string{"security_defaults_enabled": "false", "ca_mfa_all_users_policies": "", "ca_legacy_auth_block_policies": "Block legacy"},
			compliant: map[string]string{"security_defaults_enabled": "false", "ca_mfa_all_users_policies": "MFA all", "ca_legacy_auth_block_policies": "Block legacy"},
			// Defaults off but the CA list unreadable (403): unknown, not a gap.
			unknown: map[string]string{"security_defaults_enabled": "false"},
		},
		{
			check:     azureEntraDeviceJoinNoMFA,
			violating: map[string]string{"device_registration_mfa": "notRequired", "ca_device_registration_mfa_policies": ""},
			compliant: map[string]string{"device_registration_mfa": "notRequired", "ca_device_registration_mfa_policies": "MFA to register devices"},
			unknown:   map[string]string{"device_registration_mfa": "notRequired"},
		},
		{
			check:     azureEntraUsersWithoutMFA,
			violating: map[string]string{"mfa_not_capable_member_count": "3"},
			compliant: map[string]string{"mfa_not_capable_member_count": "0"},
			unknown:   map[string]string{"mfa_not_capable_admin_count": "1"},
		},
		{
			check:     azureEntraRiskPoliciesMissing,
			violating: map[string]string{"entra_p2_licensed": "true", "security_defaults_enabled": "false", "ca_risk_policies": ""},
			compliant: map[string]string{"entra_p2_licensed": "false", "security_defaults_enabled": "false", "ca_risk_policies": ""},
			unknown:   map[string]string{"security_defaults_enabled": "false", "ca_risk_policies": ""},
		},
		{
			check:     azureEntraUserConsentUnrestricted,
			violating: map[string]string{"user_consent_policies": "microsoft-user-default-legacy"},
			compliant: map[string]string{"user_consent_policies": "microsoft-user-default-low"},
			unknown:   map[string]string{},
		},
		{
			check:     azureEntraUsersCanRegisterApps,
			violating: map[string]string{"users_can_register_apps": "true"},
			compliant: map[string]string{"users_can_register_apps": "false"},
			unknown:   map[string]string{},
		},
		{
			check:     azureEntraGuestInvitesUnrestricted,
			violating: map[string]string{"guest_invites_from": "everyone"},
			compliant: map[string]string{"guest_invites_from": "adminsAndGuestInviters"},
			unknown:   map[string]string{},
		},
		{
			check:     azureEntraGuestMemberAccess,
			violating: map[string]string{"guest_access_level": "member"},
			compliant: map[string]string{"guest_access_level": "restricted"},
			unknown:   map[string]string{},
		},
		{
			check:     azureEntraGlobalAdminCount,
			violating: map[string]string{"global_admin_count": "9"},
			compliant: map[string]string{"global_admin_count": "3"},
			unknown:   map[string]string{},
		},
		{
			check:     azureEntraLogsNotExported,
			violating: map[string]string{"entra_diag_categories": "", "entra_p1_licensed": "false"},
			compliant: map[string]string{"entra_diag_categories": "AuditLogs,SignInLogs,MicrosoftGraphActivityLogs", "entra_p1_licensed": "true"},
			unknown:   map[string]string{"entra_p1_licensed": "true"},
		},
		{
			check:     azureIntuneLogsNotExported,
			violating: map[string]string{"intune_licensed": "true", "intune_diag_workspace_categories": "AuditLogs"},
			compliant: map[string]string{"intune_licensed": "true", "intune_diag_workspace_categories": "AuditLogs,OperationalLogs,DeviceComplianceOrg,Devices"},
			unknown:   map[string]string{"intune_licensed": "true"},
		},
		{
			check:     azureSubscriptionTenantTransferAllowed,
			violating: map[string]string{"subscriptions_leaving_tenant_blocked": "false", "subscriptions_entering_tenant_blocked": "true"},
			compliant: map[string]string{"subscriptions_leaving_tenant_blocked": "true", "subscriptions_entering_tenant_blocked": "true"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanServers,
			violating: map[string]string{"defender_plan_virtualmachines": "Free"},
			compliant: map[string]string{"defender_plan_virtualmachines": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanCSPM,
			violating: map[string]string{"defender_plan_cloudposture": "Free"},
			compliant: map[string]string{"defender_plan_cloudposture": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanAPIs,
			violating: map[string]string{"defender_plan_api": "Free"},
			compliant: map[string]string{"defender_plan_api": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanContainers,
			violating: map[string]string{"defender_plan_containers": "Free"},
			compliant: map[string]string{"defender_plan_containers": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanStorage,
			violating: map[string]string{"defender_plan_storageaccounts": "Free"},
			compliant: map[string]string{"defender_plan_storageaccounts": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanAppServices,
			violating: map[string]string{"defender_plan_appservices": "Free"},
			compliant: map[string]string{"defender_plan_appservices": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanCosmosDB,
			violating: map[string]string{"defender_plan_cosmosdbs": "Free"},
			compliant: map[string]string{"defender_plan_cosmosdbs": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanOSSDatabases,
			violating: map[string]string{"defender_plan_opensourcerelationaldatabases": "Free"},
			compliant: map[string]string{"defender_plan_opensourcerelationaldatabases": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanSQL,
			violating: map[string]string{"defender_plan_sqlservers": "Free"},
			compliant: map[string]string{"defender_plan_sqlservers": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanSQLVMs,
			violating: map[string]string{"defender_plan_sqlservervirtualmachines": "Free"},
			compliant: map[string]string{"defender_plan_sqlservervirtualmachines": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanKeyVault,
			violating: map[string]string{"defender_plan_keyvaults": "Free"},
			compliant: map[string]string{"defender_plan_keyvaults": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderPlanARM,
			violating: map[string]string{"defender_plan_arm": "Free"},
			compliant: map[string]string{"defender_plan_arm": "Standard"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderServersComponentsOff,
			violating: map[string]string{"defender_servers_tier": "Standard", "defender_servers_fim": "false"},
			compliant: map[string]string{"defender_servers_tier": "Standard", "defender_servers_fim": "true",
				"defender_servers_agentless_scanning": "true", "defender_servers_va_provider": "MdeTvm", "defender_wdatp_enabled": "true"},
			unknown: map[string]string{"defender_servers_tier": "Standard"},
		},
		{
			check:     azureDefenderNotificationsIncomplete,
			violating: map[string]string{"security_contact_emails": "", "security_contact_owner_notified": "true"},
			compliant: map[string]string{"security_contact_emails": "sec@contoso.com", "security_contact_owner_notified": "true",
				"security_contact_alert_min_severity": "High", "security_contact_attack_path_min_risk": "Critical"},
			unknown: map[string]string{},
		},
		{
			check:     azureMCSBPolicyDisabled,
			violating: map[string]string{"mcsb_disabled_policies": "Machines should be configured to periodically check for missing system updates"},
			compliant: map[string]string{"mcsb_disabled_policies": ""},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderEASMOff,
			violating: map[string]string{"easm_workspace_count": "0"},
			compliant: map[string]string{"easm_workspace_count": "1"},
			unknown:   map[string]string{},
		},
		{
			check:     azureDefenderIoTHubUnprotected,
			violating: map[string]string{"iot_hubs_without_defender": "factory-hub"},
			compliant: map[string]string{"iot_hubs_without_defender": ""},
			unknown:   map[string]string{},
		},
		{
			check:     azureDisabledUserHasRole,
			violating: map[string]string{"disabled_users_with_roles_count": "1"},
			compliant: map[string]string{"disabled_users_with_roles_count": "0"},
			unknown:   map[string]string{},
		},
		{
			check:     azureVMAdminWithoutMFA,
			violating: map[string]string{"privileged_vm_users_without_mfa_count": "2"},
			compliant: map[string]string{"privileged_vm_users_without_mfa_count": "0"},
			unknown:   map[string]string{},
		},
		{
			check:     azureActivityLogNotExported,
			violating: map[string]string{"activity_log_diagnostic_setting_count": "0"},
			compliant: map[string]string{"activity_log_diagnostic_setting_count": "1"},
			unknown:   map[string]string{},
		},
		{
			check:     azureActivityLogCategoriesMissing,
			violating: map[string]string{"activity_log_diagnostic_setting_count": "1", "activity_log_categories_missing": "Alert"},
			compliant: map[string]string{"activity_log_diagnostic_setting_count": "1", "activity_log_categories_missing": ""},
			unknown:   map[string]string{"activity_log_categories_missing": "Alert"},
		},
		{
			check:     azureActivityLogStorageNoCMK,
			violating: map[string]string{"activity_log_storage_without_cmk": "auditlogs"},
			compliant: map[string]string{"activity_log_storage_without_cmk": ""},
			unknown:   map[string]string{},
		},
		{
			check:     azureActivityLogRetentionShort,
			violating: map[string]string{"activity_log_retention_days": "30"},
			compliant: map[string]string{"activity_log_retention_days": "365"},
			unknown:   map[string]string{},
		},
		{
			check: azureActivityLogAlertsMissing,
			violating: map[string]string{"activity_alert_operations": "administrative|microsoft.network/networksecuritygroups/write",
				"activity_alert_whole_categories": "", "activity_alert_service_health": "true"},
			compliant: map[string]string{"activity_alert_operations": allAlertOps(),
				"activity_alert_whole_categories": "", "activity_alert_service_health": "true"},
			unknown: map[string]string{},
		},
		{
			check:     azureNoApplicationInsights,
			violating: map[string]string{"app_service_count": "3", "app_insights_component_count": "0"},
			compliant: map[string]string{"app_service_count": "3", "app_insights_component_count": "1"},
			unknown:   map[string]string{"app_insights_component_count": "0"},
		},
		{
			check:     azureResourceLoggingDisabled,
			violating: map[string]string{"resources_without_diagnostic_settings_count": "4"},
			compliant: map[string]string{"resources_without_diagnostic_settings_count": "0"},
			unknown:   map[string]string{},
		},
		{
			check:     azureKeyVaultNoPurgeProtection,
			violating: map[string]string{"purge_protection": "false", "soft_delete": "true"},
			compliant: map[string]string{"purge_protection": "true", "soft_delete": "true"},
			unknown:   map[string]string{},
		},
		{
			check:     azureKeyVaultPublicNetworkAccess,
			violating: map[string]string{"public_network_access": "Enabled", "network_default_action": "Allow"},
			compliant: map[string]string{"public_network_access": "Disabled", "network_default_action": "Allow"},
			unknown:   map[string]string{"network_default_action": "Allow"},
		},
		{
			check:     azureKeyVaultNoPrivateEndpoint,
			violating: map[string]string{"private_endpoint_count": "0"},
			compliant: map[string]string{"private_endpoint_count": "1"},
			unknown:   map[string]string{},
		},
		{
			check:     azureKeyVaultAccessPolicyModel,
			violating: map[string]string{"rbac_authorization": "false"},
			compliant: map[string]string{"rbac_authorization": "true"},
			unknown:   map[string]string{},
		},
		{
			check:     azureKeyVaultRBACKeyNoExpiry,
			violating: map[string]string{"rbac_authorization": "true", "keys_without_expiry_count": "2"},
			compliant: map[string]string{"rbac_authorization": "false", "keys_without_expiry_count": "2"},
			unknown:   map[string]string{"keys_without_expiry_count": "2"},
		},
		{
			check:     azureKeyVaultPolicyKeyNoExpiry,
			violating: map[string]string{"rbac_authorization": "false", "keys_without_expiry_count": "2"},
			compliant: map[string]string{"rbac_authorization": "true", "keys_without_expiry_count": "2"},
			unknown:   map[string]string{"keys_without_expiry_count": "2"},
		},
		{
			check:     azureKeyVaultRBACSecretNoExpiry,
			violating: map[string]string{"rbac_authorization": "true", "secrets_without_expiry_count": "2"},
			compliant: map[string]string{"rbac_authorization": "false", "secrets_without_expiry_count": "2"},
			unknown:   map[string]string{"secrets_without_expiry_count": "2"},
		},
		{
			check:     azureKeyVaultPolicySecretNoExpiry,
			violating: map[string]string{"rbac_authorization": "false", "secrets_without_expiry_count": "2"},
			compliant: map[string]string{"rbac_authorization": "true", "secrets_without_expiry_count": "2"},
			unknown:   map[string]string{"secrets_without_expiry_count": "2"},
		},
		{
			check:     azureKeyVaultKeyNoRotation,
			violating: map[string]string{"keys_without_rotation_count": "1"},
			compliant: map[string]string{"keys_without_rotation_count": "0"},
			// A data-plane rotation read the vault refused: the collector omits the key.
			unknown: map[string]string{"keys_without_expiry_count": "0"},
		},
		{
			check:     azureKeyVaultCertValidityLong,
			violating: map[string]string{"certs_validity_over_12_months_count": "1"},
			compliant: map[string]string{"certs_validity_over_12_months_count": "0"},
			unknown:   map[string]string{},
		},
		{
			check:     azureKeyVaultAuditLoggingOff,
			violating: map[string]string{"audit_logging_enabled": "false"},
			compliant: map[string]string{"audit_logging_enabled": "true"},
			unknown:   map[string]string{},
		},
	}
	registered := map[string]bool{}
	for _, c := range append(append(append(append(azureEntraChecks(), azureDefenderChecks()...), azureDefenderPlanChecks()...), azureMonitorChecks()...), azureKeyVaultChecks()...) {
		registered[c.ID] = true
	}
	require.Len(t, tests, len(registered), "every new Azure check has an absent-data row")
	for _, tt := range tests {
		t.Run(tt.check.ID, func(t *testing.T) {
			require.True(t, registered[tt.check.ID])
			build := func(md map[string]string) asset.Asset {
				return asset.Asset{ID: "res-1", Name: "r", Type: tt.check.AssetType, Provider: tt.check.Provider, Metadata: md}
			}
			require.True(t, tt.check.Violates(build(tt.violating)), "the confirmed negative must fire")
			require.False(t, tt.check.Violates(build(tt.compliant)), "the compliant state must not fire")
			require.False(t, tt.check.Violates(build(tt.unknown)), "absent data is not a violation")
			require.False(t, tt.check.Violates(build(nil)), "a nil metadata map is absent data too")
		})
	}
}

// A check silent only because a Graph or ARM read failed must not read as
// evaluated: the lifecycle would close its finding as fixed.
func TestAzureSecurityChecks_AbsentKeysNotEvaluable(t *testing.T) {
	reg := Default()
	tests := []struct {
		id string
		md map[string]string
	}{
		{"azure-entra-no-mfa-baseline", map[string]string{"security_defaults_enabled": "false"}},
		{"azure-entra-users-without-mfa", map[string]string{}},
		{"azure-entra-logs-not-exported", map[string]string{"entra_diag_categories": "AuditLogs"}},
		{"azure-defender-cosmosdb-off", map[string]string{}},
		{"azure-defender-notifications-incomplete", map[string]string{"security_contact_emails": "a@b.c"}},
		{"azure-activity-log-alerts-missing", map[string]string{"activity_alert_service_health": "true"}},
		{"azure-activity-log-categories-missing", map[string]string{"activity_log_categories_missing": "Alert"}},
		{"azure-keyvault-key-no-rotation", map[string]string{}},
		{"azure-vm-admin-without-mfa", map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			c, ok := reg.ByID(tt.id)
			require.True(t, ok)
			a := asset.Asset{ID: "r", Name: "x", Type: c.AssetType, Provider: c.Provider, Metadata: tt.md}
			require.False(t, c.Violates(a))
			require.False(t, c.Evaluable(a))
		})
	}
}

func TestEntraNoMFABaseline(t *testing.T) {
	tests := []struct {
		name     string
		md       map[string]string
		fires    bool
		severity finding.Severity
	}{
		{"security defaults on", map[string]string{"security_defaults_enabled": "true", "ca_mfa_all_users_policies": "", "ca_legacy_auth_block_policies": ""}, false, ""},
		{"full CA baseline", map[string]string{"security_defaults_enabled": "false", "ca_mfa_all_users_policies": "a", "ca_legacy_auth_block_policies": "b", "ca_admin_roles_without_mfa": ""}, false, ""},
		{"nothing at all", map[string]string{"security_defaults_enabled": "false", "ca_mfa_all_users_policies": "", "ca_legacy_auth_block_policies": "", "ca_admin_roles_without_mfa": "Global Administrator"}, true, finding.SeverityHigh},
		{"admins covered, users not", map[string]string{"security_defaults_enabled": "false", "ca_mfa_all_users_policies": "", "ca_legacy_auth_block_policies": "b", "ca_admin_roles_without_mfa": ""}, true, finding.SeverityMedium},
		{"MFA everywhere, legacy open", map[string]string{"security_defaults_enabled": "false", "ca_mfa_all_users_policies": "a", "ca_legacy_auth_block_policies": "", "ca_admin_roles_without_mfa": ""}, true, finding.SeverityMedium},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{Type: tenantSettingsType, Provider: asset.ProviderAzure, Metadata: tt.md}
			require.Equal(t, tt.fires, azureEntraNoMFABaseline.Violates(a))
			if tt.fires {
				require.Equal(t, tt.severity, azureEntraNoMFABaseline.SeverityFor(a))
			}
		})
	}
}

func TestEntraLogGaps_LicenseGated(t *testing.T) {
	a := func(md map[string]string) asset.Asset { return asset.Asset{Metadata: md} }
	require.Empty(t, entraLogGaps(a(map[string]string{"entra_diag_categories": "AuditLogs", "entra_p1_licensed": "false"})),
		"a free tenant cannot export sign-in logs")
	require.Equal(t, []string{"SignInLogs", "MicrosoftGraphActivityLogs"},
		entraLogGaps(a(map[string]string{"entra_diag_categories": "AuditLogs", "entra_p1_licensed": "true"})))
	require.Nil(t, intuneLogGaps(a(map[string]string{"intune_diag_workspace_categories": "", "intune_licensed": "false"})),
		"no Intune licence: the control does not apply")
}

func TestMissingActivityAlerts(t *testing.T) {
	a := func(md map[string]string) asset.Asset { return asset.Asset{Metadata: md} }
	require.Empty(t, missingActivityAlerts(a(map[string]string{
		"activity_alert_operations": "", "activity_alert_whole_categories": "administrative", "activity_alert_service_health": "true",
	})), "an alert on every Administrative operation covers the list (ARM writes, security solutions included, log as Administrative)")
	got := missingActivityAlerts(a(map[string]string{
		"activity_alert_operations": "", "activity_alert_whole_categories": "security", "activity_alert_service_health": "true",
	}))
	require.Len(t, got, len(cisActivityAlertOperations)-2, "a whole-Security alert covers only the security-solution rows")
	require.Empty(t, missingActivityAlerts(a(map[string]string{
		"activity_alert_operations":       "security|microsoft.security/securitysolutions/write,|microsoft.security/securitysolutions/delete",
		"activity_alert_whole_categories": "administrative", "activity_alert_service_health": "true",
	})), "CIS's category=Security alert and a category-less alert both watch their operation")
	require.Len(t, missingActivityAlerts(a(map[string]string{
		"activity_alert_operations": "security|microsoft.network/networksecuritygroups/write", "activity_alert_service_health": "true",
	})), len(cisActivityAlertOperations), "a category that never carries the event watches nothing")
	got = missingActivityAlerts(a(map[string]string{
		"activity_alert_operations": "administrative|microsoft.authorization/policyassignments/write", "activity_alert_service_health": "false",
	}))
	require.Equal(t, "6.1.2.2 microsoft.authorization/policyassignments/delete", got[0])
	require.Equal(t, "6.1.2.11 ServiceHealth", got[len(got)-1])
}

func TestServersComponentGaps(t *testing.T) {
	a := func(md map[string]string) asset.Asset { return asset.Asset{Metadata: md} }
	require.Nil(t, serversComponentGaps(a(map[string]string{"defender_servers_tier": "Free", "defender_wdatp_enabled": "false"})),
		"with Servers off the plan finding is the root cause")
	require.Equal(t, []string{"agentless scanning for machines", "file integrity monitoring"},
		serversComponentGaps(a(map[string]string{"defender_servers_tier": "Standard",
			"defender_servers_agentless_scanning": "unavailable", "defender_servers_fim": "unavailable",
			"defender_servers_va_provider": "MdeTvm", "defender_wdatp_enabled": "true"})), "Plan 1 lacks the Plan 2 components")
}

func TestKeyVaultPublicAccessGraded(t *testing.T) {
	open := asset.Asset{Metadata: map[string]string{"public_network_access": "Enabled", "network_default_action": "Allow"}}
	fw := asset.Asset{Metadata: map[string]string{"public_network_access": "Enabled", "network_default_action": "Deny"}}
	require.Equal(t, finding.SeverityMedium, azureKeyVaultPublicNetworkAccess.SeverityFor(open))
	require.Equal(t, finding.SeverityLow, azureKeyVaultPublicNetworkAccess.SeverityFor(fw))
	require.Contains(t, azureKeyVaultPublicNetworkAccess.TitleFor(fw), "restricted by its firewall")
}
