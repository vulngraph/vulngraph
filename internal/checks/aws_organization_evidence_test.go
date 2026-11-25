package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestAWSOrganizationObservation_CannotResolveDormantPrivilege(t *testing.T) {
	check, ok := Default().ByID("aws-iam-admin-role-dormant")
	require.True(t, ok)
	for _, tc := range []struct {
		name, complete, tier, lastUse string
		evaluable                     bool
	}{
		{"missing coverage", "", "unknown", "180", false},
		{"failed coverage", "false", "unknown", "180", false},
		{"failed coverage with stale standard tier", "false", "standard", "180", false},
		{"other permission evidence unknown", "true", "unknown", "180", false},
		{"observed ordinary role", "true", "standard", "180", true},
		{"recent use independently rules out dormancy", "false", "unknown", "1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset.Asset{Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
				"path": "/", "admin": "false", "privilege_tier": tc.tier, "organization_policy_complete": tc.complete,
				"last_used_observed": "true", "last_used_days": tc.lastUse, "created_days": "240",
			}}
			require.False(t, check.Violates(a))
			require.Equal(t, tc.evaluable, check.Evaluable(a), "unknown privilege must not become clean; an independent recent-use observation remains usable")
		})
	}
}

func TestAWSOrganizationObservation_RawAdminCannotOverrideEffectiveTier(t *testing.T) {
	reg := Default()
	for _, tc := range []struct {
		name, complete, tier string
		admin, evaluable     bool
	}{
		{"legacy hint", "", "", false, false},
		{"unread organization", "false", "unknown", false, false},
		{"stale hint under SCP", "true", "standard", false, true},
		{"effective admin", "true", "admin", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := asset.Asset{Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{
				"admin": "true", "organization_policy_complete": tc.complete, "privilege_tier": tc.tier,
				"last_used_observed": "true", "last_used_days": "180", "created_days": "240", "path": "/",
				"full_admin_customer_policy_only": "false", "aa_services_granted": "300", "aa_services_used": "3",
				"cloudshell_full_access": "true", "inline_kms_decrypt_all": "true",
			}}
			dormant, ok := reg.ByID("aws-iam-admin-role-dormant")
			require.True(t, ok)
			require.Equal(t, tc.admin, dormant.Violates(a))
			require.Equal(t, tc.evaluable, dormant.Evaluable(a))
			require.Equal(t, !tc.admin, awsIAMRoleUnused.Violates(a), "observed dormancy must not disappear behind an unproved admin label")
			require.Equal(t, !tc.admin, cloudShellFullAccess(a))
			require.Equal(t, !tc.admin, inlineKMSDecryptAll(a))
			a.Metadata["last_used_days"] = "1"
			require.Equal(t, tc.admin, overprivilegedAdminRole(a))
			a.Metadata["aa_services_used"] = "300"
			require.Equal(t, tc.admin, awsIAMRoleFullAdmin.Violates(a))

			a.Type = "iam_user"
			a.Metadata["inactive"] = "false"
			a.Metadata["password_last_used_days"] = "180"
			a.Metadata["access_key_last_used_days"] = "180"
			a.Metadata["console_access"] = "false"
			a.Metadata["mfa_enabled"] = "false"
			a.Metadata["active_key_count"] = "1"
			a.Metadata["access_key_age_days"] = "100"
			require.Equal(t, tc.admin, dormantAdminUser(a))
			a.Metadata["access_key_last_used_days"] = "1"
			require.Equal(t, tc.admin, awsIAMUserFullAdmin.Violates(a))
			require.Equal(t, tc.admin, awsIAMAdminUserKeyNoMFA.Violates(a))
			if !tc.admin {
				require.NotContains(t, accessKeyAgeTitle(a), "Admin")
			}
		})
	}
}
