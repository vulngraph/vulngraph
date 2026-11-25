package checks

import (
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// withMeta returns a copy of base with overrides applied; a "" override deletes the
// key, so a row can express "this reading was never observed".
func withMeta(base map[string]string, overrides map[string]string) map[string]string {
	out := maps.Clone(base)
	for k, v := range overrides {
		if v == "" {
			delete(out, k)
			continue
		}
		out[k] = v
	}
	return out
}

func TestDormantAdminRole(t *testing.T) {
	base := map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "last_used_observed": "true", "last_used_days": "120", "created_days": "400", "path": "/"}
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"admin idle past threshold", base, true},
		{"admin idle exactly at threshold", withMeta(base, map[string]string{"last_used_days": "90"}), true},
		{"admin used inside threshold", withMeta(base, map[string]string{"last_used_days": "89"}), false},
		{"never used in tracking window, old role", withMeta(base, map[string]string{"last_used_days": "9999"}), true},
		{"never used, role younger than threshold", withMeta(base, map[string]string{"last_used_days": "9999", "created_days": "10"}), false},
		{"never used, age unknown", withMeta(base, map[string]string{"last_used_days": "9999", "created_days": ""}), false},
		{"last-used not observed (GetRole failed)", withMeta(base, map[string]string{"last_used_observed": "", "last_used_days": ""}), false},
		{"not admin", withMeta(base, map[string]string{"admin": "", "privilege_tier": "standard"}), false},
		{"not admin, can escalate to admin", withMeta(base, map[string]string{"admin": "", "privilege_tier": "can_escalate_to_admin"}), true},
		{"not admin, CIEM-admin tier", withMeta(base, map[string]string{"admin": "", "privilege_tier": "admin"}), true},
		{"not admin, high tier", withMeta(base, map[string]string{"admin": "", "privilege_tier": "high"}), false},
		{"not admin, tier unknown", withMeta(base, map[string]string{"admin": "", "privilege_tier": "unknown"}), false},
		{"can escalate but used recently", withMeta(base, map[string]string{"admin": "", "privilege_tier": "can_escalate_to_admin", "last_used_days": "5"}), false},
		{"service-linked role", withMeta(base, map[string]string{"path": "/aws-service-role/ecs.amazonaws.com/"}), false},
		{"SSO reserved role still counts", withMeta(base, map[string]string{"path": "/aws-reserved/sso.amazonaws.com/"}), true},
		{"unparseable last-used", withMeta(base, map[string]string{"last_used_days": "soon"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, dormantAdminRole(asset.Asset{Metadata: tt.md}))
		})
	}
}

func TestDormantAdminUser(t *testing.T) {
	base := map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "150", "created_days": "900"}
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"both channels idle", base, true},
		{"console used recently", withMeta(base, map[string]string{"password_last_used_days": "5"}), false},
		{"key used recently", withMeta(base, map[string]string{"access_key_last_used_days": "5"}), false},
		{"console never, key idle", withMeta(base, map[string]string{"password_last_used_days": "-1"}), true},
		{"never used anything, old user", withMeta(base, map[string]string{"password_last_used_days": "-1", "access_key_last_used_days": "-1"}), true},
		{"never used anything, new user", withMeta(base, map[string]string{"password_last_used_days": "-1", "access_key_last_used_days": "-1", "created_days": "20"}), false},
		{"never used anything, age unknown", withMeta(base, map[string]string{"password_last_used_days": "-1", "access_key_last_used_days": "-1", "created_days": ""}), false},
		{"key last-use unread", withMeta(base, map[string]string{"access_key_last_used_days": ""}), false},
		{"credential state unread", withMeta(base, map[string]string{"inactive": ""}), false},
		{"no usable credential (inactive user)", withMeta(base, map[string]string{"inactive": "true"}), false},
		{"not admin", withMeta(base, map[string]string{"admin": "", "privilege_tier": "standard"}), false},
		{"not admin, can escalate to admin", withMeta(base, map[string]string{"admin": "", "privilege_tier": "can_escalate_to_admin"}), true},
		{"not admin, standard tier", withMeta(base, map[string]string{"admin": "", "privilege_tier": "standard"}), false},
		{"not admin, tier unknown", withMeta(base, map[string]string{"admin": "", "privilege_tier": "unknown"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, dormantAdminUser(asset.Asset{Metadata: tt.md}))
		})
	}
}

func TestDormantAdminSA(t *testing.T) {
	base := map[string]string{"disabled": "false", "roles": "roles/viewer,roles/editor", "sa_last_auth_days": "120"}
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"editor idle past threshold", base, true},
		{"owner idle", withMeta(base, map[string]string{"roles": "roles/owner"}), true},
		{"project IAM admin idle", withMeta(base, map[string]string{"roles": "roles/resourcemanager.projectIamAdmin"}), true},
		{"non-admin roles", withMeta(base, map[string]string{"roles": "roles/viewer,roles/storage.objectViewer"}), false},
		{"non-admin roles, can escalate to admin", withMeta(base, map[string]string{"roles": "roles/iam.serviceAccountTokenCreator", "privilege_tier": "can_escalate_to_admin"}), true},
		{"non-admin roles, tier unknown", withMeta(base, map[string]string{"roles": "roles/viewer", "privilege_tier": "unknown"}), false},
		{"recently authenticated", withMeta(base, map[string]string{"sa_last_auth_days": "10"}), false},
		{"no activity in window, old key proves age", withMeta(base, map[string]string{"sa_last_auth_days": "-1", "key_age_days": "300"}), true},
		{"no activity in window, young key", withMeta(base, map[string]string{"sa_last_auth_days": "-1", "key_age_days": "5"}), false},
		{"no activity in window, age unknown", withMeta(base, map[string]string{"sa_last_auth_days": "-1"}), false},
		{"Policy Analyzer unavailable", withMeta(base, map[string]string{"sa_last_auth_days": ""}), false},
		{"disabled account", withMeta(base, map[string]string{"disabled": "true"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, dormantAdminSA(asset.Asset{Metadata: tt.md}))
		})
	}
}

// The title names whether the principal holds admin or can escalate to it, and
// the evidence carries the tier stamp that decided it.
func TestDormantAdminTitleDistinguishesEscalation(t *testing.T) {
	role := map[string]string{"organization_policy_complete": "true", "last_used_observed": "true", "last_used_days": "200", "created_days": "400", "path": "/"}
	user := map[string]string{"organization_policy_complete": "true", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "150", "created_days": "900"}
	sa := map[string]string{"disabled": "false", "sa_last_auth_days": "200"}
	escalate := map[string]string{"privilege_tier": "can_escalate_to_admin", "privilege_tier_source": "ciem:aws-privesc-06"}
	tests := []struct {
		check            Check
		admin, base      map[string]string
		wantAdminTitle   string
		wantEscalateWord string
	}{
		{awsIAMAdminRoleDormant, map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin"}, role, "Admin IAM role", "IAM role that can escalate to admin"},
		{awsIAMAdminUserDormant, map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin"}, user, "Admin IAM user", "IAM user that can escalate to admin"},
		{gcpSAAdminDormant, map[string]string{"roles": "roles/owner"}, sa, "Admin-equivalent service account", "Service account that can escalate to admin"},
	}
	for _, tt := range tests {
		t.Run(tt.check.ID, func(t *testing.T) {
			build := func(extra map[string]string) []finding.Finding {
				md := maps.Clone(tt.base)
				maps.Copy(md, extra)
				reg := NewRegistry()
				reg.Register(tt.check)
				return reg.Run([]asset.Asset{{ID: "p", Type: tt.check.AssetType, Provider: tt.check.Provider, Metadata: md}}, time.Now())
			}
			admin := build(tt.admin)
			require.Len(t, admin, 1)
			require.Contains(t, admin[0].Title, tt.wantAdminTitle)

			esc := build(escalate)
			require.Len(t, esc, 1)
			require.Contains(t, esc[0].Title, tt.wantEscalateWord)
			require.Equal(t, admin[0].ID, esc[0].ID, "same principal, same finding row whichever title applies")
			require.Equal(t, "can_escalate_to_admin", esc[0].Metadata["privilege_tier"])
			require.Equal(t, "ciem:aws-privesc-06", esc[0].Metadata["privilege_tier_source"])
		})
	}
}

// A dormant admin principal is ONE finding. Every hygiene check describing the
// same idleness steps aside, and still fires for the same data on a non-admin —
// and when the dormant-admin verdict is unknown, so a coverage gap never makes
// both checks silent.
func TestDormantAdminOwnsThePrincipal(t *testing.T) {
	adminRole := map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "last_used_observed": "true", "last_used_days": "200", "created_days": "400", "path": "/",
		"aa_services_granted": "300", "aa_services_used": "0"}
	adminUser := map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inactive": "false", "console_access": "true", "password_last_used_days": "200",
		"active_key_count": "1", "access_key_stale": "true", "access_key_last_used_days": "150", "access_key_age_days": "400",
		"created_days": "900", "mfa_enabled": "false"}
	adminSA := map[string]string{"disabled": "false", "roles": "roles/owner", "roles_complete": "true", "permissions_complete": "true", "sa_last_auth_days": "200", "key_count": "1", "key_age_days": "400"}

	tests := []struct {
		name      string
		owner     Check
		stepAside Check
		md        map[string]string
		// notOwned makes the principal something the owner does not claim (not
		// admin, or admin but in use) while the hygiene evidence still holds.
		notOwned map[string]string
		// unknownOverride makes the owner's verdict unknown while leaving the
		// step-aside check's own evidence intact.
		unknownOverride map[string]string
	}{
		{"role-unused", awsIAMAdminRoleDormant, awsIAMRoleUnused, adminRole,
			map[string]string{"admin": "", "privilege_tier": "standard"}, map[string]string{"last_used_observed": ""}},
		{"overprivileged-role", awsIAMAdminRoleDormant, awsIAMOverprivilegedRole, adminRole,
			map[string]string{"last_used_days": "3"}, map[string]string{"last_used_observed": "", "last_used_days": ""}},
		{"user-unused-access-key", awsIAMAdminUserDormant, awsIAMUserUnusedAccessKey, adminUser,
			map[string]string{"password_last_used_days": "1"}, map[string]string{"created_days": "", "access_key_last_used_days": "-1", "password_last_used_days": "-1"}},
		{"user-stale-console", awsIAMAdminUserDormant, awsIAMUserStaleConsole, adminUser,
			map[string]string{"admin": "", "privilege_tier": "standard"}, map[string]string{"access_key_last_used_days": ""}},
		{"access-key-old", awsIAMAdminUserDormant, awsIAMAccessKeyOld, adminUser,
			map[string]string{"access_key_last_used_days": "1"}, map[string]string{"access_key_last_used_days": ""}},
		{"gcp-sa-unused", gcpSAAdminDormant, gcpSAUnused, adminSA,
			map[string]string{"roles": "roles/viewer"}, map[string]string{"key_age_days": "", "sa_last_auth_days": "-1"}},
		{"gcp-sa-user-managed-key", gcpSAAdminDormant, gcpSAUserManagedKey, adminSA,
			map[string]string{"sa_last_auth_days": "2"}, map[string]string{"sa_last_auth_days": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			build := func(md map[string]string) asset.Asset {
				return asset.Asset{ID: "p", Type: tt.owner.AssetType, Provider: tt.owner.Provider, Metadata: md}
			}
			dormant := build(tt.md)
			require.True(t, tt.owner.Violates(dormant), "the dormant-admin check owns this principal")
			require.False(t, tt.stepAside.Violates(dormant), "the hygiene check steps aside for it")

			reg := Default()
			c, ok := reg.ByID(tt.stepAside.ID)
			require.True(t, ok)
			require.True(t, c.Evaluable(dormant), "stepping aside on observed data is an observation, so a prior finding may close")

			notOwned := build(withMeta(tt.md, tt.notOwned))
			require.False(t, tt.owner.Violates(notOwned))
			require.True(t, tt.stepAside.Violates(notOwned), "a principal the owner does not claim keeps its hygiene finding")

			unknown := build(withMeta(tt.md, tt.unknownOverride))
			require.False(t, tt.owner.Violates(unknown), "the override must make the dormant-admin verdict unknown")
			require.True(t, tt.stepAside.Violates(unknown), "an unknown dormant-admin verdict must not silence the hygiene finding too")
		})
	}
}

func TestAccessKeyAgeTiers(t *testing.T) {
	tests := []struct {
		name      string
		md        map[string]string
		fires     bool
		severity  finding.Severity
		titleHint string
	}{
		{"young key", map[string]string{"access_key_age_days": "30"}, false, "", ""},
		{"past rotation", map[string]string{"access_key_age_days": "91"}, true, finding.SeverityMedium, "older than 90 days"},
		{"past a year", map[string]string{"access_key_age_days": "366"}, true, finding.SeverityHigh, "older than a year"},
		{"admin past rotation", map[string]string{"access_key_age_days": "91", "admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin"}, true, finding.SeverityHigh, "Admin IAM user"},
		{"admin young key", map[string]string{"access_key_age_days": "30", "admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin"}, false, "", ""},
		{"age unread", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin"}, false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := asset.Asset{Metadata: tt.md}
			require.Equal(t, tt.fires, awsIAMAccessKeyOld.Violates(a))
			if !tt.fires {
				return
			}
			require.Equal(t, tt.severity, awsIAMAccessKeyOld.SeverityFor(a))
			require.Contains(t, awsIAMAccessKeyOld.TitleFor(a), tt.titleHint)
		})
	}
}

func TestGCPUserManagedKeyAdminTier(t *testing.T) {
	sev := func(md map[string]string) finding.Severity {
		return gcpSAUserManagedKey.SeverityFor(asset.Asset{Metadata: md})
	}
	require.Equal(t, finding.SeverityLow, sev(map[string]string{"key_count": "1", "key_age_days": "30", "roles": "roles/owner"}))
	require.Equal(t, finding.SeverityHigh, sev(map[string]string{"key_count": "1", "key_age_days": "100", "roles": "roles/owner"}))
	require.Equal(t, finding.SeverityMedium, sev(map[string]string{"key_count": "1", "key_age_days": "100", "roles": "roles/viewer"}))
	require.Equal(t, finding.SeverityHigh, sev(map[string]string{"key_count": "1", "key_age_days": "400", "roles": "roles/viewer"}))
}

func TestAdminUserKeyNoMFA(t *testing.T) {
	base := map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "console_access": "false", "mfa_enabled": "false", "active_key_count": "1",
		"inactive": "false", "password_last_used_days": "-1", "access_key_last_used_days": "2", "created_days": "900"}
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"key-only admin without MFA", base, true},
		{"has an MFA device", withMeta(base, map[string]string{"mfa_enabled": "true"}), false},
		{"console user — aws-iam-user-no-mfa's case", withMeta(base, map[string]string{"console_access": "true"}), false},
		{"no active key", withMeta(base, map[string]string{"active_key_count": "0"}), false},
		{"not admin", withMeta(base, map[string]string{"admin": "", "privilege_tier": "standard"}), false},
		{"MFA list unread", withMeta(base, map[string]string{"mfa_enabled": ""}), false},
		{"key list unread", withMeta(base, map[string]string{"active_key_count": ""}), false},
		{"dormant admin is aws-iam-admin-user-dormant's finding", withMeta(base, map[string]string{"access_key_last_used_days": "200"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, awsIAMAdminUserKeyNoMFA.Violates(asset.Asset{Metadata: tt.md}))
		})
	}
}
