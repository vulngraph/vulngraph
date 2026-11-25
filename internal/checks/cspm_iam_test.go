package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestIAMCredentialHygieneChecks(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		md    map[string]string
		want  bool
	}{
		{"inactive user flagged", awsIAMUserInactive, map[string]string{"inactive": "true"}, true},
		{"active user not flagged", awsIAMUserInactive, map[string]string{"inactive": "false"}, false},

		{"two keys flagged", awsIAMUserMultipleActiveKeys, map[string]string{"active_key_count": "2"}, true},
		{"one key ok", awsIAMUserMultipleActiveKeys, map[string]string{"active_key_count": "1"}, false},
		{"zero keys ok", awsIAMUserMultipleActiveKeys, map[string]string{"active_key_count": "0"}, false},
		{"missing count ok", awsIAMUserMultipleActiveKeys, map[string]string{}, false},

		{"stale console flagged", awsIAMUserStaleConsole, map[string]string{"console_access": "true", "password_last_used_days": "120"}, true},
		{"never-used console flagged", awsIAMUserStaleConsole, map[string]string{"console_access": "true", "password_last_used_days": "-1"}, true},
		{"recent console ok", awsIAMUserStaleConsole, map[string]string{"console_access": "true", "password_last_used_days": "3"}, false},
		{"no console access ok", awsIAMUserStaleConsole, map[string]string{"console_access": "false", "password_last_used_days": "-1"}, false},

		{"stale active key flagged", awsIAMUserUnusedAccessKey, map[string]string{"active_key_count": "1", "access_key_stale": "true"}, true},
		{"active key in use ok", awsIAMUserUnusedAccessKey, map[string]string{"active_key_count": "1", "access_key_stale": "false"}, false},
		{"stale flag but no active key ok", awsIAMUserUnusedAccessKey, map[string]string{"active_key_count": "0", "access_key_stale": "true"}, false},
		{"no key metadata ok", awsIAMUserUnusedAccessKey, map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.check.Violates(asset.Asset{
				Provider: asset.ProviderAWS, Type: "iam_user", Metadata: tt.md,
			}))
		})
	}
}

// The three checks are wired into the default registry.
func TestIAMCredentialHygieneChecksRegistered(t *testing.T) {
	got := map[string]bool{}
	for _, c := range Default().checks {
		got[c.ID] = true
	}
	for _, id := range []string{"aws-iam-user-inactive", "aws-iam-user-multiple-active-keys", "aws-iam-user-unused-access-key", "aws-iam-user-stale-console"} {
		require.True(t, got[id], "check %q not registered in Default()", id)
	}
}

// console_access on the root asset is the credential report's root
// password_enabled. A root without a password (centralized root access) has
// no sign-in for MFA to protect; an unknown password status still fires on
// missing MFA, and unknown MFA grades nothing.
func TestRootMFAChecks(t *testing.T) {
	root := func(md map[string]string) asset.Asset {
		md["root"] = "true"
		return asset.Asset{ID: "arn:aws:iam::111:root", Type: "iam_user", Provider: asset.ProviderAWS, Metadata: md}
	}
	tests := []struct {
		name      string
		md        map[string]string
		fires     bool
		evaluable bool
		title     string
	}{
		{"password, no MFA", map[string]string{"console_access": "true", "mfa_enabled": "false"}, true, true, "AWS root account has no MFA"},
		{"password and MFA", map[string]string{"console_access": "true", "mfa_enabled": "true"}, false, true, ""},
		{"no password", map[string]string{"console_access": "false", "mfa_enabled": "false"}, false, true, ""},
		{"no password, MFA", map[string]string{"console_access": "false", "mfa_enabled": "true"}, false, true, ""},
		{"password status not_supported or unread, no MFA", map[string]string{"mfa_enabled": "false"}, true, false, "AWS root account has no MFA (root password status unknown)"},
		{"password status not_supported or unread, MFA", map[string]string{"mfa_enabled": "true"}, false, true, ""},
		{"MFA unread", map[string]string{"console_access": "true"}, false, false, ""},
		{"nothing read", map[string]string{}, false, false, ""},
	}
	rootNoMFA := registered(t, awsIAMRootNoMFA.ID)
	userNoMFA := registered(t, awsIAMUserNoMFA.ID)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := root(tt.md)
			require.Equal(t, tt.fires, rootNoMFA.Violates(a))
			if tt.fires {
				require.Equal(t, tt.title, rootNoMFA.TitleFor(a))
			} else {
				require.Equal(t, tt.evaluable, rootNoMFA.Evaluable(a), "unread MFA is unknown, never clean")
			}
			require.False(t, userNoMFA.Violates(a), "root is aws-iam-root-no-mfa's alone")
		})
	}
	user := asset.Asset{ID: "arn:aws:iam::111:user/alice", Type: "iam_user", Provider: asset.ProviderAWS,
		Metadata: map[string]string{"console_access": "true", "mfa_enabled": "false"}}
	require.True(t, userNoMFA.Violates(user))
	require.False(t, rootNoMFA.Violates(user))
}
