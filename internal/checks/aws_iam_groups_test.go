package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestIAMGroupFullAdmin(t *testing.T) {
	tests := []struct {
		name  string
		md    map[string]string
		fires bool
		sev   finding.Severity
	}{
		{"admin group with members", map[string]string{"admin": "true", "full_admin_customer_policy_only": "false", "member_count": "4"}, true, finding.SeverityHigh},
		{"admin group, members unread", map[string]string{"admin": "true", "full_admin_customer_policy_only": "false"}, true, finding.SeverityHigh},
		{"empty admin group", map[string]string{"admin": "true", "full_admin_customer_policy_only": "false", "member_count": "0"}, true, finding.SeverityLow},
		{"admin only via a customer policy steps aside", map[string]string{"admin": "true", "full_admin_customer_policy_only": "true", "member_count": "4"}, false, ""},
		{"admin via NotAction (no full_admin key)", map[string]string{"admin": "true", "member_count": "1"}, true, finding.SeverityHigh},
		{"not admin", map[string]string{"admin": "false", "member_count": "4"}, false, ""},
	}
	for _, tt := range tests {
		a := awsAsset("iam_group", tt.md)
		require.Equal(t, tt.fires, awsIAMGroupFullAdmin.Violates(a), tt.name)
		if tt.fires {
			require.Equal(t, tt.sev, awsIAMGroupFullAdmin.SeverityFor(a), tt.name)
		}
	}
}

func TestIAMGroupGrantChecksStepAsideForAdmin(t *testing.T) {
	admin := awsAsset("iam_group", map[string]string{"admin": "true", "cloudshell_full_access": "true", "inline_kms_decrypt_all": "true"})
	require.False(t, awsIAMGroupCloudShellFullAccess.Violates(admin))
	require.False(t, awsIAMGroupInlineKMSDecryptAll.Violates(admin))
}

func TestCustomerPolicyAttachmentGrading(t *testing.T) {
	tests := []struct {
		name  string
		md    map[string]string
		fires bool
		sev   finding.Severity
	}{
		{"attached", map[string]string{"managed_by": "customer", "full_admin": "true", "attachment_count": "2", "boundary_usage_count": "0"}, true, finding.SeverityHigh},
		{"count unread (principal listing)", map[string]string{"managed_by": "customer", "full_admin": "true"}, true, finding.SeverityHigh},
		{"unattached", map[string]string{"managed_by": "customer", "full_admin": "true", "attachment_count": "0", "boundary_usage_count": "0"}, true, finding.SeverityLow},
		{"boundary only", map[string]string{"managed_by": "customer", "full_admin": "true", "attachment_count": "0", "boundary_usage_count": "5"}, false, ""},
		{"attached and a boundary", map[string]string{"managed_by": "customer", "full_admin": "true", "attachment_count": "1", "boundary_usage_count": "5"}, true, finding.SeverityHigh},
		{"aws managed", map[string]string{"managed_by": "aws", "full_admin": "true", "attachment_count": "1"}, false, ""},
	}
	for _, tt := range tests {
		a := awsAsset("iam_policy", tt.md)
		require.Equal(t, tt.fires, awsIAMPolicyFullAdmin.Violates(a), tt.name)
		if tt.fires {
			require.Equal(t, tt.sev, awsIAMPolicyFullAdmin.SeverityFor(a), tt.name)
		}
	}
	unattachedKMS := awsAsset("iam_policy", map[string]string{"managed_by": "customer", "full_admin": "false", "kms_decrypt_all_resources": "true", "attachment_count": "0", "boundary_usage_count": "0"})
	require.True(t, awsIAMPolicyKMSDecryptAll.Violates(unattachedKMS))
	require.Equal(t, finding.SeverityLow, awsIAMPolicyKMSDecryptAll.SeverityFor(unattachedKMS))
}

// A policy type switched off at the root is one organization finding; the
// accounts it leaves unguarded step aside for it.
func TestOrgAccountGuardrailsStepAsideForDisabledPolicyType(t *testing.T) {
	off := awsAsset("aws_org_account", map[string]string{"scp_guardrail": "false", "scp_enabled": "false", "rcp_guardrail": "false", "rcp_enabled": "false"})
	require.False(t, awsOrgAccountNoSCPGuardrail.Violates(off))
	require.False(t, awsOrgAccountNoRCPGuardrail.Violates(off))
	org := awsAsset("aws_organization", map[string]string{"scp_enabled": "false", "rcp_enabled": "false"})
	require.True(t, awsOrgGuardrailPolicyTypeDisabled.Violates(org))
	require.Equal(t, "Organization has service control policies and resource control policies switched off", awsOrgGuardrailPolicyTypeDisabled.TitleFor(org))
}

func TestIAMUserCredentialUnused45dBand(t *testing.T) {
	tests := []struct {
		name  string
		md    map[string]string
		fires bool
	}{
		{"password idle 60d", map[string]string{"console_access": "true", "password_last_used_days": "60"}, true},
		{"password idle 90d is the stale-console finding", map[string]string{"console_access": "true", "password_last_used_days": "90"}, false},
		{"password never used is the stale-console finding", map[string]string{"console_access": "true", "password_last_used_days": "-1"}, false},
		{"password idle 44d", map[string]string{"console_access": "true", "password_last_used_days": "44"}, false},
		{"no console, stale password date", map[string]string{"console_access": "false", "password_last_used_days": "60"}, false},
		{"key idle 45d", map[string]string{"active_key_count": "1", "access_key_max_idle_days": "45"}, true},
		{"key idle 120d is the unused-key finding", map[string]string{"active_key_count": "1", "access_key_max_idle_days": "120"}, false},
		{"no active key", map[string]string{"active_key_count": "0", "access_key_max_idle_days": "-1"}, false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.fires, awsIAMUserCredentialUnused45d.Violates(awsAsset("iam_user", tt.md)), tt.name)
	}
}
