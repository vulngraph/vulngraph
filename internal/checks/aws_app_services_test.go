package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func strongCognitoPolicy() map[string]string {
	return map[string]string{
		"password_min_length": "8", "password_require_uppercase": "true", "password_require_lowercase": "true",
		"password_require_numbers": "true", "password_require_symbols": "true", "temporary_password_validity_days": "7",
	}
}

func TestCognitoWeakPasswordPolicy(t *testing.T) {
	tests := []struct {
		name     string
		override map[string]string
		fires    bool
	}{
		{"security hub defaults pass", nil, false},
		{"length 7", map[string]string{"password_min_length": "7"}, true},
		{"length 99", map[string]string{"password_min_length": "99"}, false},
		{"no uppercase", map[string]string{"password_require_uppercase": "false"}, true},
		{"no lowercase", map[string]string{"password_require_lowercase": "false"}, true},
		{"no numbers", map[string]string{"password_require_numbers": "false"}, true},
		{"no symbols", map[string]string{"password_require_symbols": "false"}, true},
		{"temporary 8 days", map[string]string{"temporary_password_validity_days": "8"}, true},
		{"temporary 1 day", map[string]string{"temporary_password_validity_days": "1"}, false},
	}
	for _, tt := range tests {
		md := strongCognitoPolicy()
		for k, v := range tt.override {
			md[k] = v
		}
		require.Equal(t, tt.fires, awsCognitoWeakPasswordPolicy.Violates(awsAsset("cognito_user_pool", md)), tt.name)
	}
	md := strongCognitoPolicy()
	delete(md, "password_min_length")
	require.False(t, awsCognitoWeakPasswordPolicy.Violates(awsAsset("cognito_user_pool", md)), "an unread length is not a short one")
}

func TestCognitoThreatProtection(t *testing.T) {
	tests := []struct {
		mode, custom string
		fires        bool
	}{
		{"OFF", "", true},
		{"AUDIT", "", true},
		{"AUDIT", "ENFORCED", true}, // standard auth in audit mode fails Cognito.1
		{"ENFORCED", "", true},
		{"ENFORCED", "AUDIT", true},
		{"ENFORCED", "ENFORCED", false},
	}
	for _, tt := range tests {
		a := awsAsset("cognito_user_pool", map[string]string{"threat_protection_mode": tt.mode, "threat_protection_custom_auth_mode": tt.custom})
		require.Equal(t, tt.fires, awsCognitoThreatProtectionNotEnforced.Violates(a), "%+v", tt)
	}
}

func TestCognitoUserPoolNoMFA(t *testing.T) {
	for _, tt := range []struct {
		mfa, pwOnly string
		fires       bool
	}{
		{"OFF", "true", true},
		{"OFF", "false", false}, // a passwordless first factor is out of scope
		{"OPTIONAL", "true", false},
		{"ON", "true", false},
	} {
		a := awsAsset("cognito_user_pool", map[string]string{"mfa_configuration": tt.mfa, "password_only_sign_in": tt.pwOnly})
		require.Equal(t, tt.fires, awsCognitoUserPoolNoMFA.Violates(a), "%+v", tt)
	}
}

func TestEMRBlockPublicAccess(t *testing.T) {
	tests := []struct {
		bpa, ports string
		fires      bool
		sev        finding.Severity
	}{
		{"true", "22", false, ""},
		{"true", "", false, ""},
		{"true", "22,8080", true, finding.SeverityLow},
		{"true", "20-30", true, finding.SeverityLow},
		{"false", "22", true, finding.SeverityMedium},
		{"false", "", true, finding.SeverityMedium},
	}
	for _, tt := range tests {
		a := awsAsset("emr_settings", map[string]string{"block_public_security_group_rules": tt.bpa, "permitted_public_ports": tt.ports})
		require.Equal(t, tt.fires, awsEMRBlockPublicAccessOff.Violates(a), "%+v", tt)
		if tt.fires {
			require.Equal(t, tt.sev, awsEMRBlockPublicAccessOff.SeverityFor(a), "%+v", tt)
		}
	}
}

func TestEMRPrimaryPublicIPOnlyRunningClusters(t *testing.T) {
	for st, fires := range map[string]bool{"RUNNING": true, "WAITING": true, "STARTING": false, "BOOTSTRAPPING": false} {
		a := awsAsset("emr_cluster", map[string]string{"state": st, "primary_public_ips": "3.3.3.3"})
		require.Equal(t, fires, awsEMRPrimaryPublicIP.Violates(a), st)
	}
}

func TestAppSyncChecks(t *testing.T) {
	for v, fires := range map[string]bool{"API_KEY": true, "AWS_IAM,API_KEY": true, "AWS_LAMBDA,OPENID_CONNECT": false, "API_KEYS": false} {
		require.Equal(t, fires, awsAppSyncAPIKeyAuth.Violates(awsAsset("appsync_graphql_api", map[string]string{"authentication_types": v})), v)
	}
	for v, fires := range map[string]bool{"": true, "NONE": true, "ERROR": false, "ALL": false, "INFO": false, "DEBUG": false} {
		require.Equal(t, fires, awsAppSyncFieldLoggingDisabled.Violates(awsAsset("appsync_graphql_api", map[string]string{"field_log_level": v})), v)
	}
	noCache := awsAsset("appsync_graphql_api", map[string]string{"api_cache": "false"})
	require.False(t, awsAppSyncCacheNotEncryptedAtRest.Violates(noCache), "no cache, nothing to encrypt")
	require.False(t, awsAppSyncCacheNotEncryptedInTransit.Violates(noCache))
}

func TestCodeBuildLogging(t *testing.T) {
	for _, tt := range []struct {
		cw, s3 string
		fires  bool
	}{
		{"DISABLED", "DISABLED", true},
		{"ENABLED", "DISABLED", false},
		{"DISABLED", "ENABLED", false},
	} {
		a := awsAsset("codebuild_project", map[string]string{"cloudwatch_logs_status": tt.cw, "s3_logs_status": tt.s3})
		require.Equal(t, tt.fires, awsCodeBuildLoggingDisabled.Violates(a), "%+v", tt)
	}
	// S3 logs off: nothing written to S3, so nothing unencrypted.
	off := awsAsset("codebuild_project", map[string]string{"s3_logs_status": "DISABLED", "s3_logs_encryption_disabled": "true"})
	require.False(t, awsCodeBuildS3LogsUnencrypted.Violates(off))
}
