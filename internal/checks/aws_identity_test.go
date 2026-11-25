package checks

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// daysAgo renders a timestamp n days in the past, the shape the collector
// stores dates in.
func daysAgo(n int) string {
	return time.Now().Add(-time.Duration(n) * 24 * time.Hour).UTC().Format(time.RFC3339)
}

func strongPasswordPolicy() map[string]string {
	return map[string]string{
		"password_policy": "present", "password_min_length": "14", "password_reuse_prevention": "24",
		"password_require_uppercase": "true", "password_require_lowercase": "true",
		"password_require_numbers": "true", "password_require_symbols": "true",
	}
}

func TestPasswordPolicyWeaknesses(t *testing.T) {
	with := func(k, v string) map[string]string {
		md := strongPasswordPolicy()
		md[k] = v
		return md
	}
	tests := []struct {
		name string
		md   map[string]string
		want int
	}{
		{"strong", strongPasswordPolicy(), 0},
		{"absent policy", map[string]string{"password_policy": "absent"}, 1},
		{"short", with("password_min_length", "8"), 1},
		{"no reuse prevention", with("password_reuse_prevention", "0"), 1},
		{"reuse 12 is below CIS 24", with("password_reuse_prevention", "12"), 1},
		{"no symbols", with("password_require_symbols", "false"), 1},
		{"unread", map[string]string{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := awsAsset("aws_account_settings", tt.md)
			require.Len(t, passwordPolicyWeaknesses(a), tt.want)
			require.Equal(t, tt.want > 0, awsIAMWeakPasswordPolicy.Violates(a))
		})
	}
}

// The no-trail account is the case per-trail grading could never report.
func TestCloudTrailNoMultiRegionTrailTitles(t *testing.T) {
	none := awsAsset("aws_account_settings", map[string]string{"cloudtrail_multi_region_logging": "false", "cloudtrail_trail_count": "0"})
	require.True(t, awsCloudTrailNoMultiRegionTrail.Violates(none))
	require.Equal(t, "AWS account has no CloudTrail trail", awsCloudTrailNoMultiRegionTrail.TitleFor(none))
	single := awsAsset("aws_account_settings", map[string]string{"cloudtrail_multi_region_logging": "false", "cloudtrail_trail_count": "2"})
	require.Equal(t, "No multi-region CloudTrail trail is logging", awsCloudTrailNoMultiRegionTrail.TitleFor(single))
}

func TestSnapshotBPASeverity(t *testing.T) {
	newSharing := awsAsset("aws_region_settings", map[string]string{"snapshot_block_public_access": "block-new-sharing"})
	require.True(t, awsEBSSnapshotBPADisabled.Violates(newSharing))
	require.Equal(t, finding.SeverityLow, awsEBSSnapshotBPADisabled.SeverityFor(newSharing))
	unblocked := awsAsset("aws_region_settings", map[string]string{"snapshot_block_public_access": "unblocked"})
	require.Equal(t, finding.SeverityMedium, awsEBSSnapshotBPADisabled.SeverityFor(unblocked))
}

// S3: the four-flag rule fires where the two neutralizing flags alone used to
// read as safe, and each tier says which condition it is.
func TestS3PublicBucketFourFlagTiers(t *testing.T) {
	tests := []struct {
		name     string
		md       map[string]string
		fires    bool
		title    string
		severity finding.Severity
	}{
		{"confirmed public", map[string]string{"public_access": "confirmed", "public": "true", "bpa_all_enabled": "false"}, true, "S3 bucket is public", finding.SeverityHigh},
		{"no block at all", map[string]string{"public_access": "possible", "public": "true", "bpa_all_enabled": "false"}, true, "S3 bucket has no Block Public Access", finding.SeverityLow},
		{"neutralized but two flags off", map[string]string{"public_access": "none", "public": "false", "bpa_all_enabled": "false"}, true, "S3 bucket Block Public Access is not fully enabled", finding.SeverityLow},
		{"all four on", map[string]string{"public_access": "none", "public": "false", "bpa_all_enabled": "true"}, false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := awsAsset("s3_bucket", tt.md)
			require.Equal(t, tt.fires, awsS3PublicBucket.Violates(a))
			if tt.fires {
				require.Equal(t, tt.title, awsS3PublicBucket.TitleFor(a))
				require.Equal(t, tt.severity, awsS3PublicBucket.SeverityFor(a))
			}
		})
	}
}

// One finding per admin principal: every more specific report wins.
func TestRoleFullAdminStepsAside(t *testing.T) {
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"plain admin role", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "path": "/"}, true},
		{"not admin", map[string]string{"path": "/"}, false},
		{"admin only via customer policy", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "path": "/", "full_admin_customer_policy_only": "true"}, false},
		{"customer and AWS-managed admin", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "path": "/", "full_admin_customer_policy_only": "false"}, true},
		{"service-linked", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "path": "/aws-service-role/x/"}, false},
		{"identity center role", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "path": "/aws-reserved/sso.amazonaws.com/"}, false},
		{"access advisor evidence", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "path": "/", "aa_services_granted": "300", "aa_services_used": "4"}, false},
		{"dormant", map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "path": "/", "last_used_observed": "true", "last_used_days": "200"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := awsAsset("iam_role", tt.md)
			require.Equal(t, tt.want, awsIAMRoleFullAdmin.Violates(a))
			if tt.name == "access advisor evidence" {
				require.True(t, awsIAMOverprivilegedRole.Violates(a), "the role must still be reported by the check it stepped aside for")
			}
			if tt.name == "dormant" {
				require.True(t, awsIAMAdminRoleDormant.Violates(a), "the role must still be reported by the check it stepped aside for")
			}
		})
	}
}

func TestUserFullAdminStepsAsideForDormant(t *testing.T) {
	active := map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inactive": "false", "password_last_used_days": "1", "access_key_last_used_days": "-1"}
	require.True(t, awsIAMUserFullAdmin.Violates(awsAsset("iam_user", active)))
	dormant := map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inactive": "false", "password_last_used_days": "200", "access_key_last_used_days": "-1"}
	require.False(t, awsIAMUserFullAdmin.Violates(awsAsset("iam_user", dormant)))
	require.True(t, awsIAMAdminUserDormant.Violates(awsAsset("iam_user", dormant)))
}

func TestAdminPrincipalStepsAsideForNarrowerGrants(t *testing.T) {
	for _, c := range []Check{awsIAMUserInlineKMSDecryptAll, awsIAMRoleInlineKMSDecryptAll, awsIAMUserCloudShellFullAccess, awsIAMRoleCloudShellFullAccess} {
		a := awsAsset(c.AssetType, map[string]string{"admin": "true", "organization_policy_complete": "true", "privilege_tier": "admin", "inline_kms_decrypt_all": "true", "cloudshell_full_access": "true"})
		require.False(t, c.Violates(a), "%s: an admin principal is reported by its admin finding", c.ID)
	}
	// An AWS-managed policy shares one ARN across accounts: never a per-policy finding.
	aws := awsAsset("iam_policy", map[string]string{"managed_by": "aws", "full_admin": "true"})
	require.False(t, awsIAMPolicyFullAdmin.Violates(aws))
	admin := awsAsset("iam_policy", map[string]string{"managed_by": "customer", "full_admin": "true", "kms_decrypt_all_resources": "true", "service_wildcard_actions": "s3:*"})
	require.True(t, awsIAMPolicyFullAdmin.Violates(admin))
	require.False(t, awsIAMPolicyKMSDecryptAll.Violates(admin), "a full-admin policy is one finding")
	require.False(t, awsIAMPolicyServiceWildcard.Violates(admin), "a full-admin policy is one finding")
}

func TestRootRecentlyUsed(t *testing.T) {
	tests := []struct {
		name string
		used string
		want bool
	}{
		{"yesterday", daysAgo(1), true},
		{"29 days", daysAgo(29), true},
		{"31 days", daysAgo(31), false},
		{"never", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, awsIAMRootRecentlyUsed.Violates(awsAsset("iam_user", map[string]string{"root": "true", "root_last_used": tt.used})))
		})
	}
	require.False(t, awsIAMRootRecentlyUsed.Violates(awsAsset("iam_user", map[string]string{"root_last_used": daysAgo(1)})), "only the root user")
}

// An unread date must never let the lifecycle read silence as a fix: the date
// probes make a predicate with an absent timestamp unevaluable.
func TestDateChecksAreUnevaluableWithoutTheirDates(t *testing.T) {
	r := Default()
	for _, tt := range []struct {
		id string
		md map[string]string
	}{
		{"aws-iam-root-recently-used", map[string]string{"root": "true"}},
		{"aws-secretsmanager-unused", map[string]string{"created_at": daysAgo(400)}},
		{"aws-secretsmanager-rotation-overdue", map[string]string{"rotation_enabled": "true", "rotation_interval_days": "30"}},
		{"aws-secretsmanager-not-rotated-90d", map[string]string{"rotation_enabled": "true", "last_rotated": ""}},
	} {
		c, ok := r.ByID(tt.id)
		require.True(t, ok)
		require.False(t, c.Evaluable(awsAsset(c.AssetType, tt.md)), "%s: an absent date is not a clean observation", tt.id)
	}
}

func TestSecretRotationChecks(t *testing.T) {
	tests := []struct {
		name              string
		md                map[string]string
		overdue, stale90d bool
	}{
		{"rotating on time", map[string]string{"rotation_enabled": "true", "rotation_interval_days": "30", "last_rotated": daysAgo(20)}, false, false},
		{"missed 30-day schedule", map[string]string{"rotation_enabled": "true", "rotation_interval_days": "30", "last_rotated": daysAgo(95)}, true, false},
		{"yearly schedule, on time but over 90", map[string]string{"rotation_enabled": "true", "rotation_interval_days": "365", "last_rotated": daysAgo(120)}, false, true},
		{"never rotated, created long ago", map[string]string{"rotation_enabled": "true", "rotation_interval_days": "30", "last_rotated": "", "created_at": daysAgo(60)}, true, false},
		{"cron schedule, old", map[string]string{"rotation_enabled": "true", "last_rotated": daysAgo(100)}, false, true},
		{"rotation off is no-rotation's finding", map[string]string{"rotation_enabled": "false", "last_rotated": "", "created_at": daysAgo(400)}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := awsAsset("secretsmanager_secret", tt.md)
			require.Equal(t, tt.overdue, awsSecretRotationOverdue.Violates(a), "overdue")
			require.Equal(t, tt.stale90d, awsSecretNotRotated90d.Violates(a), "90d")
		})
	}
}

func TestSecretUnused(t *testing.T) {
	require.True(t, awsSecretUnused.Violates(awsAsset("secretsmanager_secret", map[string]string{"last_accessed": "", "created_at": daysAgo(100)})), "never read and old")
	require.False(t, awsSecretUnused.Violates(awsAsset("secretsmanager_secret", map[string]string{"last_accessed": "", "created_at": daysAgo(10)})), "never read but new")
}

func TestACMRSAKeyTooShort(t *testing.T) {
	for alg, want := range map[string]bool{"RSA_1024": true, "RSA_2048": false, "RSA_4096": false, "EC_prime256v1": false, "": false} {
		require.Equal(t, want, awsACMRSAKeyTooShort.Violates(awsAsset("acm_certificate", map[string]string{"key_algorithm": alg})), alg)
	}
}

// A check the scanner cannot read gets no required keys, and Evaluable is then
// always true: a denied read after a finding opened would close it as fixed.
func TestNoCheckHasADynamicPredicate(t *testing.T) {
	require.Empty(t, dynamicPredicateChecks, "write the metadata lookups literally so the scanner derives the keys")
}

func TestAccountAndSSMChecksUnevaluableWhenUnread(t *testing.T) {
	r := Default()
	pp, ok := r.ByID("aws-iam-weak-password-policy")
	require.True(t, ok)
	require.False(t, pp.Evaluable(awsAsset("aws_account_settings", map[string]string{"security_contact": "true"})),
		"an unread password policy is not a strong one")
	ssm, ok := r.ByID("aws-ec2-not-ssm-managed")
	require.True(t, ok)
	require.False(t, ssm.Evaluable(awsAsset("ec2_instance", map[string]string{"state": "running", "package_inventory_gap": "ssm_access_denied"})),
		"a denied SSM listing is not a managed instance")
}

func TestNotSSMManagedOnlyRunning(t *testing.T) {
	require.False(t, awsEC2NotSSMManaged.Violates(awsAsset("ec2_instance", map[string]string{"state": "stopped", "ssm_managed": "false"})))
	require.False(t, awsEC2NotSSMManaged.Violates(awsAsset("ec2_instance", map[string]string{"state": "running", "package_inventory_gap": "ssm_unavailable"})))
}
