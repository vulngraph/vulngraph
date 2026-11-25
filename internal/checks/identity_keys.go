package checks

// identity_keys.go — long-lived key severity by privilege and age, and the
// key-only admin user that aws-iam-user-no-mfa (console users) cannot see.

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const (
	// keyRotationDays is the CIS rotation threshold for access keys.
	keyRotationDays = 90
	// keyAgeYearDays is the age at which any active key is High regardless of
	// who holds it: a year without rotation means nobody is managing it.
	keyAgeYearDays = 365
)

// keyOlderThan reports whether an observed key age (days) exceeds limit.
// Absent or unparseable is false — an unread age never grades a key.
func keyOlderThan(ageDays string, limit int) bool {
	d, err := strconv.Atoi(ageDays)
	return err == nil && d > limit
}

// accessKeyAgeSeverity grades aws-iam-access-key-old: an admin user's key past
// rotation, or any key older than a year, is High; otherwise Medium. Admin is
// an observed effective tier; an identity-policy hint alone cannot prove it.
func accessKeyAgeSeverity(a asset.Asset) finding.Severity {
	if roleAdminReach(a) == reachAdmin || keyOlderThan(a.Metadata["access_key_age_days"], keyAgeYearDays) {
		return finding.SeverityHigh
	}
	return finding.SeverityMedium
}

// accessKeyAgeTitle states the tier the severity was graded on, so the title a
// responder reads matches the grade.
func accessKeyAgeTitle(a asset.Asset) string {
	switch {
	case roleAdminReach(a) == reachAdmin:
		return "Admin IAM user has an access key older than 90 days"
	case keyOlderThan(a.Metadata["access_key_age_days"], keyAgeYearDays):
		return "IAM user has an access key older than a year"
	default:
		return "IAM user has an access key older than 90 days"
	}
}

// awsIAMAdminUserKeyNoMFA covers the admin user aws-iam-user-no-mfa cannot see:
// one with no console password, authenticating only with access keys. MFA does
// not protect access-key calls on its own; the point is that a long-lived admin
// key is the credential, and with no MFA device there is not even the option of
// requiring MFA-backed sessions (aws:MultiFactorAuthPresent) for admin actions.
var awsIAMAdminUserKeyNoMFA = Check{
	ID:          "aws-iam-admin-user-key-no-mfa",
	Title:       "Admin IAM user authenticates with a long-lived access key and has no MFA device",
	Description: "This IAM user holds admin-level access, has no console password, and has at least one active access key — so its admin access rests entirely on a long-lived static secret. An access key is not protected by MFA: anyone holding the key ID and secret (from a laptop, a CI variable, a log line, a public repository) has full account access until the key is deactivated. The user also has no MFA device, so the usual mitigation — a policy requiring aws:MultiFactorAuthPresent for privileged actions, used through MFA-backed session tokens — cannot be in place.",
	Remediation: "Move the workload to an IAM role (instance profile, IRSA, OIDC federation for CI) and delete the key. If a static key is unavoidable, remove the admin grant in favour of a scoped policy, register an MFA device and require aws:MultiFactorAuthPresent for privileged actions, and rotate the key on a schedule.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		if roleAdminReach(a) != reachAdmin || a.Metadata["console_access"] != "false" || a.Metadata["mfa_enabled"] != "false" {
			return false
		}
		n, err := strconv.Atoi(a.Metadata["active_key_count"])
		return err == nil && n > 0 && !dormantAdminUser(a)
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"active_key_count": a.Metadata["active_key_count"]}
		if v := a.Metadata["access_key_age_days"]; v != "" {
			ev["access_key_age_days"] = v
		}
		if v, ok := a.Metadata["access_key_last_used_days"]; ok {
			ev["access_key_last_used_days"] = lastUseEvidence(v)
		}
		return ev
	},
}
