package checks

// cspm_iam.go — IAM credential-hygiene checks (CIS AWS Foundations IAM section). All key on
// iam_user metadata the AWS IAM collector already emits
// (internal/collect/aws/iam.go): console_access, active_key_count, inactive,
// password_last_used_days.

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// staleConsoleDays is the CIS-recommended threshold for disabling unused
// console credentials.
const staleConsoleDays = 90

// awsIAMUserInactive flags a user with no console password and no active access
// keys — a dormant identity that only widens the attack surface (CIS: remove
// unused credentials). The collector sets inactive="true" for exactly this.
var awsIAMUserInactive = Check{
	ID:          "aws-iam-user-inactive",
	Title:       "IAM user is inactive (no console password, no active keys)",
	Description: "This IAM user has neither console access nor any active access key. Dormant users serve no purpose and only enlarge the attack surface: they can be re-activated by anyone who compromises the account, and they clutter access reviews. CIS AWS Foundations recommends removing credentials and users that are no longer required.",
	Remediation: "Confirm the user is unused, then delete it: `aws iam delete-user --user-name NAME` (after detaching policies, deleting login profile, and removing access keys). If it is a break-glass account, document it and add a review reminder.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["inactive"] == "true"
	},
}

// awsIAMUserMultipleActiveKeys flags a user with more than one active access
// key. A second key doubles the credential exposure and usually
// means a rotation was left half-finished.
var awsIAMUserMultipleActiveKeys = Check{
	ID:          "aws-iam-user-multiple-active-keys",
	Title:       "IAM user has more than one active access key",
	Description: "This IAM user has two or more active access keys. Each active key is an independent long-lived credential that can be leaked or misused; maintaining more than one doubles the exposure and is almost always the residue of an incomplete rotation. CIS AWS Foundations requires at most one active key per user.",
	Remediation: "Identify the key still in use (`aws iam get-access-key-last-used`), then deactivate and delete the other: `aws iam update-access-key --access-key-id AKIA... --status Inactive` followed by `aws iam delete-access-key`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["active_key_count"])
		return err == nil && n > 1
	},
}

// awsIAMUserUnusedAccessKey flags a user with an active access key that has gone
// unused — idle for staleKeyDays+, or provisioned and never used (the 90-day
// disable-unused-credentials rule; CIS AWS v7.0.0 2.11 sets 45 days). Distinct from aws-iam-access-key-old,
// which keys on age: a key can be young but already abandoned, or old but actively
// used. An idle long-lived key is a standing, unmonitored liability — the first
// thing an attacker reaches for and the last thing anyone notices is gone. High
// severity: these are the credentials that leak and are never caught.
var awsIAMUserUnusedAccessKey = Check{
	ID:          "aws-iam-user-unused-access-key",
	Title:       "IAM user has an unused access key (idle 90+ days or never used)",
	Description: "This IAM user has an active access key that has not signed a request in at least 90 days, or was created and never used at all. Unused long-lived keys are the highest-yield credential target: they carry the user's full permissions, rotate on no one's radar, and their absence is not noticed if they leak. CIS AWS Foundations v7.0.0 2.11 asks for credentials unused for 45 days or more to be disabled; this finding is the 90-day tier.",
	Remediation: "Confirm the key is not needed (`aws iam get-access-key-last-used --access-key-id AKIA...`), then deactivate and delete it: `aws iam update-access-key --access-key-id AKIA... --status Inactive --user-name NAME` followed by `aws iam delete-access-key`. If the workload still needs programmatic access, move it to a role with short-lived credentials.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["active_key_count"])
		// A dormant admin user is reported once, by aws-iam-admin-user-dormant.
		return err == nil && n > 0 && a.Metadata["access_key_stale"] == "true" && !dormantAdminUser(a)
	},
}

// awsIAMUserStaleConsole flags a user with console access whose password has
// not been used in staleConsoleDays (or never) — an unused human login that
// should be disabled (the 90-day tier of CIS AWS v7.0.0 2.11).
var awsIAMUserStaleConsole = Check{
	ID:          "aws-iam-user-stale-console",
	Title:       "IAM user with console access has not logged in for 90+ days",
	Description: "This IAM user can sign in to the AWS console but has not done so in at least 90 days (or has never signed in). An unused console credential is a standing target for credential stuffing and phishing while providing no operational value. CIS AWS Foundations v7.0.0 2.11 asks for credentials unused for 45 days or more to be disabled; this finding is the 90-day tier.",
	Remediation: "If the login is no longer needed, delete the login profile: `aws iam delete-login-profile --user-name NAME`. Otherwise require the user to sign in and enforce MFA.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["console_access"] != "true" || dormantAdminUser(a) {
			return false // a dormant admin user is aws-iam-admin-user-dormant's finding
		}
		d, err := strconv.Atoi(a.Metadata["password_last_used_days"])
		if err != nil {
			return false
		}
		// -1 = never used; anything >= threshold = stale.
		return d < 0 || d >= staleConsoleDays
	},
}
