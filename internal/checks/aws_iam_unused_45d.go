package checks

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// unusedCredentialDays is CIS AWS 2.11's threshold. Vulngraph's own credential
// hygiene checks fire at 90 days (staleConsoleDays, staleKeyDays); this one
// covers the 45-89 day band CIS adds and steps aside once those take over, so
// a credential is reported by exactly one of them.
const unusedCredentialDays = 45

func unusedInCISBand(v string) bool {
	d, err := strconv.Atoi(v)
	return err == nil && d >= unusedCredentialDays && d < staleConsoleDays
}

var awsIAMUserCredentialUnused45d = Check{
	ID:          "aws-iam-user-credential-unused-45d",
	Title:       "IAM user credential unused for 45 days",
	Description: "This user's console password, or one of its active access keys, has not been used for 45 to 89 days. CIS AWS 2.11 asks for credentials idle 45 days or more to be disabled: a credential nobody uses is one nobody would notice being used by someone else. Past 90 days aws-iam-user-stale-console / aws-iam-user-unused-access-key (or, for an admin, aws-iam-admin-user-dormant) report it instead.",
	Remediation: "Confirm the credential is not needed, then deactivate it: `aws iam update-access-key --user-name NAME --access-key-id AKIA... --status Inactive`, or `aws iam delete-login-profile --user-name NAME` for an unused console password.",
	Type:        "hygiene",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "iam_user",
	Violates: func(a asset.Asset) bool {
		console := a.Metadata["console_access"] == "true" && unusedInCISBand(a.Metadata["password_last_used_days"])
		keys, err := strconv.Atoi(a.Metadata["active_key_count"])
		key := err == nil && keys > 0 && unusedInCISBand(a.Metadata["access_key_max_idle_days"])
		return console || key
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"password_last_used_days":  a.Metadata["password_last_used_days"],
			"access_key_max_idle_days": a.Metadata["access_key_max_idle_days"],
		}
	},
}
