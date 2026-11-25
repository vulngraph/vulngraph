package checks

// cspm_gcp_iam.go — GCP service-account credential-hygiene checks (CIS GCP
// 1.x), the GCP mirror of cspm_iam.go. All key on gcp_service_account metadata
// the GCP IAM collector emits (internal/collect/gcp/iam.go): key_count,
// key_age_days, key_stale, key_exposed, sa_last_auth_days. Usage-based fields
// (key_stale, sa_last_auth_days) are OMITTED when the Policy Analyzer lookup
// fails, so these checks fail unknown-silent, never false-positive.

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// gcpSAKeyExposed flags a service account with a key Google itself detected as
// exposed (private key found in a public repo) or actively compromised. Google
// auto-disables such keys, but disabling only contains the credential — the
// key must be deleted and everything it touched rotated, and the incident
// investigated. This is confirmed credential leakage, not hygiene.
var gcpSAKeyExposed = Check{
	ID:          "gcp-sa-key-exposed",
	Title:       "Service account key was detected as exposed or compromised",
	Description: "Google flagged one of this service account's user-managed keys as exposed (its private key was found in a public location, typically a GitHub repository) or as compromised and used by an attacker. The key has been auto-disabled, but disabling only stops new authentications: the secret is public, the account's permissions were reachable with it, and re-enabling it is one console click. Treat this as an incident, not a misconfiguration.",
	Remediation: "Delete the flagged key (`gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL`), rotate every credential and secret the service account could reach, audit the account's activity logs for the exposure window, and remove the key from the public location.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_service_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["key_exposed"] == "true"
	},
}

// gcpSAUserManagedKey below is the one check for user-managed key hygiene,
// with no separate unused-key or old-key checks. The three predicates are
// strictly nested — every unused key is an old key is a user-managed key — so
// separate checks would report one old idle key as three findings. It is one
// finding graded by the worst observed state.

// staleKeyRotationDays is the CIS GCP v5.0.0 1.8 rotation threshold.
const staleKeyRotationDays = 90

// gcpSAUserManagedKey flags a service account with an active user-managed key
// and grades it by the worst thing observed about that key: idle (nobody would
// notice the leak) beats merely old (CIS GCP 1.8 rotation) beats simply
// existing (CIS GCP 1.5, keyless auth exists). Google-confirmed exposure keeps its own
// Critical check above — that is an incident, not a grade on this ladder.
var gcpSAUserManagedKey = Check{
	ID:          "gcp-sa-user-managed-key",
	Title:       "Service account has a user-managed key",
	Description: "This service account has at least one active user-managed key — a downloadable, non-expiring credential whose safekeeping is entirely on the holder. Google-managed alternatives (attached service accounts, Workload Identity Federation, impersonation) remove the standing secret altogether. CIS GCP Foundations v5.0.0 1.5 recommends only Google-managed keys. Severity reflects the key's state: High when it has not authenticated in 90+ days or was never used at all (an idle long-lived credential is the one that leaks and is never missed), also High when it is older than a year or older than 90 days on an account holding an admin-equivalent role (Owner, Editor, an IAM-admin role), Medium when it is older than the 90-day rotation threshold (CIS GCP 1.8), Low when it is merely present. The finding evidence carries the key's age and idleness.",
	Remediation: "Identify what uses the key, migrate it to an attached service account (GCE/GKE/Cloud Run) or Workload Identity Federation (external workloads/CI), then delete it: `gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL`. If it is still in use, rotate it now (`keys create` then `keys delete`) and plan the migration. Confirm idleness in Policy Analyzer (service account key last authentication) before deleting.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_service_account",
	Violates: func(a asset.Asset) bool {
		// A dormant admin-equivalent account is reported once, by
		// gcp-sa-admin-dormant, whose remediation deletes its keys too.
		return hasUserManagedKey(a) && !dormantAdminSA(a)
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		// key_stale is OMITTED when the Policy Analyzer lookup fails, so an
		// unknown-idleness key falls through to the age ladder rather than being
		// graded on absent data.
		if a.Metadata["key_stale"] == "true" {
			return finding.SeverityHigh
		}
		// The same age tiers as aws-iam-access-key-old: an admin-equivalent
		// account's key past rotation, or any key a year old, is High.
		if keyOlderThan(a.Metadata["key_age_days"], keyAgeYearDays) ||
			(gcpAdminEquivalent(a.Metadata["roles"]) && keyOlderThan(a.Metadata["key_age_days"], staleKeyRotationDays)) {
			return finding.SeverityHigh
		}
		if keyOlderThan(a.Metadata["key_age_days"], staleKeyRotationDays) {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	// CIS GCP 1.8 (rotate within 90 days) is the pass/fail this finding
	// carries alongside 1.5: the title and key_rotation_overdue say which side
	// of the threshold the oldest active key is on, so one finding per key
	// serves both controls instead of a second finding on the same key.
	TitleFor: func(a asset.Asset) string {
		if keyOlderThan(a.Metadata["key_age_days"], staleKeyRotationDays) {
			return "Service account has a user-managed key older than 90 days"
		}
		return "Service account has a user-managed key"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"key_count": a.Metadata["key_count"]}
		if v := a.Metadata["key_age_days"]; v != "" {
			ev["key_age_days"] = v
			ev["key_rotation_overdue"] = strconv.FormatBool(keyOlderThan(v, staleKeyRotationDays))
		}
		if v, ok := a.Metadata["key_stale"]; ok {
			ev["key_unused_90d"] = v
		}
		return ev
	},
}

// hasUserManagedKey reports whether the service account has at least one active
// user-managed key.
func hasUserManagedKey(a asset.Asset) bool {
	n, err := strconv.Atoi(a.Metadata["key_count"])
	return err == nil && n > 0
}

// gcpSAUnused flags an enabled service account with role bindings that has not
// authenticated by ANY means (key, token, impersonation) in 90+ days per
// Policy Analyzer (observation window up to ~1 year; no record at all means
// dormant for at least that long) — a dormant identity carrying standing
// permissions. Requires bound roles: an unused SA with no grants is
// inert and not worth a finding. Low severity, like aws-iam-user-inactive:
// dormant ≠ compromised, but it widens the attack surface for free.
var gcpSAUnused = Check{
	ID:          "gcp-sa-unused",
	Title:       "Service account with role bindings is dormant (no authentication in 90+ days)",
	Description: "This enabled service account holds IAM role bindings but has not authenticated in at least 90 days (Policy Analyzer reports no activity in its observation window). Dormant identities with standing permissions serve no purpose and only enlarge the attack surface: anyone who compromises or re-activates them inherits the grants, and they clutter access reviews. CIS GCP Foundations recommends removing unused identities and credentials.",
	Remediation: "Confirm the account is unused (Policy Analyzer → service account last authentication), then disable it (`gcloud iam service-accounts disable SA_EMAIL`) and, after a grace period, remove its role bindings and delete it. If it is a break-glass account, document it and add a review reminder.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_service_account",
	Violates: func(a asset.Asset) bool {
		// A dormant admin-equivalent account is gcp-sa-admin-dormant's finding.
		if a.Metadata["disabled"] == "true" || a.Metadata["roles"] == "" || dormantAdminSA(a) {
			return false
		}
		d, ok := a.Metadata["sa_last_auth_days"]
		if !ok {
			return false // Policy Analyzer unavailable — unknown, stay silent
		}
		days, err := strconv.Atoi(d)
		if err != nil {
			return false
		}
		// -1 = no activity in the ~1-year window (dormant for at least that
		// long); >= 90 = observed idle past the CIS threshold.
		return days < 0 || days >= staleKeyRotationDays
	},
}
