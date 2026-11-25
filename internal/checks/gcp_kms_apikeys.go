package checks

// gcp_kms_apikeys.go — CIS GCP Foundation 1.10/1.11 (Cloud KMS keys) and
// 1.13-1.16 (API keys), from internal/collect/gcp/kms.go and apikeys.go.

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var gcpKMSKeyPublic = Check{
	ID:          "gcp-kms-key-public",
	Title:       "Cloud KMS key is accessible to allUsers or allAuthenticatedUsers",
	Description: "The key's IAM policy, or its key ring's (which every key in the ring inherits), grants a role to allUsers or allAuthenticatedUsers. Anyone on the internet — or anyone with any Google account — can then use or inspect the key as that role allows; with an encrypter/decrypter role they can decrypt the data it protects.",
	Remediation: "Remove the public members: `gcloud kms keys remove-iam-policy-binding KEY --keyring=RING --location=LOC --member=allUsers --role=ROLE` (and allAuthenticatedUsers, and the same on the key ring).",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_kms_key",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_grants"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_grants": a.Metadata["public_grants"]}
	},
}

// kmsRotationGraded reports whether a key is one CIS GCP 1.11 grades: a
// symmetric (ENCRYPT_DECRYPT) key that can rotate automatically and still
// has a usable primary version. Asymmetric and import-only keys cannot
// rotate automatically; a key whose primary was destroyed encrypts nothing.
func kmsRotationGraded(a asset.Asset) bool {
	return a.Metadata["purpose"] == "ENCRYPT_DECRYPT" && a.Metadata["import_only"] == "false" &&
		a.Metadata["primary_state"] != "DESTROYED" && a.Metadata["primary_state"] != "DESTROY_SCHEDULED"
}

var gcpKMSKeyRotation = Check{
	ID:          "gcp-kms-key-rotation",
	Title:       "Cloud KMS key does not rotate at least every 90 days",
	Description: "This symmetric key has no automatic rotation, no scheduled next rotation, or a rotation period over 90 days, so one key version keeps encrypting new data indefinitely and a compromised version stays useful for longer.",
	Remediation: "Set automatic rotation: `gcloud kms keys update KEY --keyring=RING --location=LOC --rotation-period=90d --next-rotation-time=TIME`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_kms_key",
	Violates: func(a asset.Asset) bool {
		return kmsRotationGraded(a) &&
			(a.Metadata["rotation_within_90_days"] == "false" || a.Metadata["next_rotation"] == "false")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"rotation_period_days": a.Metadata["rotation_period_days"], "next_rotation_scheduled": a.Metadata["next_rotation"]}
	},
}

// apiKeyRotationDays is CIS GCP 1.16's rotation window.
const apiKeyRotationDays = 90

func apiKeyOld(a asset.Asset) bool {
	n, err := strconv.Atoi(a.Metadata["age_days"])
	return err == nil && n > apiKeyRotationDays
}

var gcpAPIKeyNoAppRestriction = Check{
	ID:          "gcp-apikey-no-app-restriction",
	Title:       "API key is not restricted to specific applications",
	Description: "The key has no application restriction (HTTP referrers, IP addresses, Android or iOS apps), or one that admits everything (a wildcard referrer, 0.0.0.0/0). API keys are bearer credentials embedded in apps and web pages: anyone who copies the key can use it from anywhere, against the project's quota and bill.",
	Remediation: "Restrict the key to the referrers, addresses or apps that use it: `gcloud services api-keys update KEY_ID --allowed-referrers=https://app.example.com/*` (or --allowed-ips / --allowed-application).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_api_key",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "app_restriction") },
}

var gcpAPIKeyNoAPIRestriction = Check{
	ID:          "gcp-apikey-no-api-restriction",
	Title:       "API key is not restricted to specific APIs",
	Description: "The key may call every API enabled in the project (it has no API targets, or targets cloudapis.googleapis.com). A leaked key then reaches every enabled API that accepts API keys, not just the one it was issued for.",
	Remediation: "Restrict the key to the APIs it needs: `gcloud services api-keys update KEY_ID --api-target=service=maps-backend.googleapis.com`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_api_key",
	Violates:    func(a asset.Asset) bool { return a.Metadata["api_restricted"] == "false" },
}

var gcpAPIKeyNotRotated = Check{
	ID:          "gcp-apikey-not-rotated",
	Title:       "API key is older than 90 days",
	Description: "The key was created more than 90 days ago. API keys never expire; a key copied into a repository, a mobile app build or a log stays valid until someone replaces it.",
	Remediation: "Create a replacement key with the same restrictions, move clients to it, then delete the old one: `gcloud services api-keys create ...` and `gcloud services api-keys delete KEY_ID`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_api_key",
	Violates:    apiKeyOld,
	EvidenceFor: func(a asset.Asset) map[string]string { return map[string]string{"age_days": a.Metadata["age_days"]} },
}

var gcpAPIKeyExists = Check{
	ID:          "gcp-apikey-exists",
	Title:       "Project uses an API key",
	Description: "An API key exists in the project. CIS recommends standard authentication (service accounts, OAuth) over API keys, which are unscoped bearer secrets, and deleting keys a service no longer needs. This informational finding steps aside when the key is also unrestricted or overdue for rotation — those findings carry it.",
	Remediation: "Confirm the key is still needed by an active service; delete it if not (`gcloud services api-keys delete KEY_ID`), or move the client to service-account authentication.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_api_key",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["app_restriction"] != "" && a.Metadata["api_restricted"] == "true" && !apiKeyOld(a) &&
			a.Metadata["age_days"] != ""
	},
}
