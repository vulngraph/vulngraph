package checks

// gcp_data.go — CIS GCP Foundation data-service and workload controls:
// BigQuery (7.1-7.3), Dataproc (8.1), App Engine HTTPS (4.10), secrets in
// function environments (1.18), pending OS updates (4.12) and Workspace
// 2-Step Verification (1.3).

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var gcpBigQueryDatasetPublic = Check{
	ID:          "gcp-bigquery-dataset-public",
	Title:       "BigQuery dataset is publicly accessible",
	Description: "The dataset's access list grants a role to allUsers or allAuthenticatedUsers, so anyone on the internet — or anyone with any Google account — can read (or with a writer role, change) every table in it.",
	Remediation: "Remove the public entries: `bq show --format=prettyjson PROJECT:DATASET > ds.json`, delete the allUsers / allAuthenticatedUsers entries from access, then `bq update --source ds.json PROJECT:DATASET`.",
	Type:        "exposure",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_bigquery_dataset",
	Violates:    func(a asset.Asset) bool { return a.Metadata["public_access_entries"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"public_access_entries": a.Metadata["public_access_entries"]}
	},
}

var gcpBigQueryDatasetNoCMEK = Check{
	ID:          "gcp-bigquery-dataset-no-cmek",
	Title:       "BigQuery dataset has no default customer-managed key",
	Description: "The dataset sets no default Cloud KMS key, so tables created in it default to Google-managed keys the organisation cannot rotate, audit or revoke unless each sets its own; existing tables on Google-managed keys are reported by gcp-bigquery-table-no-cmek.",
	Remediation: "Set a default key (`bq update --default_kms_key=projects/P/locations/L/keyRings/R/cryptoKeys/K PROJECT:DATASET`) and re-encrypt existing tables (`bq cp -f --destination_kms_key=KEY DATASET.TABLE DATASET.TABLE`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_bigquery_dataset",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "default_cmek") },
}

var gcpBigQueryTableNoCMEK = Check{
	ID:          "gcp-bigquery-table-no-cmek",
	Title:       "BigQuery tables are not encrypted with a customer-managed key",
	Description: "Tables in this dataset are encrypted with Google-managed keys rather than a Cloud KMS key the organisation controls (each table carries its own encryptionConfiguration, whatever the dataset default — tables created before a default was set, or copied in, keep Google-managed keys). The evidence names up to 20 of them.",
	Remediation: "Re-encrypt each listed table with the dataset key: `bq cp -f --destination_kms_key=KEY DATASET.TABLE DATASET.TABLE`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_bigquery_dataset",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["tables_without_cmek_count"])
		return err == nil && n > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"count": a.Metadata["tables_without_cmek_count"], "tables": a.Metadata["tables_without_cmek"]}
	},
}

var gcpDataprocNoCMEK = Check{
	ID:          "gcp-dataproc-no-cmek",
	Title:       "Dataproc cluster disks are not encrypted with a customer-managed key",
	Description: "The cluster's persistent disks use Google-managed encryption (no encryptionConfig.gcePdKmsKeyName), so the data staged on them cannot be revoked or audited through a Cloud KMS key the organisation controls.",
	Remediation: "Recreate the cluster with a key: `gcloud dataproc clusters create CLUSTER --region=REGION --gce-pd-kms-key=projects/P/locations/L/keyRings/R/cryptoKeys/K`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_dataproc_cluster",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "disk_cmek") },
}

var gcpAppEngineHTTPAllowed = Check{
	ID:          "gcp-appengine-http-allowed",
	Title:       "App Engine service serves plain HTTP",
	Description: "A serving version of this App Engine standard service has URL handlers whose securityLevel is not SECURE_ALWAYS, so those URLs answer over unencrypted HTTP instead of redirecting to HTTPS, exposing sessions and data to anyone on the network path.",
	Remediation: "Set `secure: always` on every handler in app.yaml and redeploy (`gcloud app deploy`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_appengine_service",
	Violates:    func(a asset.Asset) bool { return a.Metadata["http_allowed_versions"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"versions": a.Metadata["http_allowed_versions"]}
	},
}

// secretEnvDescription is shared by the function and Cloud Run variants.
const secretEnvDescription = "Environment variables whose names suggest a credential (password, secret, token, API key) hold a literal value instead of a Secret Manager reference. Anyone with the viewer permission on the function or service — and every log or crash report that dumps the environment — sees the secret in plaintext. Only variable names are recorded."

var gcpFunctionEnvPlaintextSecret = Check{
	ID:          "gcp-function-env-plaintext-secret",
	Title:       "Cloud Function stores a secret in plaintext environment variables",
	Description: secretEnvDescription,
	Remediation: "Store the value in Secret Manager and expose it as a secret environment variable or volume: `gcloud functions deploy FN --set-secrets=NAME=SECRET:latest`, then remove the plaintext variable.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_function",
	Violates:    func(a asset.Asset) bool { return a.Metadata["plaintext_secret_env"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"variables": a.Metadata["plaintext_secret_env"]}
	},
}

var gcpCloudRunEnvPlaintextSecret = Check{
	ID:          "gcp-cloudrun-env-plaintext-secret",
	Title:       "Cloud Run service or 2nd-gen function stores a secret in plaintext environment variables",
	Description: secretEnvDescription + " 2nd-gen Cloud Functions run as Cloud Run services and are reported here (cloud_function_gen2).",
	Remediation: "Store the value in Secret Manager and reference it: `gcloud run services update SERVICE --set-secrets=NAME=SECRET:latest` (or `gcloud functions deploy FN --gen2 --set-secrets=...`), then remove the plaintext variable.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloudrun_service",
	Violates:    func(a asset.Asset) bool { return a.Metadata["plaintext_secret_env"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"variables": a.Metadata["plaintext_secret_env"], "cloud_function_gen2": a.Metadata["cloud_function_gen2"]}
	},
}

var gcpGCEOSUpdatesPending = Check{
	ID:          "gcp-gce-os-updates-pending",
	Title:       "VM has pending operating system updates",
	Description: "OS Config reports package updates available but not installed on this instance, on a platform graph cannot match to CVEs (Windows, Container-Optimized OS, or a distribution without an enabled advisory feed). On CVE-matchable Linux VMs the missing patches are reported as vulnerability findings instead, so this check steps aside there.",
	Remediation: "Apply updates through VM Manager patch jobs (`gcloud compute os-config patch-jobs execute --instance-filter-names=INSTANCE`) or a patch deployment schedule.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["os_updates_pending"])
		return err == nil && n > 0 && a.Metadata["package_cve_matchable"] != "true"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"pending_updates": a.Metadata["os_updates_pending"]}
	},
}

var googleUserNo2SV = Check{
	ID:          "google-user-no-2sv",
	Title:       "Google Workspace user is not enrolled in 2-Step Verification",
	Description: "This active Workspace account has no second factor, so a phished or reused password alone signs in — to Gmail, Drive and every Google Cloud project the account can reach. Admins are graded High.",
	Remediation: "Enforce 2-Step Verification for the organisational unit (Admin console > Security > Authentication > 2-step verification) and have the user enrol; prefer security keys for admins.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    "google", // the Workspace collector (internal/collect/google)
	AssetType:   "human_identity",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["two_step_enrolled"] == "false" && a.Metadata["suspended"] == "false"
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["is_admin"] == "true" {
			return finding.SeverityHigh
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"two_step_enforced": a.Metadata["two_step_enforced"], "is_admin": a.Metadata["is_admin"]}
	},
}
