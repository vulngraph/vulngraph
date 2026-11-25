package checks

// gcp_project_settings.go — CIS GCP Foundation project-wide settings, each
// evaluated on the project's ONE cloud_account asset
// (internal/collect/gcp/logging.go, project_services.go, posture.go): log
// export (2.3, 2.4), change alerting (2.5-2.12), Essential Contacts (1.17),
// Cloud Asset Inventory (2.14), Access Approval (2.16), VPC Service Controls
// (3.8) and customer-supplied disk keys (4.7). Every key is absent when the
// read behind it failed; list keys are present-and-empty when observed clean.
// All are logging or hygiene posture: Low or Info, never the page band.
//
// The organization-inherited three (catch-all sink, Essential Contacts,
// Access Approval) apply to any GCP asset carrying their key: the
// organization's one gcp_organization settings asset when the organization
// is readable, otherwise the project's cloud_account — never both for the
// same gap (the collector decides which).

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// settingEvidence copies one project-settings key into the finding.
func settingEvidence(key, as string) func(asset.Asset) map[string]string {
	return func(a asset.Asset) map[string]string {
		return map[string]string{as: a.Metadata[key]}
	}
}

var gcpLoggingNoCatchAllSink = Check{
	ID:          "gcp-logging-no-catch-all-sink",
	Title:       "Log entries are not all exported through a sink",
	Description: "On the organization: no aggregated (includeChildren) sink with an empty filter and no active exclusion exports every project's log entries. On a project outside any organization: no such sink on the project covers it. Log entries then live only in the project's own _Default bucket for its retention period, where a project owner can delete or shorten them; an export to a separate, locked destination is what survives an incident or an insider.",
	Remediation: "Create a sink with no filter to a central bucket, BigQuery dataset or Pub/Sub topic, ideally once at the organization: `gcloud logging sinks create all-logs storage.googleapis.com/BUCKET --organization=ORG_ID --include-children` (grant the sink's writer identity access to the destination).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "",
	Violates:    func(a asset.Asset) bool { return a.Metadata["log_catch_all_sink"] == "false" },
}

var gcpLoggingSinkBucketNotLocked = Check{
	ID:          "gcp-logging-sink-bucket-not-locked",
	Title:       "Log export bucket has no locked retention policy",
	Description: "A log sink of this project exports to a Cloud Storage bucket without a locked retention policy (Bucket Lock), so anyone with storage admin rights on the bucket can delete the exported logs or shorten their retention — erasing the record an investigation depends on.",
	Remediation: "Set a retention policy on each log bucket and lock it: `gcloud storage buckets update gs://BUCKET --retention-period=365d` then `gcloud storage buckets update gs://BUCKET --lock-retention-period`. Locking is irreversible; size the period first.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["log_sink_buckets_unlocked"] != "" },
	EvidenceFor: settingEvidence("log_sink_buckets_unlocked", "buckets"),
}

var gcpLoggingChangeAlertsMissing = Check{
	ID:          "gcp-logging-change-alerts-missing",
	Title:       "Project does not alert on security-relevant configuration changes",
	Description: "One or more of the CIS change alerts is not in place: project ownership, audit configuration, custom IAM roles, VPC firewall rules, routes, networks, Cloud Storage IAM, and Cloud SQL configuration. An alert is in place when an enabled Cloud Monitoring alert policy fires on a log-based metric, or a log-match condition, whose filter contains every clause of the CIS filter for that change. The missing ones are listed in the evidence.",
	Remediation: "For each missing change, create a log-based metric with the CIS filter (`gcloud logging metrics create NAME --log-filter='FILTER'`) and an enabled alert policy on `logging.googleapis.com/user/NAME` with a notification channel, or one log-match alert policy per filter.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["log_alerts_missing"] != "" },
	EvidenceFor: settingEvidence("log_alerts_missing", "missing_alerts"),
}

var gcpEssentialContactsMissing = Check{
	ID:          "gcp-essential-contacts-missing",
	Title:       "Essential Contacts do not cover every notification category",
	Description: "No valid essential contact (set on the project or inherited from a folder or the organization) subscribes to one or more of the Legal, Security, Suspension, Technical and Technical Incidents categories, so Google's security, abuse and suspension notices go to whoever happens to hold an owner role — or nobody.",
	Remediation: "Add organization-level contacts for the missing categories: `gcloud essential-contacts create --email=security@example.com --notification-categories=SECURITY,TECHNICAL_INCIDENTS --organization=ORG_ID` (or one contact with ALL).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "",
	Violates:    func(a asset.Asset) bool { return a.Metadata["essential_contacts_missing"] != "" },
	EvidenceFor: settingEvidence("essential_contacts_missing", "missing_categories"),
}

var gcpCloudAssetInventoryDisabled = Check{
	ID:          "gcp-cloud-asset-inventory-disabled",
	Title:       "Cloud Asset Inventory API is not enabled",
	Description: "The Cloud Asset API is disabled in the project, so its resource and IAM-policy history — the five-week record of who changed what, used for incident reconstruction — is not available.",
	Remediation: "Enable it: `gcloud services enable cloudasset.googleapis.com --project=PROJECT`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["cloud_asset_api_enabled"] == "false" },
}

var gcpAccessApprovalDisabled = Check{
	ID:          "gcp-access-approval-disabled",
	Title:       "Access Approval is not enrolled",
	Description: "The organization (or, when the organization cannot be read, the project and its ancestors) is not enrolled in Access Approval, so Google support and engineering access to the project's content proceeds without an explicit approval from the organization. Access Approval requires an Assured Workloads or Enhanced/Premium support tier.",
	Remediation: "Enrol where the support tier allows it: `gcloud access-approval settings update --organization=ORG_ID --enrolled_services=all --notification_emails=security@example.com`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "",
	Violates:    func(a asset.Asset) bool { return a.Metadata["access_approval_enrolled"] == "false" },
}

var gcpVPCSCNotInPerimeter = Check{
	ID:          "gcp-vpcsc-project-not-in-perimeter",
	Title:       "Project is not protected by a VPC Service Controls perimeter",
	Description: "The project is in no enforced, regular service perimeter that restricts a service, so a stolen credential can copy its data (Cloud Storage, BigQuery and other supported APIs) to a project the attacker controls; VPC Service Controls is the control that blocks that exfiltration path regardless of IAM.",
	Remediation: "Add the project to a service perimeter restricting the services that hold its data (start in dry-run mode): `gcloud access-context-manager perimeters update PERIMETER --add-resources=projects/PROJECT_NUMBER --policy=POLICY_ID`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return observedNone(a, "vpc_sc_perimeter") },
}

var gcpGCEDisksNoCSEK = Check{
	ID:          "gcp-gce-disks-no-csek",
	Title:       "Project VMs do not encrypt disks with customer-supplied keys",
	Description: "These VM instances have disks encrypted with Google-managed or Cloud KMS keys rather than customer-supplied encryption keys (CSEK). CIS recommends CSEK for critical VMs, so Google cannot decrypt their disks without a key the organisation supplies on every start. Which VMs are critical is the organisation's call: this is one informational finding per project, listing the instances (GKE nodes excluded).",
	Remediation: "For critical workloads, recreate the disks with a customer-supplied key (`gcloud compute disks create DISK --csek-key-file=KEY_FILE`) and keep the key material in your own key store; losing it loses the disk.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["vms_without_csek"] != "" },
	EvidenceFor: settingEvidence("vms_without_csek", "instances"),
}
