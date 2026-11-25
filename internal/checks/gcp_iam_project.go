package checks

// gcp_iam_project.go — CIS GCP Foundation IAM and audit-logging controls.
//
// The project-wide controls (1.2, 1.7, 1.9, 1.12, 2.1) evaluate the project's
// cloud_account anchor, which the IAM collector stamps from the getIamPolicy
// responses it already reads (internal/collect/gcp/iam_project.go): one
// finding per project, the offending principals in the evidence. Every
// member list is present-and-empty when observed clean; negative inherited
// membership evidence and audit_logging_* need complete ancestor reads.

import (
	"maps"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Partial unions retain positive detection candidates. For evaluability, their
// absence claims are unknown: let the normal missing-evidence probes decide
// whether another observed fact (for example recent use) can still prove clean.
func gcpIAMObservedMetadata(a asset.Asset) asset.Asset {
	if a.Provider != asset.ProviderGCP || a.Type != "gcp_service_account" {
		return a
	}
	if a.Metadata["roles_complete"] == "true" && a.Metadata["permissions_complete"] == "true" {
		return a
	}
	a.Metadata = maps.Clone(a.Metadata)
	if a.Metadata["roles_complete"] != "true" {
		delete(a.Metadata, "roles")
		delete(a.Metadata, "inherited_roles")
	}
	if a.Metadata["permissions_complete"] != "true" {
		delete(a.Metadata, "privilege_tier")
		delete(a.Metadata, "privilege_tier_source")
	}
	return a
}

// gcpSAAdminRole reports whether a role list holds Owner, Editor or any admin
// role — CIS GCP 1.6 names "*Admin", "*admin", Owner and Editor, which takes
// in service-scoped admin roles (roles/storage.admin, roles/compute.admin)
// beyond the project-control set gcpAdminEquivalent covers.
func gcpSAAdminRole(roles string) bool {
	for _, r := range strings.Split(roles, ",") {
		r = strings.TrimSpace(r)
		if r == "roles/owner" || r == "roles/editor" || strings.Contains(strings.ToLower(r), "admin") {
			return true
		}
	}
	return false
}

var gcpSAAdminPrivileges = Check{
	ID:          "gcp-sa-admin-privileges",
	Title:       "Service account holds an admin role",
	Description: "This enabled service account holds Owner, Editor or an admin role. Service accounts are non-interactive identities used by code: anyone who can run code as it, impersonate it (iam.serviceAccounts.actAs / getAccessToken) or holds one of its keys inherits that administrative access, with no MFA in the way. CIS GCP Foundations recommends no admin roles on service accounts. Severity is High for Owner and the roles that administer IAM itself (they can grant themselves anything), Medium for Editor and service-scoped admin roles. The default Compute Engine service account holds Editor unless that grant was removed. A dormant admin service account is reported by gcp-sa-admin-dormant instead.",
	Remediation: "Replace the admin role with the narrowest predefined or custom role the workload needs (IAM Recommender shows unused permissions): `gcloud projects remove-iam-policy-binding PROJECT --member=serviceAccount:SA_EMAIL --role=ROLE`. For the default Compute Engine account, remove its Editor grant and attach dedicated service accounts to workloads.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gcp_service_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["disabled"] == "false" && gcpSAAdminRole(a.Metadata["roles"]) && !dormantAdminSA(a)
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		for _, r := range strings.Split(a.Metadata["roles"], ",") {
			switch strings.TrimSpace(r) {
			case "roles/owner", "roles/iam.securityAdmin", "roles/resourcemanager.projectIamAdmin",
				"roles/resourcemanager.folderAdmin", "roles/resourcemanager.organizationAdmin":
				return finding.SeverityHigh
			}
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"roles": a.Metadata["roles"]}
		if v := a.Metadata["inherited_roles"]; v != "" {
			ev["inherited_roles"] = v
		}
		return privilegeEvidence(a, ev)
	},
}

// memberEvidence reports a project-anchor member list.
func memberEvidence(key string) func(asset.Asset) map[string]string {
	return func(a asset.Asset) map[string]string {
		return map[string]string{"members": a.Metadata[key]}
	}
}

var gcpIAMConsumerAccountMember = Check{
	ID:          "gcp-iam-consumer-account-member",
	Title:       "Project grants IAM roles to personal Google accounts",
	Description: "The project's IAM policy (or one it inherits) grants a role to an identity outside the organisation: a consumer Google account (@gmail.com / @googlemail.com), graded Medium, or a user, group or domain on a domain other than the organization's own (and its subdomains), graded Low. Such accounts sit outside the organisation's identity controls: no enforced MFA or session policy, no offboarding when the person leaves, and no audit trail the organisation owns. A secondary domain of the same Workspace account is reported too — CIS compares against the organization domain; allowlist it with the iam.allowedPolicyMemberDomains policy and accept the finding.",
	Remediation: "Replace each outside account with a corporate identity, remove the binding (`gcloud projects remove-iam-policy-binding PROJECT --member=user:EMAIL --role=ROLE`), and enforce the `iam.allowedPolicyMemberDomains` organization policy so it cannot recur.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["consumer_account_members"] != "" || a.Metadata["non_org_domain_members"] != ""
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["consumer_account_members"] != "" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if a.Metadata["consumer_account_members"] != "" {
			return "Project grants IAM roles to personal Google accounts"
		}
		return "Project grants IAM roles to identities outside the organization's domain"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"members":             a.Metadata["consumer_account_members"],
			"non_org_members":     a.Metadata["non_org_domain_members"],
			"organization_domain": a.Metadata["organization_domain"],
		}
	},
}

var gcpIAMSAImpersonationProjectWide = Check{
	ID:          "gcp-iam-sa-impersonation-project-wide",
	Title:       "Users can impersonate every service account in the project",
	Description: "A user, group or domain holds Service Account User or Service Account Token Creator on the project itself. At project scope those roles apply to EVERY service account in the project, including the default Compute Engine account with Editor, so the principal can act as or mint tokens for the most privileged of them. Grant them on individual service accounts instead.",
	Remediation: "Remove the project-level binding (`gcloud projects remove-iam-policy-binding PROJECT --member=MEMBER --role=roles/iam.serviceAccountUser`) and grant the role on the specific service account the principal needs (`gcloud iam service-accounts add-iam-policy-binding SA_EMAIL --member=MEMBER --role=...`).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["sa_impersonation_project_members"] != "" },
	EvidenceFor: memberEvidence("sa_impersonation_project_members"),
}

var gcpIAMSASeparationOfDuties = Check{
	ID:          "gcp-iam-sa-separation-of-duties",
	Title:       "Principal both administers and uses service accounts",
	Description: "A principal holds Service Account Admin and Service Account User together, so it can create a service account, grant it roles through anyone who trusts it, and then act as it — the separation of duties CIS GCP 1.9 requires is absent.",
	Remediation: "Split the roles across different principals: keep Service Account Admin with the team that manages identities and grant Service Account User per service account to those who deploy workloads.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["sa_admin_user_members"] != "" },
	EvidenceFor: memberEvidence("sa_admin_user_members"),
}

var gcpIAMKMSSeparationOfDuties = Check{
	ID:          "gcp-iam-kms-separation-of-duties",
	Title:       "Principal both administers KMS and uses keys",
	Description: "A principal holds Cloud KMS Admin together with a CryptoKey Encrypter/Decrypter role, so the same identity that manages keys and their IAM can also decrypt data with them — the separation of duties CIS GCP 1.12 requires is absent.",
	Remediation: "Keep roles/cloudkms.admin with key custodians and grant the CryptoKey usage roles, per key, to the workloads that encrypt and decrypt.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["kms_admin_crypto_members"] != "" },
	EvidenceFor: memberEvidence("kms_admin_crypto_members"),
}

var gcpAuditLoggingNotConfigured = Check{
	ID:          "gcp-audit-logging-not-configured",
	Title:       "Project does not capture Data Access audit logs for all services",
	Description: "The project's effective audit configuration (its own plus the folders' and organization's) does not enable ADMIN_READ, DATA_READ and DATA_WRITE logs for allServices, or exempts principals from them. Admin Activity logs are always on, but reads and writes of data — who read which object, secret or table — go unrecorded.",
	Remediation: "Add an allServices audit config with ADMIN_READ, DATA_READ and DATA_WRITE and no exempted members, ideally at the organization so every project inherits it (`gcloud organizations get-iam-policy`, edit auditConfigs, `set-iam-policy`). Data Access logs are billable; scope exclusions in the log router rather than with exemptions.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["audit_logging_all_services"] == "false" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"gaps": a.Metadata["audit_logging_gaps"]}
	},
}
