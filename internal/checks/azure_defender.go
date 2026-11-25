package checks

// azure_defender.go — Microsoft Defender for Cloud subscription settings (CIS
// Azure Foundations 8.1.x, 8.2.1) and the subscription-wide identity joins
// (CIS 3.1.1, 5.3.5). Each is ONE finding on the azure_subscription settings
// asset (internal/collect/azure/defender.go, entra_tenant.go). Turning on a
// Defender plan is "enable service X" hygiene, so the plan and notification
// checks stay Low/Info; the identity joins are privilege findings.

import (
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const subscriptionType = "azure_subscription"

func azureDefenderChecks() []Check {
	return []Check{
		azureDefenderServersComponentsOff,
		azureDefenderNotificationsIncomplete,
		azureMCSBPolicyDisabled,
		azureDefenderEASMOff,
		azureDefenderIoTHubUnprotected,
		azureDisabledUserHasRole,
		azureVMAdminWithoutMFA,
	}
}

// serversComponentGaps lists the Defender for Servers components that are off
// (CIS 8.1.3.2–8.1.3.5). Asked only when the Servers plan is on: with the plan
// off its components cannot be on, and azure-defender-servers-off already says
// so. A component whose read failed is not listed.
func serversComponentGaps(a asset.Asset) []string {
	if a.Metadata["defender_servers_tier"] != "Standard" {
		return nil
	}
	var gaps []string
	if v := a.Metadata["defender_servers_agentless_scanning"]; v == "false" || v == "unavailable" {
		gaps = append(gaps, "agentless scanning for machines")
	}
	if v := a.Metadata["defender_servers_fim"]; v == "false" || v == "unavailable" {
		gaps = append(gaps, "file integrity monitoring")
	}
	if a.Metadata["defender_servers_va_provider"] == "none" {
		gaps = append(gaps, "vulnerability assessment for machines")
	}
	if a.Metadata["defender_wdatp_enabled"] == "false" {
		gaps = append(gaps, "endpoint protection (Defender for Endpoint integration)")
	}
	return gaps
}

var azureDefenderServersComponentsOff = Check{
	ID:          "azure-defender-servers-components-off",
	Title:       "Defender for Servers components are off",
	Description: "Defender for Servers is on, but some of its components are not: agentless scanning, file integrity monitoring, vulnerability assessment for machines, or the Defender for Endpoint integration. Agentless scanning and file integrity monitoring need Plan 2; on Plan 1 they are reported as off.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans → Servers → Settings: turn the listed components On (choose Plan 2 for agentless scanning and file integrity monitoring).",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return len(serversComponentGaps(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{
			"components_off": strings.Join(serversComponentGaps(a), "; "),
			"servers_plan":   a.Metadata["defender_servers_subplan"],
		}
	},
}

// notificationGaps lists CIS 8.1.12–8.1.15 security-contact gaps. Nil when the
// security contacts were not read.
func notificationGaps(a asset.Asset) []string {
	var gaps []string
	if observedNone(a, "security_contact_emails") {
		gaps = append(gaps, "no security contact email")
	}
	if a.Metadata["security_contact_owner_notified"] == "false" {
		gaps = append(gaps, "subscription owners are not notified")
	}
	if observedNone(a, "security_contact_alert_min_severity") {
		gaps = append(gaps, "alert email notifications are off")
	}
	if observedNone(a, "security_contact_attack_path_min_risk") {
		gaps = append(gaps, "attack path email notifications are off")
	}
	return gaps
}

var azureDefenderNotificationsIncomplete = Check{
	ID:          "azure-defender-notifications-incomplete",
	Title:       "Defender for Cloud email notifications are incomplete",
	Description: "The subscription's Defender for Cloud email notifications are missing a security contact address, notification of subscription owners, alert notifications by severity, or attack path notifications — so a high-severity alert can fire with nobody told.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Email notifications: add the security contact address, notify users with the Owner role, and turn on alert (minimum severity High or lower) and attack path notifications. CLI: `az security contact create`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return len(notificationGaps(a)) > 0 },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"gaps": strings.Join(notificationGaps(a), "; "), "emails": a.Metadata["security_contact_emails"]}
	},
}

// azureMCSBPolicyDisabled is CIS 8.1.10 and 8.1.11 — 8.1.10 is the system
// updates policy specifically, one of the benchmark policies an assignment can
// disable.
var azureMCSBPolicyDisabled = Check{
	ID:          "azure-mcsb-policy-disabled",
	Title:       "Microsoft cloud security benchmark policies are disabled",
	Description: "The subscription's Microsoft cloud security benchmark assignment (SecurityCenterBuiltIn) sets non-deprecated policies to Disabled, so Defender for Cloud stops assessing and recommending on them — including, when listed, the check that machines are scanned for missing system updates.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Security policies → Microsoft cloud security benchmark: set the listed policies back to their default effect (Audit/AuditIfNotExists), or exempt specific resources instead of disabling the policy.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["mcsb_disabled_policies"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"disabled_policies": a.Metadata["mcsb_disabled_policies"]}
	},
}

var azureDefenderEASMOff = Check{
	ID:          "azure-defender-easm-off",
	Title:       "Defender External Attack Surface Management is not set up",
	Description: "The subscription holds no Defender EASM workspace (CIS 8.1.16), so internet-facing assets the organisation has lost track of are not discovered. A tenant normally needs one workspace; this is informational on subscriptions that do not host it.",
	Remediation: "Create a Defender EASM workspace (Azure portal → Microsoft Defender EASM → Create) in the subscription that should own external attack surface discovery.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["easm_workspace_count"] == "0" },
}

var azureDefenderIoTHubUnprotected = Check{
	ID:          "azure-defender-iot-hub-unprotected",
	Title:       "IoT hubs are not covered by Defender for IoT",
	Description: "IoT hubs in the subscription have no enabled Defender for IoT security solution, so device and hub threats raise no alerts (CIS 8.2.1).",
	Remediation: "IoT Hub → Defender for Cloud → Enable Microsoft Defender for IoT for each listed hub.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return a.Metadata["iot_hubs_without_defender"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"iot_hubs": a.Metadata["iot_hubs_without_defender"]}
	},
}

// azureDisabledUserHasRole is CIS 5.3.5. A disabled account cannot sign in
// today, but its standing role is restored the moment anyone re-enables it.
var azureDisabledUserHasRole = Check{
	ID:          "azure-disabled-user-has-role",
	Title:       "Disabled users still hold role assignments on the subscription",
	Description: "Entra accounts that are disabled still hold Azure role assignments at, above or below this subscription. Re-enabling such an account (or restoring it from a leaver process) silently restores its access; the assignments also obscure who really has access. Access through a group is not expanded.",
	Remediation: "Remove the listed users' role assignments (Subscription → Access control (IAM) → Role assignments, or `az role assignment delete --assignee <user> --scope <scope>`), and add role removal to the leaver process.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["disabled_users_with_roles_count"])
		return err == nil && n > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"count": a.Metadata["disabled_users_with_roles_count"], "assignments": a.Metadata["disabled_users_with_roles"]}
	},
}

// azureVMAdminWithoutMFA is CIS 3.1.1: a user who can administer a VM (Owner,
// Contributor, Virtual Machine Contributor or Virtual Machine Administrator
// Login on it) with no usable MFA method is one phished password from it.
var azureVMAdminWithoutMFA = Check{
	ID:          "azure-vm-admin-without-mfa",
	Title:       "Users who can administer VMs are not MFA capable",
	Description: "Users holding Owner, Contributor, Virtual Machine Contributor or Virtual Machine Administrator Login over at least one VM in the subscription have not registered a usable multifactor method, so a stolen password gives full control of those machines. Access through a group is not expanded.",
	Remediation: "Have the listed users register MFA and enforce it (security defaults or a Conditional Access policy requiring MFA for Azure management), or remove their VM-administering roles.",
	Type:        "rbac",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["privileged_vm_users_without_mfa_count"])
		return err == nil && n > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"count": a.Metadata["privileged_vm_users_without_mfa_count"], "users": a.Metadata["privileged_vm_users_without_mfa"]}
	},
}
