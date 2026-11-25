package checks

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS Azure Foundations v6 RBAC controls (5.3.3, 5.4, 5.7). Each is a fact
// about the whole subscription, so each fires at most once, on the
// azure_subscription asset the identities collector builds from the role
// listings.

// azureRootUserAccessAdmin is CIS 5.3.3. User Access Administrator at "/" is
// Entra "elevated access": it can grant itself any role on every subscription
// and management group in the tenant. Meant to be switched on for minutes.
var azureRootUserAccessAdmin = Check{
	ID:          "azure-root-user-access-admin",
	Title:       "User Access Administrator assigned at the tenant root scope",
	Description: "A principal holds User Access Administrator at the root scope (\"/\"), the standing form of Entra elevated access. It can assign itself Owner on every subscription and management group in the tenant.",
	Remediation: "Remove the assignment (Entra ID → Properties → Access management for Azure resources: No, or `az role assignment delete --role \"User Access Administrator\" --scope \"/\" --assignee ID`) and use elevated access only for the duration of a task.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_subscription",
	Violates:    func(a asset.Asset) bool { return a.Metadata["root_user_access_admins"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"principals": a.Metadata["root_user_access_admins"]}
	},
}

// azureCustomOwnerRole is CIS 5.4. Medium, not High: a role definition grants
// nothing until assigned, but a wildcard custom role is an Owner that escapes
// every review keyed on the built-in Owner role.
var azureCustomOwnerRole = Check{
	ID:          "azure-custom-owner-role",
	Title:       "Custom role grants all actions at subscription scope",
	Description: "A custom role definition allows every action (\"*\") and is assignable at this subscription or above it — an Owner-equivalent role that access reviews looking for the built-in Owner role miss.",
	Remediation: "Delete the custom role or narrow its Actions to what the job needs; use the built-in Owner role where full control is really required.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_subscription",
	Violates:    func(a asset.Asset) bool { return a.Metadata["custom_owner_roles"] != "" },
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"roles": a.Metadata["custom_owner_roles"]}
	},
}

// azureSubscriptionOwnerCount is CIS 5.7: between two and three owners. Too
// many is standing privilege sprawl (Medium); fewer than two is a lockout and
// continuity risk (Low).
var azureSubscriptionOwnerCount = Check{
	ID:          "azure-subscription-owner-count",
	Title:       "Subscription does not have two or three owners",
	Description: "The number of principals holding Owner on the subscription (directly or inherited from a management group or the root) is outside the two-to-three range. More owners widen standing full control; fewer leave the subscription one account away from being unmanageable. A group counts as one principal.",
	Remediation: "Keep two or three Owner assignments on the subscription; grant narrower built-in roles for day-to-day work and use PIM for just-in-time Owner.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAzure,
	AssetType:   "azure_subscription",
	Violates: func(a asset.Asset) bool {
		n, err := strconv.Atoi(a.Metadata["owner_count"])
		return err == nil && (n < 2 || n > 3)
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if n, err := strconv.Atoi(a.Metadata["owner_count"]); err == nil && n < 2 {
			return finding.SeverityLow
		}
		return finding.SeverityMedium
	},
	TitleFor: func(a asset.Asset) string {
		if n, err := strconv.Atoi(a.Metadata["owner_count"]); err == nil && n < 2 {
			return "Subscription has fewer than two owners"
		}
		return "Subscription has more than three owners"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"owner_count": a.Metadata["owner_count"], "owners": a.Metadata["owners"]}
	},
}

// azureFoundationsChecks are the CIS Azure Foundations v6 checks for
// network, storage and RBAC controls.
func azureFoundationsChecks() []Check {
	return []Check{
		azureNSGAllPortsOpenInternet,
		azureNSGUDPOpenInternet,
		azureNSGHTTPOpenInternet,
		azureSubnetNoNSG,
		azureVNetNoDDoSProtection,
		azureAppGatewayNoWAF,
		azureAppGatewayMinTLS,
		azureAppGatewayHTTP2Disabled,
		azureStorageDefaultNetworkAllow,
		azureStoragePublicNetworkAccess,
		azureStorageMinTLS,
		azureStorageSharedKeyAccess,
		azureStorageKeyNotRotated,
		azureStorageNoKeyExpiryPolicy,
		azureStorageCrossTenantReplication,
		azureStorageNoPrivateEndpoint,
		azureStorageTrustedServicesBypassOff,
		azureStoragePortalNotEntraAuth,
		azureRootUserAccessAdmin,
		azureCustomOwnerRole,
		azureSubscriptionOwnerCount,
	}
}
