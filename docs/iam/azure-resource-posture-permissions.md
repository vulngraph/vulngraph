# Azure read access for resource-service posture

Vulngraph's Azure collector (`internal/collect/azure`) reads the resource-service
settings behind the CIS Microsoft Azure Foundations controls for storage,
networking and Databricks, and the CIS AKS managed-cluster controls. Every
call is a read. The built-in **Reader** role on the subscription grants all
of them (`*/read`). No data-plane role is needed, and Vulngraph never lists or
reads storage account keys.

> Vulngraph never grants this itself: no code path grants IAM permissions to Vulngraph or
> anyone else. Its only IAM writes are human-approved key actions through the executor
> (disabling or deleting an AWS access key, disabling a GCP service-account key), run
> with the connector's separate execution role.
> Grant Reader through whatever IAM process your organization already uses.

| Call | Permission | Used for |
|---|---|---|
| Blob service properties, per storage account | `Microsoft.Storage/storageAccounts/blobServices/read` | Blob and container soft delete, versioning (CIS 9.2.x) |
| File service properties, per storage account | `Microsoft.Storage/storageAccounts/fileServices/read` | Share soft delete, SMB versions and channel encryption (9.1.x) |
| File share list, per storage account (read until an SMB share is seen) | `Microsoft.Storage/storageAccounts/fileServices/shares/read` | Whether the account holds shares, and SMB ones, which gate the soft-delete and SMB checks |
| Management locks, subscription-wide | `Microsoft.Authorization/locks/read` | Delete locks on storage accounts (9.3.9) |
| Application Gateway WAF policies | `Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read` | WAF state, request-body inspection, bot protection (7.10, 7.14, 7.15) |
| Generic resource list (virtual network gateways), then a GET per gateway | `Microsoft.Resources/subscriptions/resources/read`, `Microsoft.Network/virtualNetworkGateways/read` | Point-to-site authentication types (7.9) |
| Network Watchers and their flow logs | `Microsoft.Network/networkWatchers/read`, `Microsoft.Network/networkWatchers/flowLogs/read` | Watcher region coverage, flow-log retention and traffic analytics (7.5, 7.6, 7.8, 6.1.1.5, 6.1.1.6) |
| Bastion hosts | `Microsoft.Network/bastionHosts/read` | Bastion presence (8.4.1) |
| AKS managed clusters | `Microsoft.ContainerService/managedClusters/read` | CIS AKS section 5 cluster settings. Credentials (`listClusterUserCredential`, `listClusterAdminCredential`) are never called |
| Databricks workspaces | `Microsoft.Databricks/workspaces/read` | CIS 2.1.x workspace networking and encryption |

The storage reads run at most eight accounts at a time.

Every client is built with resource-provider auto-registration disabled. By
default the Azure SDK answers a `MissingSubscriptionRegistration` error by
registering the provider (`POST providers/{namespace}/register`), which is a
write. Vulngraph instead reads that error on a listing's first page as "none of
these exist": a subscription that never registered `Microsoft.ContainerService`
or `Microsoft.Databricks` has no clusters or workspaces.

## What happens when one is missing

The collector never fails silently, and a missing permission never shows up
as a clean result:

- **WAF policies, VPN gateways, AKS clusters, Databricks workspaces.** These
  are resource families of their own. A failed listing logs a warning, marks
  the sweep partial and makes no completeness claim. The affected resources
  are not reported as deleted. If the WAF policy listing fails, any gateway
  whose WAF is an attached policy has an unknown WAF state; it does not read
  as protected.
- **Storage service properties, locks, Network Watcher, Bastion.** These only
  add settings to assets that were already collected. A failed read leaves
  those settings absent, so the checks that need them do not run, and an open
  finding stays open instead of closing as fixed.
