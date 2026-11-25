# Azure connector permissions

Every call the Azure collector makes is a read (HTTP GET). Vulngraph never
remediates on its own (ADR 087). The ARM clients for the settings
collectors also turn off the Azure SDK's automatic resource-provider
registration, which is a write. When a permission below is missing, the
setting it backs reads as **unknown**: the check stays silent and does not
close an open finding. It never reads as passing.

## 1. Azure RBAC: `Reader` on each subscription (required)

The built-in `Reader` role (`*/read`) covers every ARM read:

| Area | Operations | Backs |
|---|---|---|
| Inventory | compute, network, storage, web, SQL, `Microsoft.KeyVault/vaults/read` | existing checks, Key Vault 8.3.5–8.3.8 |
| Key Vault metadata | `Microsoft.KeyVault/vaults/keys/read`, `vaults/secrets/read` (ARM returns attributes only, never secret values) | 8.3.1–8.3.4, 8.3.9, 8.3.11 |
| RBAC | `Microsoft.Authorization/roleAssignments/read`, `roleDefinitions/read` | 5.3.3, 5.3.5, 5.4, 5.7, 3.1.1 |
| Defender for Cloud | `Microsoft.Security/pricings/read`, `securityContacts/read`, `settings/read`, `serverVulnerabilityAssessmentsSettings/read`, `iotSecuritySolutions/read` | 8.1.x, 8.2.1 |
| Policy | `Microsoft.Authorization/policyAssignments/read`, `policySetDefinitions/read`, `policyDefinitions/read` | 8.1.10, 8.1.11 |
| Monitor | `Microsoft.Insights/diagnosticSettings/read` (subscription and per resource), `activityLogAlerts/read`, `components/read` | 6.1.1.1–6.1.1.4, 6.1.2.x, 6.1.3.1, 6.1.4 |
| Log destinations | `Microsoft.Storage/storageAccounts/read`, `Microsoft.OperationalInsights/workspaces/tables/read` | 6.1.1.3, activity-log retention |
| Other | `Microsoft.Easm/workspaces/read`, `Microsoft.Devices/IotHubs/read`, `Microsoft.Resources/subscriptions/read` | 8.1.16, 8.2.1, tenant ID |

If the activity log is sent to a storage account or workspace in another
subscription, the connector needs `Reader` there as well. Without it, 6.1.1.3
and retention are unknown.

## 2. Microsoft Graph application permissions (Entra ID checks)

Grant these on the connector's app registration as **application**
permissions, then grant admin consent. All of them are read-only.

| Permission | Graph call | Backs |
|---|---|---|
| `Policy.Read.All` | `policies/identitySecurityDefaultsEnforcementPolicy`, `identity/conditionalAccess/policies`, `policies/authorizationPolicy` | 5.1.1, risk policies, user consent, app registration, guest settings |
| `Policy.Read.DeviceConfiguration` | `policies/deviceRegistrationPolicy` | 5.1.2 |
| `AuditLog.Read.All` | `reports/authenticationMethods/userRegistrationDetails` | 5.1.3, 3.1.1 |
| `User.Read.All` | `users?$filter=accountEnabled eq false` | 5.1.3, 5.3.5, 3.1.1 |
| `RoleManagement.Read.Directory` | `roleManagement/directory/roleAssignments` (Global Administrator) | Global Administrator count |
| `Organization.Read.All` | `subscribedSkus` (P1/P2/Intune licensing, used to stay silent where a feature is not licensed) | 6.1.1.7–6.1.1.9, risk policies |

The authentication-methods registration report requires an Entra ID P1 or P2
licence. On free tenants it returns 403, and 5.1.3 and 3.1.1 stay unknown.

With Workload Identity (no client secret), the managed identity or federated
app gets the same application permissions through
`New-MgServicePrincipalAppRoleAssignment` (managed identities have no
portal consent screen).

The tenant settings asset is keyed by tenant **and** application
(`azure-tenant:<tenant>:<app id>`). Connectors that share one app registration
see the same Graph permissions and share one asset. A connector on a
different app gets its own asset, so a missing consent on one app never blanks
another app's view of the tenant.

## 3. Tenant diagnostic settings: required role unverified

Two tenant-scope ARM reads are not covered by a subscription `Reader`
assignment:

- `GET /providers/microsoft.aadiam/diagnosticSettings` backs 6.1.1.7 and 6.1.1.8.
- `GET /providers/Microsoft.Intune/diagnosticSettings` backs 6.1.1.9.

**Unverified:** we have not confirmed on a live tenant which grant authorizes
these reads. Public sources disagree. Some say an Entra directory role is
enough (`Security Reader` or `Global Reader`; for Intune, `Global Reader` or
`Intune Administrator`). Others, for example Sysdig's Azure troubleshooting
guide, say an Azure RBAC role at the tenant root scope (`/`) is required, which
may be `Contributor` (a write role Vulngraph does not otherwise need). Try
`Global Reader` first. Grant a root-scope Azure role only if your policy
allows it. If neither is granted, these three controls stay unknown; they never
read as passing.

## 4. Key Vault data plane: `Key Vault Reader` (optional)

Two Key Vault checks read the vault's data plane:

- Key rotation (8.3.9) is read from the ARM key's `rotationPolicy`. When ARM
  omits it, the collector reads `GET https://<vault>.vault.azure.net/keys/<name>/rotationpolicy`.
- Certificate validity (8.3.11) is read from `GET https://<vault>.vault.azure.net/certificates`.
  ARM does not document whether its secrets list includes the secrets that
  back certificates, so the collector does not rely on it.

These reads need:

- **RBAC vaults:** `Key Vault Reader` (data action `Microsoft.KeyVault/vaults/*/read`).
- **Access-policy vaults:** an access policy granting the `Get Rotation Policy`
  key permission and the `List` certificate permission.
- Network reach from the worker to the vault.

Vaults that are private, firewalled, or not granted report rotation and
certificate validity as unknown. No secret or key material is ever read.

## 5. Tenant subscription policy (5.6)

`GET /providers/Microsoft.Subscription/policies/default` can be read by any
principal in the tenant. No extra grant is needed.
