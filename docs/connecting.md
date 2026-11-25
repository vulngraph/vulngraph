# Connecting your accounts

One page per provider, from "I have nothing set up" to a synced connector. Every collector is read-only. The
exact grants, call by call, are in the permission references this page links to.

You create connectors under **Settings → Connectors → Add connector**, then press **Test** (where offered) and
**Sync now**. A permission error on the connector names the grant it is missing.

## Choose how Vulngraph authenticates

| Provider | Preferred | Stored credential (fallback) |
|---|---|---|
| AWS | The identity Vulngraph runs as (EKS Pod Identity, IRSA or an instance role) assumes a read-only role in each account | Static access keys on the connector |
| AWS Organization | One StackSet puts a read-only role in every account ([guide](onboarding-aws-org.md)) | Access key for the hub, stored once |
| GCP | Workload Identity: the pod runs as a Google service account | None needed |
| Azure | Azure Workload Identity | Service principal client secret |
| GitHub | A GitHub App (always a stored private key) | |
| Okta | A read-only API token (always stored) | |
| Google Workspace | A service-account key with domain-wide delegation (always stored) | |
| Kubernetes | The in-cluster service account | |

Stored credentials are encrypted at rest under `GRAPH_SECRET_KEY`
([details](../deploy/README.md#connector-credential-encryption)). A stored credential is only as narrow as what
you grant it, so create a dedicated identity for Vulngraph and give it the minimum.

## Give Vulngraph a cloud identity (once)

Skip this when you run the local Compose stack with stored credentials. For Kubernetes and the Helm chart, the
worker and serve pods federate their service account, so no cloud secret is stored. The commands are in
[Cloud auth: OIDC](../deploy/README.md#cloud-auth-oidc):

- **AWS, OIDC web identity:** register the cluster's OIDC issuer as an IAM OIDC provider with audience
  `sts.amazonaws.com`, create a base role that trusts the `graph` service account, then set `aws.enabled` and
  `aws.roleArn` in the chart. On EKS you can annotate the service account for IRSA instead.
- **GCP, Workload Identity:** create a collector service account, grant it `roles/viewer` and
  `roles/iam.securityReviewer`, bind the `graph` Kubernetes service account to it, then set
  `serviceAccount.gcpServiceAccount`.
- **Azure, Workload Identity:** annotate the service account with `azure.workload.identity/client-id` and set
  `serviceAccount.azureWorkloadIdentity: true`.

## AWS, one account

1. **Deploy the read-only role in the account you want to scan.** Use
   [`deploy/aws/graph-readonly-role.yaml`](../deploy/aws/graph-readonly-role.yaml). It grants `SecurityAudit`
   and `ViewOnlyAccess` plus the few reads those policies miss, and nothing that writes. Set `HubRoleArn` to
   the role Vulngraph runs as (the base role above) and `ExternalId` to a random string you keep.
2. **Create the connector.** Provider **aws**, then:

   | Field | Value |
   |---|---|
   | `role_arn` | the `GraphReadOnly` role you just created |
   | `external_id` | the same ExternalId |
   | `region` | the home region to sweep from |

   No role yet, only an existing user? `aws_access_key_id` and `aws_secret_access_key` work in place of
   `role_arn`, as a migration path.
3. **Sync now.** Optional extras: [VM software inventory](iam/vm-software-inventory.md), [VM disk
   scanning](iam/disk-scan-aws.md) (off by default), [bring your own agent](iam/byoa-inventory.md), [ECR image
   scanning](iam/ecr-registry-scanning-permission.md), [Terraform ownership](iam/README.md) (read its warning
   first, state files can hold secrets) and the other [permission references](iam/README.md).

Many accounts? Use [AWS Organization onboarding](onboarding-aws-org.md) instead: one StackSet, no key copied
into any account, new accounts picked up automatically.

## GCP

1. **Grant the collector service account** `roles/viewer` and `roles/iam.securityReviewer` on each target
   project, or once on the folder or organization above them. The full call map, a narrower custom role and the
   optional organization-level role are in [`iam/gcp-cspm-permissions.md`](iam/gcp-cspm-permissions.md).
2. **Bind Workload Identity** as in [Cloud auth: OIDC](../deploy/README.md#cloud-auth-oidc), so the pod runs as
   that service account.
3. **Create the connector.** Provider **gcp**, with `project_id` set to the project to scan. One connector per
   project.

## Azure

1. **Grant `Reader` on each subscription**, plus the read-only Microsoft Graph application permissions for the
   Entra ID checks. [`iam/azure-permissions.md`](iam/azure-permissions.md) lists every call and what is
   unknown without each grant. Do not grant `Contributor` or any write role. Optional, off by default:
   [VM disk scanning](iam/disk-scan-azure.md).
2. **Choose the identity.** Workload Identity needs only `subscription_id`. A service principal also needs
   `tenant_id`, `client_id` and `client_secret`; give the secret an expiry.
3. **Create the connector.** Provider **azure**, with those fields.

## GitHub

Vulngraph reads repositories, workflows, Kubernetes and Terraform files, and code and secret scanning alerts
through a GitHub App you own.

1. **Create the App** under Settings → Developer settings → GitHub Apps → New GitHub App. Give it only the
   read-only repository permissions in [`iam/identity-and-code-connectors.md`](iam/identity-and-code-connectors.md#github-app):
   Metadata, Contents, Administration, Code scanning alerts and Secret scanning alerts. No organization or
   account permissions are needed.
2. **Generate a private key** and download the `.pem` file.
3. **Install the App** only on the repositories you want inventoried. The installation id is the number at the
   end of the installation's URL.
4. **Create the connector.** Provider **github**, with `app_id`, `installation_id` and the contents of the
   `.pem` as `private_key_pem`.
5. **Optional, sync on every change.** Set a `webhook_secret` on the connector and add a GitHub webhook to
   `https://<your-host>/api/webhooks/github/<connector-id>` with the same secret
   ([details](getting-started.md#5-keep-the-data-fresh)).

## Okta

1. Create a dedicated Okta user and give it only the **Read-Only Administrator** role.
2. Sign in as that user and create an API token. A token inherits its creator's role, so never mint one as a
   Super Administrator. Okta revokes a token unused for 30 days, and when its user is deactivated.
3. Create the connector: provider **okta**, `domain` (for example `acme.okta.com`) and `api_token`.

## Google Workspace

1. Create a service account and a key. It needs no Google Cloud IAM roles.
2. In the Admin console, under Security → Access and data control → API controls → Domain-wide delegation,
   authorize the service account's client ID for the single scope
   `https://www.googleapis.com/auth/admin.directory.user.readonly`.
3. Pick an admin whose role grants only reading users, not a Super Admin.
4. Create the connector: provider **google_workspace**, `service_account_json` and `admin_email`.

## Kubernetes

No credentials are stored. The worker reads the cluster it runs in, using its own service account. Apply the
read-only RBAC in [Kubernetes connector RBAC](../deploy/README.md#kubernetes-connector-rbac), then create a
connector with provider **kubernetes** and no fields. Other clusters are scanned by running a Vulngraph worker
in them.

## Check it worked

- The connector shows a recent sync time and no error. Assets appear within a few minutes, and the graph
  follows shortly after.
- A missing permission is reported as **unknown**, never as passing, so a thin result usually means a missing
  grant. Compare the connector's error against the permission reference for that provider.
- To check an account from the command line before you install anything, use [quick scan](quick-scan.md).
