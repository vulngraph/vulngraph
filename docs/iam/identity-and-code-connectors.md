# GitHub, Okta, Google Workspace and Azure connector permissions

These connectors store a credential in Vulngraph (encrypted under
`GRAPH_SECRET_KEY`, [deploy/README.md](../../deploy/README.md#connector-credential-encryption)).
Every call their collectors make is a read, but the stored credential is only as
narrow as what you grant it: a token that can write keeps that power in the
database, whatever Vulngraph does with it. Grant the minimum below.

## GitHub App

The connector authenticates as a GitHub App (`app_id`, `installation_id`,
`private_key_pem`). It asks for an installation token without narrowing it, so
the token carries every permission the App has: the App's permission list is
the ceiling. Create a dedicated App with only these, all **read-only**:

| Permission (repository) | Calls (`internal/collect/github`) | Backs |
|---|---|---|
| Metadata: read (always granted) | `GET /installation/repositories` (`github.go`) | the repository inventory |
| Contents: read | `GET /repos/{repo}/git/trees/{branch}`, `GET /repos/{repo}/contents/{path}` (`iac.go`, `k8s_ingest.go`, `workflow_ingest.go`, `identity_harvest.go`, whose fetched files `image_harvest.go` also scans, `tfstate_ingest.go`); GraphQL `repository { object(expression: "HEAD:<path>") }` (`codeowners.go`); `GET /repos/{owner}/{repo}/dependency-graph/sbom/generate-report` and `fetch-report/{sbom_uuid}` (`sbom_report.go`; temporary downloads omit credentials) | IaC checks, k8s manifest and workflow federation joins, CODEOWNERS ownership, declared identities and images, Terraform backends, SBOM packages |
| Administration: read | GraphQL `repository { defaultBranchRef { branchProtectionRule { id } } }` (`branchprotection.go`) | default-branch protection. Without it every repo reads as unknown, never as unprotected |
| Code scanning alerts: read | `GET /orgs/{org}/code-scanning/alerts`, `GET /repos/{repo}/code-scanning/alerts` (`ghas.go`, `ghas_closed.go`) | code-scanning findings |
| Secret scanning alerts: read | `GET /orgs/{org}/secret-scanning/alerts`, `GET /repos/{repo}/secret-scanning/alerts` (`ghas.go`, `ghas_closed.go`) | leaked-secret findings and GitHub's validity verdict |

No organization or account permissions are needed. `GET /orgs/{org}/installation`
(`resolve.go`) and the token exchange authenticate as the App itself and need
no permission. Install the App only on the repositories you want inventoried.

## Okta

The connector stores an SSWS API token (`api_token`). An Okta API token carries
the admin role of the user who created it, so a token minted by a Super
Administrator can write anything in the org. Create a dedicated Okta user, give
it only the **Read-Only Administrator** role, sign in as that user and create
the token there. The collector (`internal/collect/okta`) only sends GETs:

| Call | Backs |
|---|---|
| `GET /api/v1/users?filter=status eq "ACTIVE"` (`okta.go`) | human identities |
| `GET /api/v1/groups`, `GET /api/v1/groups/{id}/users` (`okta.go`) | group membership |
| `GET /api/v1/users/{id}/factors` (`factors.go`) | MFA enrolment per user |
| `GET /api/v1/policies?type=...`, `GET /api/v1/policies/{id}/rules` (`policies.go`) | MFA enrolment and authentication policy checks |

Okta revokes a token that goes unused for 30 days, and a token stops working
when its creating user is deactivated: offboarding that user breaks the
connector, so keep the user a service account rather than a person.

## Google Workspace

The connector stores a service-account key (`service_account_json`) with
domain-wide delegation and impersonates `admin_email`. The collector
(`internal/collect/google`) requests one scope,
`https://www.googleapis.com/auth/admin.directory.user.readonly`, and calls only
`GET admin.googleapis.com/admin/directory/v1/users`.

- In the Admin console (Security → Access and data control → API controls →
  Domain-wide delegation), authorize the service account's client ID for that
  one scope and nothing else. The delegation list, not Vulngraph, is the
  ceiling: any scope listed there can be requested with the stored key.
- Impersonate a dedicated admin whose role grants only the Users read
  privilege, not a Super Admin.
- The service account needs no Google Cloud IAM roles for this.

## Azure

[azure-permissions.md](azure-permissions.md) lists every call. In short:
`Reader` on each subscription plus the read-only Microsoft Graph application
permissions it names. Do not grant `Contributor` or any write role to the
collection identity; remediation uses a separate `execute_client_id` credential, only
after a person approves it
([security-hardening.md](../security-hardening.md#connectors-and-remediation)).
Prefer workload identity over a stored client secret, and if you use a secret,
give it an expiry.
