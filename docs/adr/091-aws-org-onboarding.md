# ADR 091 — AWS Organization onboarding: one StackSet, one org connector, no copied keys

**Status:** accepted (2026-10-09)

## Context

Vulngraph collected AWS one account per `aws` connector. For an organization the only
helper was `graph bootstrap`: it read a hub IAM user's static keys from a
Kubernetes Secret, listed the organization once, and created a connector per
account with **the hub keys copied into every connector's config**. That had
four problems:

- The hub secret existed N+1 times. Rotating it meant re-running bootstrap; a
  leaked connector row leaked the hub.
- Discovery ran once. An account created afterwards was never collected; a
  suspended or closed one kept syncing and failing.
- The member role (`GraphReadOnly`) was provisioned however the operator
  managed it, with no template stating what graph needs.
- `DiscoverAccounts` filtered on the Organizations `Status` field, which AWS
  retired in September 2026 — against a current endpoint it can skip every
  account.

## Decision

### 1. Deployment: one StackSet, three roles

`deploy/aws/` holds the CloudFormation templates, also served by the binary at
`GET /api/aws-org/templates/{name}` (embedded, so air-gapped installs need no
checkout), with Terraform equivalents in `deploy/terraform/aws-org{,-hub}`:

| Role | Where | Can do |
|---|---|---|
| `GraphHub` (`graph-hub-role.yaml`) | graph's own account | only `sts:AssumeRole` on the discovery role and on `arn:*:iam::*:role/GraphReadOnly` (optionally scoped by `aws:ResourceOrgID`) |
| `GraphOrgDiscovery` | management or delegated-admin account | `organizations:List*`/`Describe*` for accounts, OUs and roots |
| `GraphReadOnly` (`graph-readonly-role.yaml`) | every account | `SecurityAudit` + `ViewOnlyAccess` + an inline policy of exactly the reads neither covers |

`graph-org-stackset.yaml` is a SERVICE_MANAGED StackSet with auto-deployment
(new accounts in the target OUs get the role; removed ones lose it), plus a
nested stack for the management account, which StackSets never target, plus the
discovery role. Every trust policy requires the connector's `sts:ExternalId`.

Every one of those trust policies names only the hub role, so whatever graph
starts from must become a hub session before the first hop. `TrustType`
`eks-pod-identity` and `irsa` hand the pods a hub session directly (the SDK
chain resolves it). `TrustType=principal` trusts an existing principal (an
instance role, or the IAM user whose key `hub_auth=access_key` stores), so the
connector names the hub role in `hub_role_arn` and Vulngraph calls
`sts:AssumeRole` on it from that principal's credentials, cached and refreshed,
before any other hop. The principal trust carries no ExternalId: the hub role
and the principal are both the operator's own, the trust names that one
principal ARN, and the confused deputy the ExternalId guards against sits on
the cross-account hops, which keep it.

The inline extras were derived by listing every AWS API call in the collectors,
`cmd/graph` and the live MCP path and checking each against the current
SecurityAudit and ViewOnlyAccess versions: `ce:GetCostAndUsage`,
`ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`,
`identitystore:DescribeUser`, `identitystore:DescribeGroup`, and (opt-in,
`GrantTerraformStateRead`, off by default because state files hold secrets)
`s3:GetObject` on `*tfstate*`/`*terraform-state*` buckets. `TestReadOnlyRoleGrantsOnlyReads`
pins that set and that every action is a read.

The Approve & run execution role (`graph-execution-role.yaml`) is a separate,
optional template, granting exactly the executor's action list
(`TestExecutionRoleIsTheExecutorActionList`). It is not part of the StackSet by
default. ADR 087 is unchanged: execution still needs a human approval and a
`read_write` connector.

### 2. The `aws_org` connector type

An `aws_org` connector holds the hub choice and the ExternalId:
`hub_auth` (`ambient`, the default, meaning graph's IRSA / Pod Identity /
instance role; or `access_key`, the fallback, with the key stored once on this
connector), `hub_role_arn` (the hub role to assume first, for a principal-trust
hub; required with `access_key`, since an IAM user key is never itself a hub
session), `management_role_arn`, `external_id`, `member_role_name`, `region`,
optional `regions`, account/OU include and exclude filters, and an optional
`execute_role_name`. Values are validated at create (ARN shape, ExternalId
charset and length, role names, account/OU ids).

### 3. Children reference the org; credentials resolve on read

Discovery creates one ordinary `aws` connector per in-scope ACTIVE account. Its
stored config is references only: `org_connector_id`, `role_arn`, `region`,
`aws_account_id`, and optionally `regions` and `execute_role_arn`.
`connector.Service.Get` — the chokepoint every consumer (sync, live MCP reads,
ECR auth, executor, cost) already goes through — merges the org's hub key (if
any), `hub_role_arn` (if any) and ExternalId into the returned config **in
memory**. The collector's chain (`baseConfig`: base identity → assume
`hub_role_arn` when set → assume `role_arn` with `external_id`) then does hub →
member; the live MCP path does the same, and the executor starts from the
ambient identity, assumes `hub_role_arn` when set, then `execute_role_arn`.

Guards: `checkChildConfig` refuses to write a child config carrying a key, a
session token or an ExternalId; `Create` refuses `org_connector_id` from the API
(children are discovery's); a child whose org is gone or is not an `aws_org`
fails with `ErrOrgParentMissing` rather than falling back to the pod's ambient
identity.

### 4. Reconciliation, and what a failed listing means

`DiscoverAWSOrgsArgs` is an hourly singleton (`periodicSingletonOpts`, sync
queue, 10-minute timeout, RunOnStart) that reconciles every enabled org, then
enqueues a first sync for each child it created. "Sync now" on an org connector
enqueues the same job. The org connector's own `sync_status` records the
discovery outcome; `EnqueueSyncs` skips `aws_org` and the sync worker cancels
one rather than overwrite that status with "no collector".

Per account (`planAccount`): ACTIVE and in scope → child exists and enabled
(created, re-enabled, or config refreshed); SUSPENDED / PENDING_CLOSURE /
CLOSED / filtered out / absent from a complete listing → child **disabled, never
deleted**, data kept; PENDING_ACTIVATION → no child yet; an unknown state, or an
OU filter that cannot place the account → nothing changes. An account another
`aws` connector already collects is a `conflict`, not a second child. Every
account's outcome is a row in `aws_org_accounts` (Postgres), shown in the UI
with the child's health.

**A failed or empty listing changes no child.** `ListAccounts` fails as a whole
if any page fails, and zero accounts is `ErrEmptyDiscovery` (every organization
lists at least its management account): "could not list" must never read as
"every account left". The failure is recorded on the org connector.

Deleting an org connector disables its children in the same transaction.

### 5. Connection test

`POST /api/connectors/{id}/test` (admin; it makes live calls with the org's
credential, through the same hub config discovery uses, `hub_role_arn` hop
included) reports the hub identity, the management-role listing, and an
explicit `sts:AssumeRole` plus one read (`iam:GetAccountSummary`) in up to 10
active accounts, each failure classified: `role_missing_or_untrusted` (STS
reports a missing role, a trust policy that does not name the hub and a wrong
ExternalId identically, and the detail says so), `hub_not_permitted`,
`scp_deny`, `reads_denied`, `hub_credentials_invalid`, `throttled`.

### 6. Bootstrap

`graph bootstrap`'s key-copying path (`DiscoverAccounts`, `Reachable`,
`pickHub`, `AWS_ORG_ACCOUNT_IDS`, `AWS_HUB_SECRET_KEYS`) is removed. Bootstrap
still registers standalone static-key profiles, and with
`AWS_ORG_MANAGEMENT_ROLE_ARN` + `AWS_ORG_EXTERNAL_ID` registers one `aws_org`
connector (ambient hub, or `AWS_ORG_HUB_PROFILE`'s key stored once on it, which
requires `AWS_ORG_HUB_ROLE_ARN`; that variable sets `hub_role_arn`).

## Consequences

- One credential to rotate (or none, with an ambient hub). Children never hold
  one; `TestReconcileOrg_ChildrenNeverStoreCopiedKeys` and a guardmutation row pin it.
- New accounts are collected within about an hour of the StackSet reaching them;
  suspended and closed accounts stop syncing without losing history.
- STS load is unchanged per sweep: each child assumes its role once per sweep
  (the existing config cache), bounded by the sync queue's worker count; the
  test samples at most 10 accounts.
- A standalone `aws` connector for an account the org also covers surfaces as
  `conflict`; deleting it hands the account to the org connector. Asset IDs
  are the same, so assets and findings carry over; the child's first sync has
  no stored hashes and treats every asset as changed.
- A child deleted by hand is recreated on the next discovery; excluding the
  account by filter is how to stop collecting it.
- Re-creating an org connector adopts the old one's orphaned children (their
  `org_connector_id` names a connector that no longer exists) instead of
  reporting every account as `conflict`.

## Rejected

- **Copy the hub key into each child, encrypted.** The status quo; N copies of
  one secret and no rotation story.
- **A `parent_connector_id` column on `connectors`.** The child already carries
  the reference in its config, and `aws_org_accounts` gives the org → child
  direction with the per-account status the UI needs.
- **Deleting children of removed accounts.** Deletion of collected data is
  ADR 081's job with its own evidence rules; an account leaving the organization
  is not proof its resources are gone.
