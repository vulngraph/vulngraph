# Onboarding an AWS Organization

Vulngraph collects every account in an AWS Organization through one `aws_org`
connector. A CloudFormation StackSet puts a read-only role in every account,
including accounts created later, and graph discovers the accounts itself and
manages one `aws` connector per account. No access key is copied into any
account or any per-account connector. The design is
[ADR 091](adr/091-aws-org-onboarding.md).

```
graph (GraphHub) ──AssumeRole + ExternalId──▶ GraphOrgDiscovery   (management account: list accounts)
                 └─AssumeRole + ExternalId──▶ GraphReadOnly        (every account: SecurityAudit + ViewOnlyAccess + extras)
```

The templates are in [`deploy/aws/`](../deploy/aws/) and can also be downloaded
from graph (Settings → Connectors → Add connector → `aws_org`, or
`GET /api/aws-org/templates/{name}`). Terraform equivalents are in
[`deploy/terraform/aws-org`](../deploy/terraform/aws-org) (management account)
and [`deploy/terraform/aws-org-hub`](../deploy/terraform/aws-org-hub).

## 1. Generate an ExternalId

In graph, open Settings → Connectors → Add connector and choose `aws_org`. The
form generates a random ExternalId (`graph-` + 32 hex characters). Copy it; every
role below requires it. Keep the form open, or note the value.

## 2. Create the hub role (graph's own account)

Deploy `graph-hub-role.yaml` in the account graph runs in, and run graph's pods
as the role:

| `TrustType` | Use when |
|---|---|
| `eks-pod-identity` (default) | graph runs on EKS with Pod Identity — add a pod identity association for graph's service account (`graph` in the release namespace, Helm `serviceAccount.name`). The trust accepts only `PodNamespace`/`PodServiceAccount` (default `graph`/`graph`), plus `EKSClusterArn` when set; never associate the scanner's `graph-scanner`. If you set Helm `serviceAccount.serveName`, set `ExecutorServiceAccount` to the same name, or the trust refuses serve; with Approve & run, see [Credential isolation](security-hardening.md#credential-isolation) |
| `irsa` | graph runs on EKS with IRSA — set `OIDCProviderArn`, `OIDCProviderHost`, `ServiceAccount`, and annotate the service account with the role ARN (Helm: `serviceAccount.annotations: {eks.amazonaws.com/role-arn: <HubRoleArn>}`). The trust accepts that one subject, so leave Helm `serviceAccount.serveName` empty |
| `principal` | an EC2 instance role, or the IAM user whose access key you will store on the connector (`hub_auth=access_key`). Set `TrustedPrincipalArn` to it, and set the connector's `hub_role_arn` to the `HubRoleArn` output (step 4): graph then calls `sts:AssumeRole` on the hub role from that principal's credentials. A principal in another account also needs `sts:AssumeRole` on the hub role in its own policies; in the hub's account the trust naming it is enough |

Pod Identity here is how graph itself gets its role. In the clusters graph
scans, EKS Pod Identity associations are not collected: a workload whose role
comes from one has no `ExecutesAs` edge to it ([Known limitations](known-limitations.md)).

`ManagementRoleArn` is the discovery role from step 3 — its name is fixed by
`DiscoveryRoleName` (default `GraphOrgDiscovery`), so you can fill in
`arn:aws:iam::<management account>:role/GraphOrgDiscovery` before step 3 exists.
Note the `HubRoleArn` output.

## 3. Deploy the StackSet (management account)

StackSets with service-managed permissions run from the management account or a
StackSets delegated administrator.

1. Once: `aws cloudformation activate-organizations-access`.
2. Upload `graph-readonly-role.yaml` to an S3 bucket the management account can
   read.
3. Deploy `graph-org-stackset.yaml`:

```sh
aws cloudformation deploy --stack-name graph-org \
  --template-file graph-org-stackset.yaml --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    HubRoleArn=arn:aws:iam::<graph account>:role/GraphHub \
    ExternalId=<external id> \
    TargetOUIds=r-xxxx \
    MemberTemplateURL=https://<bucket>.s3.amazonaws.com/graph-readonly-role.yaml
```

`TargetOUIds` takes OU ids or the root id. Terraform ownership
([iam/README.md](iam/README.md)) is off by default; add
`GrantTerraformStateRead=true` to let the member roles read Terraform state.
Read the warning under [Permissions](#permissions) first: state files often
hold plaintext secrets, and the grant lets the role read them.

Both modes give every account exactly one `GraphReadOnly`:

| Where the stack runs | `CallAs` | Member role in… |
|---|---|---|
| management account | `SELF` (default) | target OUs via the StackSet; the management account via a nested stack |
| StackSets delegated administrator | `DELEGATED_ADMIN` | target OUs via the StackSet, which includes the delegated admin itself when it is in a target OU. No role is added by the stack. Deploy `graph-readonly-role.yaml` once in the management account as a plain stack (same parameters). |

In delegated-admin mode the discovery role is created in the delegated admin
and can list the organization only if Organizations delegates that to it (an
Organizations resource policy allowing `organizations:ListAccounts`,
`ListRoots`, `ListOrganizationalUnitsForParent` and `ListAccountsForParent`);
otherwise deploy the discovery role in the management account instead.

The stack creates:

- the `graph-readonly` StackSet, auto-deploying `GraphReadOnly` to every account
  in the target OUs, including accounts added later. An account that leaves the
  organization loses the role (`RetainStacksOnAccountRemoval=false`).
- `GraphReadOnly` in the management account itself (`CallAs=SELF` only) —
  StackSets never target the management account.
- `GraphOrgDiscovery`, which only lists accounts, OUs and roots. Its ARN is the
  `ManagementRoleArn` output.

## 4. Create the connector

Back in the form:

| Field | Value |
|---|---|
| `management_role_arn` | the `ManagementRoleArn` output |
| `external_id` | pre-filled; must equal the StackSet parameter |
| `member_role_name` | `GraphReadOnly` unless you changed it |
| `region` | home region for the children (default `us-east-1`) |
| `regions` | optional: limit the regional sweep, comma-separated |
| `include_ous`, `exclude_ous`, `include_accounts`, `exclude_accounts` | optional scope filters (comma-separated ids). Excludes win; with any include set, an account must match one. OU filters match nested OUs. |
| `hub_auth` | leave empty for graph's own identity. `access_key` plus `aws_access_key_id` / `aws_secret_access_key` stores a key once, on this connector only. |
| `hub_role_arn` | only with `TrustType=principal`: the `HubRoleArn` output. Graph assumes it first, from its own identity or the stored key. Required with `hub_auth=access_key`; leave empty for `eks-pod-identity` and `irsa`, where graph already runs as the hub. |
| `execute_role_name` | optional, see [Approve & run](#approve--run-optional) |

Then click **Test connection** on the new connector. It checks, in order:

1. **Hub identity** — graph has a working AWS identity (`sts:GetCallerIdentity`).
2. **List accounts** — the hub can assume the discovery role and list the organization.
3. **Member roles** — `sts:AssumeRole` plus one read in up to 10 active accounts.

| Cause | Meaning |
|---|---|
| `role_missing_or_untrusted` | the role is not deployed in that account, its trust policy does not name the hub role, or the ExternalId differs. STS reports all three the same way. Check the StackSet instance for the account first. |
| `hub_not_permitted` | the hub role's own policy does not allow assuming that role name (check `MemberRoleName` on the hub stack) |
| `scp_deny` | a service control policy denies the assume or the reads |
| `reads_denied` | assumed, but the role has no read permissions |
| `hub_credentials_invalid` | AWS rejected the hub credential |
| `throttled` | STS throttled the test; run it again |

Discovery runs hourly, or immediately with **Sync now** on the org connector. **Accounts** lists every discovered account:

| Status | Child connector |
|---|---|
| `active` | enabled; first sync is enqueued when created |
| `pending` | none until the account finishes activating |
| `suspended`, `closed` | disabled, data kept |
| `removed` | the account left the organization: disabled, data kept |
| `excluded` | out of the filters: disabled, data kept |
| `conflict` | another `aws` connector already collects the account — delete it to let the org connector take over |
| `unknown` | AWS reported a state graph does not know, or an OU filter could not place the account: left as it was |
| `error` | graph could not create or update the child (detail says why) |

If discovery itself fails (the listing errors, or returns no accounts), **no
child is disabled**: the error shows on the org connector and the next run
retries.

## Permissions

`GraphReadOnly` = `SecurityAudit` + `ViewOnlyAccess` + these reads, which
graph's collectors make and neither managed policy grants (checked against the
policies' versions current on 2026-10-09):

| Action | Used by |
|---|---|
| `ce:GetCostAndUsage` | Cost surface ([cost-explorer-permission.md](iam/cost-explorer-permission.md)) |
| `ecr:GetAuthorizationToken`, `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer` | image CVE sweep of private ECR images ([ecr-image-pull-permission.md](iam/ecr-image-pull-permission.md)). The sweep reads the OS/package manifests inside each layer, but the grant lets the role download full layer content |
| `identitystore:DescribeUser`, `identitystore:DescribeGroup` | Identity Center principals |
| `codebuild:ListReportGroups`, `codebuild:BatchGetReportGroups` | CodeBuild report-export encryption ([aws-app-identity-services-permissions.md](iam/aws-app-identity-services-permissions.md)) |
| `glue:GetMLTransforms`, `s3express:GetLifecycleConfiguration` | Glue ML transform encryption and S3 directory bucket lifecycle posture ([aws-data-store-permissions.md](iam/aws-data-store-permissions.md)) |
| `waf:GetRule`, `waf-regional:GetRule`, `wafv2:GetRuleGroup` | WAF rule contents for the WAF Classic empty-rule and v2 rule-metric checks ([aws-cloudfront-waf-permissions.md](iam/aws-cloudfront-waf-permissions.md)) |
| `macie2:GetMacieSession`, `macie2:GetAutomatedDiscoveryConfiguration` | Macie status per region ([aws-logging-detection-permissions.md](iam/aws-logging-detection-permissions.md)) |
| `s3:GetObject` on `*tfstate*` / `*terraform-state*` buckets the account owns (`s3:ResourceAccount`) | Terraform ownership ([iam/README.md](iam/README.md)). Only with `GrantTerraformStateRead=true`; off by default |

Two of these extras can expose secrets to the role Vulngraph assumes (the
AWS managed policies can too; see the last item):

- **Terraform state** routinely holds plaintext secrets (database passwords,
  private keys, tokens). With `GrantTerraformStateRead=true` the member role can
  read every object in every `*tfstate*` / `*terraform-state*` bucket the
  account owns (an `s3:ResourceAccount` condition keeps buckets in other
  accounts out, even when their bucket policy admits the role). Vulngraph's parser keeps only each resource's address, `arn` and
  `id` and discards the rest in memory, but anyone holding the hub role or the
  worker's credentials can read the full state. Leave it off unless you need
  Terraform ownership, and narrow the bucket list if you turn it on.
- **ECR layers.** `ecr:GetDownloadUrlForLayer` lets the role download every
  layer of every image in the account's repositories, so a secret baked into an
  image is readable by it.
- **The managed policies themselves.** `SecurityAudit` and `ViewOnlyAccess`
  are read-only, but some of their Describe/List/Get calls return configuration
  that commonly holds secrets in plaintext. Responses Vulngraph's collectors
  receive (files in `internal/collect/aws`), and what they keep:

  | Call | Secret-bearing content | Kept |
  |---|---|---|
  | `ecs:DescribeTaskDefinition` (`ecs.go`, `ecs_taskdef.go`) | Container environment variables | Names of secret-looking plaintext variables, to flag them |
  | `codebuild:BatchGetProjects` (`codebuild.go`) | Project environment variables | Names of plaintext AWS-credential variables, to flag them |
  | `elasticbeanstalk:DescribeConfigurationSettings` (`elasticbeanstalk.go`) | Every option setting, including environment properties, read into memory | Three platform options (health reporting, managed actions, log streaming) |
  | `lambda:ListFunctions` (`lambda.go`) | Function environment variables | None |
  | `cloudformation:DescribeStacks` (`cloudformation.go`) | Stack parameters other than `NoEcho` ones | None |
  | `sagemaker:DescribeModel` (`sagemaker.go`) | Container environment variables | None |
  | `apigateway:GET` on stages (`apigateway_stages.go`) | Stage variables | None |
  | `glue:GetJobs` (`glue.go`) | Job default arguments | None |
  | `ec2:DescribeLaunchTemplateVersions` (`launch_templates.go`) | User data of each template's default version | None |
  | `ec2:DescribeSpotFleetRequests` (`launch_templates.go`) | User data of each fleet's launch specifications | None |
  | `bedrock-agentcore:GetAgentRuntime` (`agentcore.go`) | Runtime environment variables | None |
  | `autoscaling:DescribeLaunchConfigurations` (`autoscaling.go`) | Launch configuration user data | None |
  | `elasticmapreduce:DescribeCluster` (`emr.go`) | Cluster configurations | None |

  The role also allows `states:DescribeStateMachine` to return state machine
  definitions, but `stepfunctions.go` requests metadata only, so the
  collectors never receive them. Calls no collector makes but the role is
  allowed include EC2 instance user data (`ec2:DescribeInstanceAttribute`) and
  CloudFormation templates (`cloudformation:GetTemplate`). Vulngraph stores
  none of these values, but anyone holding the hub role or the worker's
  credentials can read them across every member account. Check the current
  policy versions in IAM for the exact action list.

Route tables and SSM inventory (`ec2:DescribeRouteTables`,
`ssm:DescribeInstanceInformation`, `ssm:ListInventoryEntries`) are already in
the managed policies. The template has no write permission, and
`deploy/aws/templates_test.go` fails if one is added.

## Approve & run (optional)

Vulngraph never changes your accounts on its own ([ADR 087](adr/087-no-autonomous-remediation.md)).
To let it carry out remediations a person approves, deploy
`graph-execution-role.yaml` (as a second StackSet, or per account). It grants
only the executor's actions: revoke a security-group ingress rule, stop/start
an instance, deactivate/delete an access key, block public access on a bucket.
Each grant is held to the role's own account. Tag a security group, instance
or IAM user `vulngraph-protected` (any value), for example a break-glass user,
and the role cannot act on it. Some grants are wider than the executor's own
calls, because IAM has no condition key for the request fields involved:
`iam:UpdateAccessKey` can also set a key back to Active (the executor only
deactivates), and `s3:PutBucketPublicAccessBlock` can also turn Block Public
Access off (the executor only turns all four settings on). This role does not
exclude buckets by tag (S3 evaluates resource tags only on buckets with
attribute-based access control turned on), and untagged instances and security
groups are all in scope.
Starting an instance whose EBS volumes use a customer managed KMS key also needs
`kms:CreateGrant`, so the role has it, limited to grants EC2 creates for AWS
resources (`kms:GrantIsForAWSResource`, `kms:ViaService` = EC2) on keys in the
same account. The key's policy must delegate to IAM (the default key policy
does); otherwise add the role to the key policy. There is no Terraform module for
this role; deploy the template.

| `graph-execution-role.yaml` parameter | Value |
|---|---|
| `HubRoleArn` | the hub stack's `HubRoleArn` output; only it may assume the role |
| `ExternalId` | the org connector's ExternalId |
| `RoleName` | default `GraphExecute`; must match the connector's `execute_role_name` and differ from the read-only role |
| `ExecutorServiceAccount` | EKS Pod Identity only, optional: serve's own ServiceAccount (Helm `serviceAccount.serveName`, e.g. `graph-serve`). When set, the role's trust also requires the `kubernetes-service-account` session tag to equal it, so only serve can assume the role. Leave empty when serve shares `PodServiceAccount`, and for IRSA or `principal` |

Then:

1. Set `execute_role_name` on the org connector.
2. Update the hub stack (`graph-hub-role.yaml`) with `ExecutionRoleName` set to
   the same name; without it the hub has no permission to assume the role. If
   you set `ExecutorServiceAccount` on the execution roles, set the same value
   for `ExecutorServiceAccount` on the hub stack: the hub then trusts serve's
   ServiceAccount too and lets only its sessions assume the execution role, and
   serve needs its own pod identity association to the hub role. Use the same
   value on the hub stack and on every execution role: an execution role pinned
   to a ServiceAccount the hub does not trust refuses serve. With the
   [`aws-org-hub`](../deploy/terraform/aws-org-hub) module the same two settings
   are `execution_role_name` and `executor_service_account`.
3. Run graph with `hub_auth` ambient (the executor never uses a stored key; with
   `TrustType=principal` it assumes `hub_role_arn` from graph's own identity),
   and switch the child connectors you want to `read_write`.

See [Credential isolation](security-hardening.md#credential-isolation) for what
`ExecutorServiceAccount` does and does not protect against.

## Security notes

- **No copied keys.** A child connector stores `org_connector_id`, `role_arn`,
  `region` and `aws_account_id` only. The hub credential (if any), `hub_role_arn`
  and the ExternalId are read from the org connector when the child is used, in memory.
  Vulngraph refuses to write a child config that contains a key or an ExternalId.
- **Prefer the ambient hub.** With `hub_auth` ambient there is no long-lived
  AWS secret in graph at all.
- **ExternalId** on every trust policy stops another tenant of the same hub
  principal from steering graph into your roles (the confused-deputy problem).
  It is random per connector and is never returned by the API.
- **Scoped roles, read-only members.** The hub can only assume graph's roles;
  the discovery role can only list the organization. The member role is
  read-only, with no write permission of any kind, but it is not least
  privilege: `SecurityAudit` and `ViewOnlyAccess` allow reads no collector
  makes, some of which return secrets (see [Permissions](#permissions) for
  those, for Terraform state and ECR layers, and for the list of extra reads
  derived from the collectors' AWS API calls). Set `OrgId` on the templates to
  confine the trust and the hub's assumes to your organization.
- **STS limits.** Each child assumes its role once per sweep; concurrency is
  bounded by the sync queue's workers. The connection test samples at most 10
  accounts.
- **Deleting the org connector** disables its children (data kept); it does not
  touch AWS. If you later create a new org connector for the same organization,
  its discovery **adopts** those orphaned children: the same connector (name,
  history, data) is pointed at the new org and re-enabled for each active,
  in-scope account. A child of an org connector that still exists is never
  adopted; it shows as `conflict`.

## Migrating from `graph bootstrap`'s per-account connectors

Older `graph bootstrap` runs created `aws-<account id>` connectors with the hub
key copied into each. The org connector reports those accounts as `conflict`.
Delete the old connectors (Delete, not Purge — Purge removes the account's data)
and run **Sync now** on the org connector. `graph bootstrap` itself now creates
an `aws_org` connector instead (`AWS_ORG_MANAGEMENT_ROLE_ARN`,
`AWS_ORG_EXTERNAL_ID`; see [configuration.md](configuration.md#bootstrap-command)).
