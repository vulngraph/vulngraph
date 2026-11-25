# Granting Vulngraph read access to Terraform state (the tfstate-ownership gate)

> Onboarding a whole AWS Organization? [onboarding-aws-org.md](../onboarding-aws-org.md)
> deploys `GraphReadOnly` without this grant; set `GrantTerraformStateRead=true`
> (`grant_terraform_state_read = true` in the Terraform module) to add it. The
> rest of this page is for a role you provision yourself.

> **Terraform state holds secrets.** State files routinely contain plaintext
> database passwords, private keys and tokens. This grant lets the role
> Vulngraph assumes read the whole state object, not only the parts Vulngraph
> uses. Vulngraph's parser (`internal/collect/iac/tfstate.go`) keeps only each
> resource's address, `arn` and `id` and discards everything else in memory,
> but anyone who holds the hub role or the worker's credentials can read every
> state file the grant covers. Grant it only if you want Terraform ownership,
> and prefer listing your state buckets explicitly over the wildcards below.

Vulngraph's Terraform-ownership feature reads each repo's `.tf` `backend "s3"`
block, resolves the state bucket's owning account automatically, and reads the
state object to map declared resources → their live ARNs → the owning repo.

If the role Vulngraph assumes (`GraphReadOnly`) can list/describe
buckets but has no `s3:GetObject` on the state objects, every state read fails
with `403 AccessDenied`. Vulngraph surfaces each blocked bucket as an
auto-resolving, info-severity `unreadable_tf_state` finding (source
`iac_terraform`) whose description carries the exact grant and says it is
optional. If you do not want Terraform ownership, leave the grant off and
ignore those findings. **This directory is that grant.**
Once applied, ownership edges appear on the next sync and the findings
auto-resolve.

> Vulngraph never grants this itself: no code path grants IAM permissions to Vulngraph or
> anyone else. Its only IAM writes are human-approved key actions through the executor
> (disabling or deleting an AWS access key, disabling a GCP service-account key), run
> with the connector's separate execution role.
> Apply this through whatever IAM process your organization already uses for
> cross-account read roles.

---

## The model: one hub role, cheap cross-account spokes

Vulngraph does **not** need an OIDC provider in every account. Its pods get **one
hub role** in the account graph runs in ([`graph-hub-role.yaml`](../../deploy/aws/graph-hub-role.yaml)),
and that hub does plain `sts:AssumeRole` (with the connector's ExternalId) into a
lightweight **spoke role in each member account**, into the discovery role in the
management account, and, for Approve & run, into the execution role. The spokes
aren't OIDC — they just trust the hub role.

How the pods get the hub is the template's `TrustType`, and each produces a different
STS call on the hub role, which is what to look for in CloudTrail:

| `TrustType` | How graph's pods get the hub | STS call on the hub role |
|---|---|---|
| `eks-pod-identity` (default) | a pod identity association for graph's ServiceAccount; the EKS Pod Identity Agent fetches the credentials (`eks-auth:AssumeRoleForPodIdentity`) | `sts:AssumeRole` with `sts:TagSession`, made by the service principal `pods.eks.amazonaws.com`, carrying the `kubernetes-namespace` and `kubernetes-service-account` session tags the trust checks |
| `irsa` | the ServiceAccount's `eks.amazonaws.com/role-arn` annotation; the AWS SDK exchanges the projected service-account token | `sts:AssumeRoleWithWebIdentity`, federated through the cluster's OIDC provider, for the one `sub` the trust names |
| `principal` | an existing IAM role or user (`TrustedPrincipalArn`): an instance role, or the IAM user whose key the connector stores (`hub_auth=access_key`) | `sts:AssumeRole` by that principal, with session name `graph-hub` and no ExternalId. Vulngraph makes this call itself, from the principal's credentials (the ones the AWS SDK resolves, or the stored key), when the `aws_org` connector's `hub_role_arn` is set to the `HubRoleArn` output; without it every hop into a spoke is refused, since the spokes trust only the hub role. `hub_role_arn` is required with `hub_auth=access_key` |

Cross-account S3 read is only possible via a principal *in* each account (AWS
isolation), so a per-account role is unavoidable; the trick is deploying/maintaining it without touching accounts by hand.

Cross-account S3 read has exactly two grant shapes: an **identity role per account**
(e.g. Vulngraph's `GraphReadOnly`) or a **bucket policy per bucket**.
The role path is strictly less work — bucket policies would be per-bucket-manual,
which is worse. So: add the read to a per-account role, deployed by a repeatable
mechanism.

---

## Grant the read on the role Vulngraph already uses

### Extend `GraphReadOnly` (**zero Vulngraph change**)

Vulngraph already assumes a read-only role in each account (`GraphReadOnly` from the
provided templates, or your own), so `GetObject` "just works" the moment that role
carries the permission — **no code, config, hub, or connector change.** Add the
statement from [`tfstate-read-policy.json`](./tfstate-read-policy.json) to wherever
the read-only role Vulngraph assumes in each account is **provisioned**, and let that
mechanism re-apply it everywhere.

The policy grants only reads: `s3:GetObject` on state objects plus
`s3:ListBucket`/`s3:GetBucketLocation` on the buckets. Reading a state object
reads every secret in it (see the warning above). Its wildcards match every
bucket whose name contains `terraform-state` or `tfstate`, and the
`s3:ResourceAccount` condition holds them to buckets the role's own account owns
(S3 ARNs carry no account id, so without it the wildcards would also match a
central state bucket in another account whose bucket policy admits the role).
Vulngraph reads a state bucket with the role of the account that owns it when
the bucket is in its inventory (an `s3_bucket` asset from a connected AWS
account), so a central state bucket needs the grant on that account's role.
A bucket missing from inventory is read with the GitHub connector's fallback
account (`tfstate_aws_account_id`) instead; if that account does not own the
bucket, the condition denies the read and Vulngraph reports it as an
`unreadable_tf_state` finding rather than as a repo with no state. Connect the
bucket's own account, or set the fallback to it. If your policy standards
forbid mid-ARN wildcards, replace the wildcard entries with your own state buckets
and extend the list as new state buckets appear — object ARNs (`/*`) in
`GraphReadTfStateObjects`, bucket ARNs in `GraphListTfStateBuckets`:

```json
"Resource": [
  "arn:aws:s3:::your-terraform-state-bucket-1/*",
  "arn:aws:s3:::your-terraform-state-bucket-2/*"
]
```

However the read-only role is fanned out to your accounts —
identify that mechanism first, then extend it:

- **A StackSet / Control Tower customization** → add the statement to that template;
  it re-propagates to all accounts (and future ones). ← if you run Control Tower,
  you already have StackSets under the hood.
- **A multi-account Terraform module** (provider-per-account / `for_each` over
  accounts) → add the statement to that module and apply.
- **`OrganizationAccountAccessRole`-based bootstrap** → add it to that bootstrap.
- **Manually / ad-hoc** → add the statement to whatever role the connector uses.

A separate state-reader role does not work: Vulngraph reads Terraform state with the
account connector's own role (`readonly_role_arn` if set, otherwise `role_arn`, or
the connector's static keys), so the permissions must be on that role.

---

## How a StackSet works (the mechanics)

You create **one** stack set in the Org management (or a delegated-admin) account
holding a CloudFormation template (here: the one that provisions `GraphReadOnly`). You tell it
*"deploy to these OU IDs."* CloudFormation assumes into every account in those OUs
via its own execution role and creates/updates the stack there. With
**service-managed permissions + `AutoDeployment: Enabled=true`**, existing *and
future* accounts in the OU are covered, and editing the template updates every
account at once. You never log into individual accounts — which is the whole point.

**Multiple OUs / Organizations:** OUs in one Organization → one StackSet listing
each OU ID. Separate Organizations (separate management/root accounts) → one
StackSet per Org (StackSets can't cross an Org boundary), each targeting its OUs.

**One-time prerequisite** (management/delegated-admin account):
`aws cloudformation activate-organizations-access`.

---

## After applying

1. The next Vulngraph sync (`SYNC_INTERVAL`, configurable) reads the now-readable state.
2. The `ci_access`/`tf_ownership` correlate rules join resources → repos → the
   `iac_terraform` `defined_in` edges appear.
3. The `unreadable_tf_state` findings for the granted buckets stop being re-observed
   and **auto-resolve**. Any bucket still failing keeps its finding — a
   precise, self-updating coverage signal.

Verify: run the **"Terraform-managed resources → owning repo"** preset, or
`MATCH ()-[e:DefinedInAsset|DefinedInIamRole]->(r:Repo) WHERE e.provenance='iac_terraform' RETURN count(*)`.

---

## Other permission pages

- [`disk-scan-aws.md`](disk-scan-aws.md) and [`disk-scan-azure.md`](disk-scan-azure.md): optional, off by default,
  reading VM disks from snapshots (the Azure page also covers creating them).
- [`byoa-inventory.md`](byoa-inventory.md): your own agent submits a VM's package list, so Vulngraph holds no
  snapshot permission.
- [`vm-software-inventory.md`](vm-software-inventory.md): SSM and OS Config inventory.
