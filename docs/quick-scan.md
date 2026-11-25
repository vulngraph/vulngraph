# Quick scan: check one account without the stack

`graph scan <provider>` runs one read-only sweep of an account and prints the
findings. It needs no Postgres, no ClickHouse and no LLM key, and it stores
nothing: credentials are read from the environment and the results exist only
in the process. Progress goes to stderr, so stdout stays machine-readable.

```sh
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… AWS_SESSION_TOKEN=…   # temporary STS credentials work
graph scan aws --region eu-west-1
```

`graph scan <provider> -h` lists the flags and the credentials the provider needs.

To see what the output looks like first, `graph scan demo` scans Acme, a fictional AWS account
bundled with the binary (no credentials, no network). Its findings, and the attack path they
sit on, are described in [`docs/demo.md`](demo.md).

## Providers

| Provider | Credentials | Flags |
|---|---|---|
| `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` (optional), or `--role-arn`. SSO or profile users: `eval $(aws configure export-credentials --format env)` | `--region`, `--regions r1,r2` (default: every enabled region) |
| `gcp` | Application Default Credentials (`gcloud auth application-default login`) | `--project` or `GOOGLE_CLOUD_PROJECT` |
| `azure` | `AZURE_SUBSCRIPTION_ID`, plus either all three of `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, or none of them to use an ambient login such as `az login` (a partial set is refused) | |
| `okta` | `OKTA_DOMAIN`, `OKTA_API_TOKEN` | |
| `googleworkspace` | `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-account **key file** with domain-wide delegation (not an ADC login: the same variable means something different for `gcp`) | `--admin-email` or `GOOGLE_WORKSPACE_ADMIN_EMAIL` |

Kubernetes and GitHub need a running stack for now: the Kubernetes collector
reads in-cluster credentials and the GitHub collector needs a GitHub App.

## Output and filters

| Flag | Meaning |
|---|---|
| `--format table\|json\|sarif` | Output format (default `table`). |
| `--only data` | Findings on data stores only: buckets and storage accounts, databases, warehouses, caches, file systems, streams and secrets. |
| `--severity LEVEL` | Show only findings at or above this severity. It does not affect `--fail-on`, and the output says how many findings it hid. |
| `--check ID,ID` | These check IDs only. |
| `--compliance BENCHMARK` | Only checks mapped to a benchmark that applies to the provider (see below). Coverage per benchmark is in `docs/cspm-coverage.md`. |
| `--fail-on LEVEL` | Exit non-zero if a finding in scope (after `--only`, `--check`, `--compliance`) is at or above this severity. |

Benchmarks by provider: `aws` has `aws-fsbp`, `cis-aws-foundations` and `cis-eks`; `azure` has `cis-azure-foundations` and `cis-aks`; `gcp` has `cis-gcp-foundation` and `cis-gke`; `googleworkspace` has `cis-gcp-foundation`; `okta` has none. `cis-kubernetes` applies to Kubernetes, which this mode cannot scan.

Exit code 1 means either that `--fail-on` found a finding at or above the threshold or that the scan itself failed; the message on stderr says which.

The JSON output has `assets`, `partial` and `findings` (`check_id`, `severity`,
`title`, `resource_type`, `resource_id`, `remediation`, `evidence`, …).
SARIF carries each resource as the artifact URI (line 1) and as a logical location,
with a stable fingerprint per check and resource and a `security-severity` score per
rule. Whether GitHub code scanning accepts a result whose URI is a cloud resource ID,
not a repository file, has not been verified against a live upload.

## Permissions

Read-only access is enough, but for AWS the managed `SecurityAudit` and
`ViewOnlyAccess` policies cover most calls, not all: some checks (WAF rule
contents, Macie, Identity Center, Cost Explorer, Glue ML transforms, S3
Express) need extra read actions, and without them those checks have no data.
`docs/onboarding-aws-org.md` lists them and `deploy/aws/graph-readonly-role.yaml`
is a role with the full set.

## What a clean result means

If a permission or API error skips a service or region, the output is marked
partial: a warning in the table, `"partial": true` in JSON, and an unsuccessful
invocation in SARIF (plus a stderr warning for JSON and SARIF). With `--fail-on`
a partial scan exits non-zero even when it found nothing. Some best-effort
reads (for example individual Macie, CodeBuild or flow-log lookups) only log a
warning and do not set the partial flag, so "no findings" can still hide
a missing grant: give the scan the full read role.

This mode evaluates the registered checks over collected assets. It does not
report provider-native findings (GuardDuty, GitHub advanced security alerts),
and graph features (attack paths, blast radius, the DSPM view) need the full
stack.
