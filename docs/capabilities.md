# Capabilities

What Vulngraph does, in detail, with the limits of each part. The
[README](../README.md) has the summary; [known limitations](known-limitations.md)
lists the gaps that cut across features. If this page and the code disagree, the
code wins.

## Asset graph

Collectors cover AWS most deeply, with narrower coverage of GCP, Azure, GitHub
and Kubernetes, plus Okta and Google Workspace identity. Inventory lands in ClickHouse, and a
correlation sweep turns it into a property graph of typed edges (`graphschema.EdgeTypes`:
`ExposedToInternet`, `CanAssume`, `RunsPackage`, `DeploysTo`, `ConnectedViaSG`, …). Internet
exposure is derived from observed network rules and public-access configuration, re-computed
every sweep. Risk propagates by BFS (attenuating by 0.7 × the edge type's
registry weight per hop, at most 4 hops and 20 nodes per walk, adding at most 30 points).

## Network exposure evidence

GCE exposure matches each interface's network, destination address and IP family; omitted
source selectors in an ingress VPC firewall rule mean IPv4 world. Explicit source tags and
service accounts do not acquire that default. Numeric protocol aliases and ordered denies
are evaluated with destination applicability. Azure evaluates subnet and NIC NSGs for the
same private destination, source port and IP family, including observed ASG membership.
Unread rule lists, unsupported selectors and incomplete address evidence retain possible
exposure. Bounded evaluation also returns possible evidence when its work budget is exhausted.
EC2 public addressing and a world-open security group without route evidence remain possible.
For mixed-confidence exposure, `ports` describes the edge's grade and `possible_ports` retains
additional unconfirmed ports. Unmodeled non-transport protocol candidates remain possible.

These are modeled network decisions, not connection tests. AWS NACLs and GCP hierarchical
and network firewall policies are not applied to these exposure edges. GCP cross-project Shared VPC joins are also incomplete. Narrow Allow source
ranges are not a general source-address reachability solver. See
[known limitations](known-limitations.md) before interpreting an absent path as isolation.

## Graph engine

[LadybugDB](https://github.com/LadybugDB/ladybug), the community-maintained
successor of [Kùzu](https://github.com/kuzudb/kuzu), is linked unmodified as the prebuilt
library of a pinned release (see [`NOTICE`](../NOTICE)). It holds an in-memory projection of the graph for multi-hop Cypher.
Each correlate sweep re-reads the graph's load set from ClickHouse and rebuilds the
projection when that set's content digest changes (otherwise it refreshes scores and signals
in place); the worker writes a snapshot after each full rebuild, and mounting a volume for it
lets restarts warm-start. ClickHouse stays
the source of truth. Graph traversals (explore neighbours and seed matching) fall back to a ClickHouse BFS
if the engine is unavailable; raw Cypher, saved queries and NL-to-Cypher do not.

## CSPM and CIEM

About 850 posture checks, mostly AWS (roughly AWS 470, GCP 130, Kubernetes 130, Azure 120,
GitHub and Google Workspace a handful, at time of writing). They cover CIS Benchmark controls and other common misconfigurations. Per-benchmark coverage is in
[`docs/cspm-coverage.md`](cspm-coverage.md). There are also 66 documented CIEM
privilege-escalation techniques across AWS, GCP and Azure. AWS evaluation applies unconditional
explicit Deny statements, permission boundaries and SCPs, and Azure honours role NotActions.
Negated deny exceptions stay grouped within each statement. Trust analysis separates assumption
methods and distinguishes absent, false and true MFA context values. SCP grants are unioned
within each attachment level and intersected across the account/OU/root chain. Unreadable
restrictions remain uncertain candidate evidence. GCP IAM
deny policies and Azure deny assignments are not collected, so those paths can over-report too.
Detection is action-based: a technique fires when its actions are allowed on any resource, so
`iam:PassRole` on one harmless role counts the same as on `*` (the matched scopes are kept on the
result for triage), and an AWS Deny with a Condition is ignored. Expect raw path counts to
over-report; broad techniques such as `aws-privesc-15` (any `sts:AssumeRole`) are the noisiest.
Approximate AWS grants (including unevaluated conditions and unresolved policy variables) cannot establish
unrestricted admin authority for severity reduction. An explicit deny also prevents that
reduction, even when the engine cannot determine exactly how much authority it removes.

AWS boundary reads cover every collected role and user. Failed attachment or document reads
retain incomplete restriction evidence; partially read or malformed SCP sets do the same.
These inputs preserve candidate paths without proving admin authority. Known unconditional
denies still apply, but an incomplete cap's Allow intersection is skipped because missing
Allow documents could otherwise erase candidates. The collector's `admin` hint cannot override
the AWS evaluator's tier. Legacy principal assets without boundary completeness evidence remain
uncertain until recollected, unless they already contain a readable attached boundary. Legacy
SCP assets without typed organization and attachment-level evidence are also uncertain until
refreshed. Missing organization evidence cannot prove that SCPs do not apply. The selector
distinguishes observed standalone accounts, management accounts, member accounts, disabled SCP
policy types, and service-linked roles. Ordinary service and deployment roles are not exempt.
A same-sweep membership observation rejects contradictory older organization records.
Stored organization observations expire after 24 hours (one missed cycle at the scheduler's
12-hour maximum interval); this is a local evidence policy, not an AWS guarantee. Their
collection timestamp is persisted but excluded from semantic content hashing.
The resulting organization-coverage observation reaches CIEM, graph permissions, posture
checks and finding resolution; a raw collector admin hint cannot substitute for it. SCP and
boundary alternatives preserve every compatible action/resource overlap, independent of order.
These observations still do not model session policies, resource-control policies, every
resource policy or the resource compatibility needed by every escalation technique.

Azure RBAC candidates retain their ARM assignment scopes, assignment conditions and independent
permission blocks. Data-plane permissions are stored separately and do not grant ARM actions.
Scope comparisons respect resource hierarchy and identifier boundaries; management-group
ancestry is not inferred. These rules follow [Azure scope semantics](https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview)
and the [control/data-plane separation](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions).
Assignment conditions remain unevaluated, and [deny assignments](https://learn.microsoft.com/en-us/azure/role-based-access-control/deny-assignments)
are not collected. Therefore even a subscription Owner assignment is an approximate permission
candidate and does not lower escalation severity on the premise of already proven admin access.
Legacy or partial Azure inventory cannot establish a clean CIEM evaluation or close findings;
refresh it to collect `role_grants_complete` evidence. Legacy exclusions cannot suppress ARM
candidates because their assignment grouping or control/data-plane origin was lost. Resource compatibility across
multi-action techniques, deny-assignment enforcement, group membership and Entra authorization
remain outside this ARM candidate model; it is not an Azure authorization simulator.

GCP IAM collection unions service-account grants from the project and its ancestors.
A condition is excluded as expired only when its entire expression is a supported timestamp
comparison; compound CEL expressions remain candidates. In particular, a
[limited IAM administrator](https://docs.cloud.google.com/iam/docs/setting-limits-on-granting-roles)
may hold `projects.setIamPolicy` while being allowed to grant only selected roles.
Because conditions and [GCP deny policies](https://docs.cloud.google.com/iam/docs/deny-access-change-permissions)
are not evaluated, neither an Owner label nor a set-IAM-policy permission lowers CIEM severity
as proof of unrestricted authority. Failed ancestry or role-definition reads retain known
candidates but mark the permission observation incomplete. Legacy inventory without explicit
`roles_complete` and `permissions_complete` evidence stays unknown until refreshed; it cannot
close dependent findings as fixed. Complete empty observations can still close findings.
These flags describe the collected hierarchy and role definitions, not a complete GCP
authorization model: resource-level bindings, group membership, principal access boundaries
and IAM deny policies are not resolved by this service-account permission union.
GCP candidates receive the `high` privilege tier rather than a claim of proven admin or
escalation to admin; a legacy collector `admin` hint cannot override that distinction.

For GCS, the bucket's `inherited` public-access prevention setting is not itself a verdict.
The collector reads the nearest configured boolean policy in the project, folder and
organization hierarchy. Unconditional enforcement overrides retained public IAM bindings;
an explicit reset or a completely read hierarchy without a policy uses the constraint's
unenforced default. Conditional policies require bucket-tag evaluation and remain unknown,
as do unreadable or incomplete policy/ancestry responses. Unknown prevention produces neither
a missing-guardrail conclusion nor a public/private exposure verdict. Direct bucket enforcement
still establishes protection without ancestor reads. Required reads are in
[GCP permissions](iam/gcp-cspm-permissions.md).

## Vulnerabilities and supply chain

VM package CVEs come from AWS SSM Inventory and GCP OS
Config, matched against OSV, KEV and EPSS. GitHub SBOMs become package nodes. `depends_on` means
a package is in the SBOM; `runs_package` means it is running on a workload. Container images are
pulled and scanned for their OS and language packages (`IMAGE_SCAN_DISABLED` turns that off). A VM
with no SSM or OS Config inventory can get one from its disk (below).

### VM disk scanning

Disk scanning reads a VM's boot disk from a cloud snapshot, finds its OS package database
(dpkg, apk, rpm) and uses the package list the same way as an SSM or OS Config one. Nothing is
installed in the VM. It is **off by default and opt-in per connector**: the `DISK_SCAN_ENABLED`
switch makes the jobs exist, and then an admin signed in as a person turns it on for each AWS or
Azure connector on the Connectors page (`PUT /api/connectors/{id}/disk-scan`, never an API key or
MCP) by typing a sentence that names the cost and the permissions. That is the standing approval
and is audited as `connector.disk_scan_change`.

- **`existing_snapshots`** reads snapshots you already have, with a read-only snapshot grant.
  Nothing is written to your account on AWS; on Azure it needs the dedicated disk-scan principal with a
  read-only role, which requests a short-lived read SAS on each snapshot and never creates or deletes one.
- **`create_snapshots`** also creates a tagged snapshot of the volume, reads it and deletes it, using
  a separate dedicated role that can do nothing else. Snapshots live 6 hours at most (a sweeper
  deletes any tagged one past that, even without a database record); by default 2 snapshots are
  alive at once and 50 are created a day.
- **Bring your own agent** keeps snapshot permissions out of Vulngraph: your scanner submits the
  package list ([bring your own agent](iam/byoa-inventory.md)).

Per-cloud grants: [AWS](iam/disk-scan-aws.md), [Azure](iam/disk-scan-azure.md). GCP can only be
set to `existing_snapshots`, and nothing reads GCP disks yet.

A VM's disk-scan state is `scanned`, `not_enabled` or `none` (shown on the asset page, in
`GET /api/assets/{id}/disk-scan` and in MCP `get_disk_scan_status`). **`not_enabled` means the
connector has not opted in, so the disk was not read.** `none` means it is enabled but no readable disk produced a
package list. Both are unknown, never "no vulnerabilities", and each volume that was not read
carries a gap (`no_snapshot_available`, `snapshot_pending`, `encrypted_no_key`, `unsupported_fs`,
`unsupported_partition`, `read_error`, `over_cap`, `permission_denied`, `stale`). A result older
than 7 days is `stale`. Vulnerabilities are matched by the same
`refresh_vm_vuln` job as any other VM inventory.

What it reads: Linux boot volumes on ext2/3/4 or XFS, under an MBR or GPT partition table, and only
the package databases and OS release files; the filesystem readers are Vulngraph's own, written
for untrusted input. Limits are in [known limitations](known-limitations.md) and the risks in
[threats 17 to 19](threat-model.md).

## Prioritisation

Each finding is enriched into a 0–100 contextual score from blast radius,
KEV/EPSS and graph signals. Findings also get a structural "safe to fix" class and an
evidence-backed "must fix" class (internet-reachable attack path, exploitability, blast radius;
or a non-test-mode credential leaked in a public repository). Vulngraph does not test leaked keys
itself: a key is called live only when GitHub's secret-scanning validity check reports it
`active`; with no verdict the reason says "validity unknown", and the key is still treated as
urgent rather than safe.
An unknown internet-hop count is kept as unknown rather than scored as 0-hop.
Familiar role names (managed roles, deployment roles and default service accounts) never
suppress escalation findings. An observed absence of a modeled internet path remains a
bounded scoring heuristic, not proof of safety or absence of other entry points; unavailable
reachability adds no negative factor. The scoring logic version advances to `v2` so the
existing full-pass mechanism recalculates findings previously suppressed by name.

## Scanning

Vulngraph analyzes container images and package inventories and supports opt-in
VM disk inventory. Active external probing, Nuclei templates, scan profiles and
the generic scan-import API have been retired. Historical findings remain
available. Use the scoped package-inventory API for external VM inventory.

## IaC

Terraform in connected GitHub repos is checked against a small set of 10 rules, all for AWS
resources (S3, security groups, RDS, EBS, KMS, IAM policies, EC2). Declared infrastructure (k8s manifests, Terraform state, CI-workflow role
federation, role ARNs and service-account emails written in repo files) is joined to the live
graph by deterministic keys.

## Data-sensitivity tagging

Storage assets are tagged with a likely data class using a
name/tag heuristic. Content is not scanned.

## Reasoning and governance

For higher-scoring findings, the respond worker asks an LLM
(any supported provider: the Anthropic API or an OpenAI-compatible server, hosted or local; see
[`docs/llm-providers.md`](llm-providers.md))
for an action plan, with the graph context attached. Every state-changing plan waits for a
person; only read-only `observe` plans need no approval. Confidence comes only from people:
their denials (from a signed-in session or an email link; an API key cannot record a verdict)
and the results of fixes a person approved that then ran. It sets how urgently a proposal is
raised, not whether a person is asked. The LLM output is advisory: a proposed plan or severity verdict is a
suggestion for a person to judge. An approval webhook receiver you wire up to act on
approvals is outside the executor's checks
([Approval webhook](security-hardening.md#approval-webhook)).

The quality of the LLM's decisions is not measured in CI. CI unit-tests prompt building and
response parsing against a fake model, which catches structural breakage, not bad judgement.
Two small hand-written golden sets make real LLM calls and run only when someone starts them:
locally (`go test -tags=eval ./internal/reason/`) or through the manual
`.github/workflows/eval.yaml` workflow. Nothing runs them on a prompt or model change. The
respond set (10 cases) checks one thing per case: whether the reasoner picks a read-only
`observe` plan or proposes an action. Every case must pass. It does not grade the rationale or
which action class is proposed. The adjudicator set (8 cases) checks only whether a
high/critical verdict holds or is demoted, and passes at 7 of 8. Each case is sampled once, so a
green run is one draw from a non-deterministic model, not a pass rate. No results are published
for any model.

**Drift analysis** is an LLM reading of each connector's new inventory changes (the `drift_analysis`
purpose). It is off by default (`DRIFT_ANALYSIS_ENABLED`), advisory, and never starts a scan: it writes a
summary, an exposure judgement and a recommended, not needed or unknown scan call, shown on the Drift page
and over MCP. Evidence is checked against the assets in the prompt, and a "not needed" is only kept when every input was known and the batch was not truncated.
A failure or an exhausted budget gives unknown, never "no scan needed". It has no scan-start tool or executable profile suggestion. Its quality is checked only by a six-case opt-in drift set.

## Detections, alerting, MCP

Scheduled Cypher detections, outbound Slack and webhook alerts,
and a JSON-RPC 2.0 MCP endpoint (`POST /api/mcp`) with scoped `gph_` keys, so any MCP client
can query the graph. Sign-ins (and refused ones), sign-outs, live cloud reads (over MCP and in
chat), executions, suppressions, manual finding resolves, and changes to connectors, users, API
keys, alert channels, the approval policy, saved queries are written to
`audit_events` ([list](security-hardening.md#what-is-recorded)); other reads are not audited
per call, and an API key records only `last_used_at` (and an `auth.api_key_refused` row when a
session-only route turns it away).

## Observability

Off by default: Prometheus `/metrics` (`METRICS_PORT`) and OpenTelemetry
tracing (`OTEL_EXPORTER_OTLP_ENDPOINT`).

## Process modes and sign-in

The binary has three long-running modes: `serve` (HTTP API + UI), `worker` (sync, correlate, enrich,
respond and inventory jobs) and `scanner` (runs opt-in disk-volume reads in isolation; in the
Helm chart it gets neither `GRAPH_SECRET_KEY`, the LLM key nor a cloud identity, see
[`security-hardening.md`](security-hardening.md#credential-isolation)). Its
datastore users are its own (`graph_scanner`): River's job tables and the disk-scan tables on
Postgres, and the schema readiness ledger on ClickHouse, and nothing on
users, API keys or connectors, so code running in the scanner cannot make itself a Vulngraph
admin through the database. It can still enqueue or delete River jobs and write scan results
and findings. Docker Compose has no scanner pod; there scans run inside the worker, which holds
everything (template tests run in serve), so treat the Compose stack as an evaluation setup. Sign-in is local
email/password accounts (`graph user create`; turned off behind IAP or oauth2-proxy unless
`PASSWORD_LOGIN_BREAK_GLASS=true`), Google OAuth, Okta OIDC, GCP IAP, or a cluster
oauth2-proxy. `BYPASS_AUTH` turns authentication off; see
[`docs/security-hardening.md`](security-hardening.md) before using it. Some layering
rules are lint-enforced (storage imports in domain, handler and service files;
the LLM SDK quarantine) and the rest are checked in review; see
[`CONTRIBUTING.md`](../CONTRIBUTING.md).
