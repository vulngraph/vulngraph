# Evaluating Vulngraph

For anyone deciding whether to try it: what it needs, how to try it without risk, and where to check each
claim in the code.

## At a glance

| | |
|---|---|
| What it is | A self-hosted security graph for cloud accounts: inventory, attack paths, posture checks, vulnerability scanning and risk ranking by what an attacker can reach. |
| License | Apache-2.0 |
| Stack | One Go binary (`serve`, `worker`, `scanner`), Postgres, ClickHouse, an embedded React UI, LadybugDB as an in-memory Cypher engine. |
| Sources | AWS, GCP, Azure, GitHub and Kubernetes, plus Okta and Google Workspace identity. |
| Coverage | About 850 posture checks mapped to CIS Benchmarks, 66 privilege-escalation techniques across AWS, GCP and Azure. |
| Access it needs | Read-only. Connectors start in `read_only` mode, and the executor rejects every action on one before it makes any cloud call. |
| LLM | Optional. It proposes; a person approves. |
| Status | Pre-1.0, one maintainer, built with AI coding assistance, used internally before this first public release, no independent security testing yet. |

## Try it with no credentials

The bundled demo is a fictional AWS account. It makes no cloud calls.

```sh
git clone https://github.com/vulngraph/vulngraph
cd vulngraph/deploy/docker-compose
docker compose up -d
docker compose exec serve /graph scan demo     # the checks, no database needed
```

[Getting started](getting-started.md) shows how to load the demo into the UI, and
[examples](examples.md) shows what you will see.

## If you connect a real account

Use a sandbox or a read-only role first. Do not hand a new tool broader access than it needs.

- **Read-only by default.** For AWS the role is `SecurityAudit` plus `ViewOnlyAccess` plus a short list of
  extra reads. The CloudFormation template is
  [`deploy/aws/graph-readonly-role.yaml`](../deploy/aws/graph-readonly-role.yaml) and the reasoning for each
  extra is in [`onboarding-aws-org.md`](onboarding-aws-org.md). Read the template before you apply it.
- **No write access unless you grant it twice.** A connector must be switched to `read_write` by an admin,
  its role must be given the write permissions, and every state-changing action then needs an admin's explicit
  request. Destructive actions also need a second admin's approval. An API key cannot switch a connector to
  `read_write` ([details](security-hardening.md#connectors-and-remediation)).
- **Nothing remediates on its own.** Only read-only actions run without a person.
- **Credentials are isolated.** The scanner runs in its own pod with no encryption key, LLM key or cloud
  identity, and the application's database users cannot change the schema or rewrite the audit log.
- **You can see every outbound connection.** They are listed in
  [configuration](configuration.md#network-egress), each with a switch, and `OFFLINE_MODE=true` turns off the
  ones that can be.

## Check the claims in the code

| Claim | Where to look |
|---|---|
| Privilege escalation honours Deny, permission boundaries and SCPs | `internal/app/ciem/evaluator.go` and the tests beside it |
| Exposure needs a public entry point and a permissive path | `internal/app/correlate/reachability.go` |
| The graph only reads fresh edges | `TestGraphEdgesReadersApplyFreshness` in `internal/graphschema` |
| Nothing state-changing runs without a person | `TestAutoExecuteGateRequiresKnownEvidence`, `TestGate_NoStateChangingInputIsAutonomous` in `internal/policy`; `TestOnlyHumanTransportsBuildExecutionRequests` in `internal/app/executor` |
| Every write route is role-gated | `TestEveryWriteRouteIsGatedOrExempt` in `internal/httpsrv` |
| Data it could not read is not reported as clean | the "degraded input" rule in [`AGENTS.md`](../AGENTS.md) and the tests that pin it |

## How much is behind it

The repository has about 5,000 Go test functions across roughly 900 test files, 64 of them integration tests
that run against real Postgres and ClickHouse in CI, and 308 frontend tests. The AWS collector alone is 130
source files with about 100 test files. A separate harness mutates each structural guard and fails the build if
the guard does not fail with it. CI runs lint, tests, secret scanning and CodeQL on every change.

## Missed paths and false negatives

In a security graph the dangerous bug is the quiet one: a privilege-escalation path that is not drawn, so the
result looks clean. The code is written against that failure:

- **Missing data is unknown, never clean.** A collector that could not read something records that it could
  not, and checks that depend on it stay silent instead of passing. The project rule is "a zero value is not a
  measurement" ([`AGENTS.md`](../AGENTS.md)), and tests pin it for the paths that matter. For example, an
  unreadable permission boundary or SCP fails open, so it can only add findings, never hide one.
- **Completeness is proven before anything is deleted.** A sweep that did not list every page cannot mark
  resources as gone or findings as fixed.
- **The gaps are written down.** [Known limitations](known-limitations.md) lists what it does not model, such
  as network ACLs in exposure, GCP firewall policies and EKS Pod Identity, and the compliance rollup shows
  controls it cannot assess as unknown. Treat a clean result as "clean within what it reads", and run it
  beside your other tools, not instead of them.

## Prompt injection and the approval step

Resource tags, repository names and finding titles are text an attacker can choose, and an LLM may read them.
The design assumes that text is hostile:

- **Untrusted text is fenced.** Everything a cloud or scanner returned is wrapped in markers that the model is
  told to treat as data, and one shared escaper (`pkg/promptfence`) neutralises any attempt to forge the end
  marker. Fencing reduces the risk and cannot remove it, so it is not the control that matters.
- **The model cannot invent an action.** Remediation is a fixed catalogue of typed actions, such as
  `sg_rule_remove`, `s3_block_public` and `iam_key_disable`. An unknown action is rejected, parameters are
  validated, and a dry run shows the plan. The model chooses among them and cannot widen what one does.
- **A person approves, and an agent cannot approve for itself.** A read-only connector rejects every action
  before any cloud call. Executions from an API key or an MCP client always need a grant minted by a
  different admin from a signed-in session, and a key can never mint a grant. A grant expires in 10 minutes and
  works once. Destructive actions also need a second admin.
- **Every execution is recorded first.** An intent row is written before the cloud call, and the call is
  refused if it cannot be written. Routine actions can be undone from the request and audit row.
- **Limits.** The two-person rule compares user ids, so it does not stop one person who holds two admin
  accounts. An approver must have been an admin for at least 24 hours by default (counted from account creation or promotion to admin, whichever is later), and
  [security hardening](security-hardening.md#connectors-and-remediation) says how to narrow this further.

## Audit it yourself in five minutes

```sh
git clone https://github.com/vulngraph/vulngraph && cd vulngraph

gitleaks dir .                       # secrets; CI runs this on every change, with no allowlist file
grep -n '^FROM\|^USER' Dockerfile    # every base image is pinned by digest; the runtime user is nonroot
ls scripts third_party               # six helper scripts, and two inert stand-in modules (see NOTICE)
go list -m all | wc -l               # inspect the current module count
grep -rn 'http.Client{' --include='*.go' . | grep -v _test    # HTTP clients are built only in pkg/safenet
grep -n 'permissions' -A1 .github/workflows/*.yaml            # workflows default to read-only
grep -n 'Reject read-only' -B2 -A3 internal/app/executor/service.go   # the only path that changes a cloud
```

The frontend has 10 production dependencies. The first thing to read is
[`docs/security-hardening.md`](security-hardening.md); the second is
[`docs/configuration.md`](configuration.md#network-egress), which lists every outbound connection. The [threat model](threat-model.md) puts the boundaries and the undefended cases in one place.

## What to know before relying on it

- **Limits.** [Known limitations](known-limitations.md) lists the gaps that affect what it reports, such as
  network ACLs and GCP firewall policies not being applied to exposure.
- **Age and history.** This repository starts at the first public release. Earlier development history was
  not published, so the commit count says little about how much is behind it. Pre-1.0 means APIs and the
  schema can change.
- **AI-assisted development.** It is built with AI coding assistants under written rules
  ([`AGENTS.md`](../AGENTS.md)), and every change goes through the same tests and checks as any other.
- **Internal use, no independent security testing yet.** It ran internally, including in production, for a while
  before being open sourced, but it has had no third-party security review or penetration test. Treat it as
  new to public scrutiny. Report
  vulnerabilities privately through [GitHub security advisories](https://github.com/vulngraph/vulngraph/security/advisories/new)
  or as described in [`SECURITY.md`](../SECURITY.md).
