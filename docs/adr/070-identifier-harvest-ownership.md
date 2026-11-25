# ADR 070 — Map IAM-as-code by harvesting identifiers, not by per-tool parsers

**Status:** accepted (implemented 2026-07-31)

## Context

Repo→cloud-identity ownership was built one tool at a time: Terraform state (ADR 065, with
`tfstate_aws_account_id` as its fallback account) and a workflow parser (ADR 063). Every new
place identities are defined needed a new parser, a new config key, or both.

That model does not scale to where identities can live. IAM roles and policies can be
declared as raw IAM JSON across many Terraform root modules, in separate per-environment
repositories, and as literal role ARNs written in many files — none of which a per-tool
parser reads.

## Decision

Add a generic, configuration-free path that runs alongside the per-tool parsers: **harvest
identifiers, then join on exact equality.**

1. **`iac.HarvestIdentities`** (pure) extracts concrete cloud identities from any file's bytes
   — IAM role/user ARNs, GCP service-account emails, GitHub Actions OIDC subjects. Content type
   is irrelevant: Terraform, CDK, CloudFormation, Helm, k8s manifests, IRSA/Workload-Identity
   annotations, raw policy JSON and shell glue all write these identifiers identically.
2. **`collectRepoHarvest`** sweeps every non-archived repo in every collected org over a
   broad extension allowlist (bounded: `harvestMaxFiles = 400` files/repo,
   `harvestConcurrency = 8` repos in parallel, vendored/generated dirs skipped, truncation and
   caps logged; `internal/collect/github/identity_harvest.go`).
3. **`declared_cloud_identity`** intermediates carry `(repo, path, kind, value)`.
4. **`correlate.DeclaredIdentityOwnership`** joins them to live assets and emits `defined_in`
   (live identity → repo) and, where a trust policy's OIDC subject sits alongside a role ARN in
   the same file, `federated_access` (subject's repo → role). Both reuse existing rels, so there
   is no Ladybug schema change.

Two properties make this trustworthy rather than heuristic:

- **The join is string equality against a live asset ID.** Role ARNs and service-account
  emails are globally unique and byte-identical on both sides. Nothing is reconstructed, so
  edges are `confidence: high`.
- **Non-literals are rejected.** `${...}`, `!Sub`, Helm templates and wildcards name no single
  identity. The identity patterns never match their characters (`$`, `{`, `}`, `*`), so a
  match that runs into one is dropped rather than harvested truncated: followed by `${`, `{{`
  or a lone `*` (`role/app-${env}`, `role/app-*`), or preceded by `}` or a lone `*`
  (`${p}-sa@…`). Braces and asterisks that only delimit a whole literal (a YAML flow mapping,
  Markdown bold) do not count, nor do parentheses or angle brackets: an identity in prose, an
  XML element or a Markdown link is still harvested. An account id must be a full 12 digits.

An identity with no live match is skipped, never guessed at: it means the account is not
collected or the reference is stale, and inventing an edge to a nonexistent node fabricates
topology (the failure behind ADR 049 and the `resolveTargetPrincipals` fix).

## Consequences

- A new repo, org, or IaC tool is covered as soon as it appears: no config key, no parser.
  The per-tool parsers stay, because they extract structure the harvest cannot (k8s workload
  shapes, Terraform state addresses, workflow role assumptions).
- Cost is one tree listing plus up to `harvestMaxFiles` content fetches per repo per sweep,
  concurrency-bounded and sharing the GitHub client's rate limiting.
- `federated_access` from a trust policy requires exactly one literal role ARN in the same file
  as the subject: the harvest records which file a subject sits in, not which role block, so a
  file naming no role or several is skipped. That pairs raw policy JSON and hand-written trust
  files that spell out their role's ARN. It does not pair a Terraform `aws_iam_role` with its
  `assume_role_policy`, or a CloudFormation role, because those reference the role's ARN as
  `${aws_iam_role.x.arn}` or `!GetAtt`, which contain no ARN text for the harvest to match. A subject alone
  in prose or a README yields nothing, which is correct.
- Remaining gap: a file that holds only a trust policy and never writes its role's ARN (the
  role's name comes from elsewhere, such as the module that creates it) yields no ownership
  edge. Terraform state (ADR 065) covers that case when the state is readable. A role name is
  never inferred from a filename.

Cites ADR 061 (the IaC ownership model this generalizes), 063 (the workflow-side federation
path, whose IAM-side counterpart this is), 065 (Terraform state, which covers roles whose ARN
no file writes).
