# ADR 063: CI-workflow → cloud-identity federation

**Status:** accepted (2026-07-18)

## Context

The only repo → cloud-identity link the platform had was `federation_trust`
(`internal/app/correlate/federation.go`): it parses the **AWS side** of the
relationship — an IAM role's trust policy — for a GitHub Actions OIDC `sub`
(`token.actions.githubusercontent.com:sub` → `repo:org/name:ref:…`) and joins it
to a `Repo` node. That is authoritative when it fires, but it is blind whenever
the role lives in an account the AWS connector does not scan, the repo assumes
the role with static credentials rather than OIDC (no trust entry to parse), or
the batch IAM sweep never ingested the role at all (paging / filter / timing —
so there is no live node to join to in the first place).

This can leave few `federated_access` edges, and whole families of
service repos with none, even when the relevant accounts and roles are
inventoried: the missing piece is not missing accounts but the missing **link**. The untapped, uniform source is the repo side:
the GitHub Actions workflow YAML itself encodes the repo's intent to assume a
specific role or service account **by ARN / email** — a far stronger, more
durable join key than the name/label heuristics `DeploysTo` relies on, and one
that exists regardless of whether the target role trusts OIDC, static keys, or
is even scanned yet.

This ADR complements ADR 061 (IaC → graph correlation — the collector-supplies
/ correlate-joins pattern this feature follows) and ADR 062 (cloud→Ladybug sync
fidelity — the same "silent drop becomes a visible signal" principle applied
here to unmonitored federation targets).

## Decision

**Parse the repo side of federation from workflow YAML; reuse the existing
`federated_access` edge type; make unresolved matches visible instead of
silently dropped.**

- `internal/collect/iac/workflows.go` is a pure leaf parser: given the text of
  one `.github/workflows/*.{yml,yaml}` file, it recognizes
  `aws-actions/configure-aws-credentials` (`with.role-to-assume`) and
  `google-github-actions/auth` (`with.service_account`) steps and emits
  `[]DeclaredCIAccess{Provider, TargetARN|TargetSA, WorkflowPath, Resolved}`.
  A `${{ … }}` expression, `env` var, or matrix value we cannot statically
  resolve is emitted with `Resolved:false` and no ARN — counted for coverage,
  never guessed and never joined.
- `internal/collect/github/workflow_ingest.go` walks `.github/workflows/`
  across **all** non-archived repos (the same bounded-tree-walk shape as
  `iac.go`) and projects each resolved record into a
  `declared_ci_access` asset. Like `declared_k8s_workload`, this is a correlation-only intermediate: it is in
  `asset.NeverSyncTypes` (never synced into Ladybug as a node) and exists purely
  so the correlate sweep can join it against the live inventory.
- The new `ci_access` correlate rule (`internal/app/correlate/ci_access.go`)
  joins each `declared_ci_access` asset's target ARN/SA against the live
  `iam_role` / `gcp_service_account` node id (both are ARN/email-keyed
  already, so no new index is needed):
  - **Live match** → emit the existing `federated_access` edge (repo → role),
    `provenance:"gh_workflow"`, `confidence:"high"`. Reusing the edge type
    means the result flows through the "Repos with cloud access" preset, the
    NL prompt, reach/BFS, and contextpack with **no new frontend or reach
    work** — this is a pure coverage improvement to an existing capability,
    not a new one.
  - **No live match, but the target account maps to a known connector** →
    accumulate as a `PendingVerify` candidate rather than dropping it; a
    `verify_ci_role` River job does a live `GetRole` out-of-band (the
    correlate sweep is a full rebuild every cycle, so inline per-ARN live
    reads would make it slow and rate-limit-fragile). On success the role is
    ingested as a first-class `iam_role` asset and the edge is emitted with
    `provenance:"gh_workflow+live"`, marking that the role was confirmed by a
    live read rather than inferred from declared config. This label marks the
    verification event, not a durable state: `graph_edges` is a
    `ReplacingMergeTree` keyed on `(src_id, edge_type, dst_id)` (properties are
    not in the key), so once the role is a known node the next correlate sweep
    re-stamps the same edge as plain `gh_workflow`. Both values are
    `confidence:"high"` and both are matched by the "Repos → roles their CI
    assumes" preset, so the edge stays queryable either way — do not rely on
    `gh_workflow+live` persisting as a durable marker.
  - **No live match and no connector for the account** → emit a low-severity
    `unmonitored_federation` finding on the repo instead of silently dropping
    the reference. The blind spot becomes a visible, actionable signal:
    "this repo's CI assumes a role in an account we do not monitor."
- GCP has no equivalent live-verify tail in this slice: an unmatched
  `target_sa` is simply skipped (counted for coverage, not escalated to a
  job); see Consequences.
- No new node or edge type: `federated_access` already exists and is already
  loaded for `Repo → IamRole` (which `gcp_service_account` also maps into, per
  `assetTypeToNode`). The Ladybug rel table was extended to carry the
  `provenance`/`confidence`/`workflow_path` properties these edges stamp
  (previously it persisted only `trust_type`/`subject`, silently dropping the
  rest), so `SchemaVersion` was bumped.

## Consequences

- **Coverage, not correctness, is the axis this changes.** `federation_trust`
  remains the authoritative source when a trust policy is present — this
  feature does not replace it, it fills the gap where CI reaches a role/SA
  the trust-policy parse or the batch IAM sweep never surfaced. Where both
  fire for the same edge, the deterministic reconciler keeps the
  highest-confidence provenance and records both.
- **Coverage honesty on unresolved expressions.** A workflow that assumes a
  role via `${{ secrets.ROLE_ARN }}`, an `env:` var, or a matrix value is
  explicitly `Resolved:false` and never joined — this feature does not
  attempt to reconstruct dynamic values, so a repo with only dynamic
  role-assumption steps still shows zero `gh_workflow` edges. That is a
  stated, logged limitation, not a silent miss: it is the same honesty
  convention the Terraform parser already uses for unsupported shapes.
- **Asymmetry between AWS and GCP is deliberate, not an oversight this
  slice.** AWS gets the full three-tier resolution (live match → live-verify
  job → unmonitored finding) because `LiveAWSCaller.GetRole` and a connector
  registry keyed by AWS account ID already exist. GCP stops at "live match or
  skip" because there is no equivalent live-verify job wired for GCP service
  accounts yet. A future slice can add one following the same
  `verify_ci_role` pattern.
- **`unmonitored_federation` findings are new, visible risk signal** on repos
  whose CI reaches an account with no connector — previously this was
  invisible (no edge, no finding, nothing to triage). This is intentionally
  low-severity: the finding says "we can't see this account," not "this is
  misconfigured."
- **No new job lane class beyond `verify_ci_role`** — it rides the existing
  River `enrich`/`verify` queue pattern (ADR 002), `MaxAttempts` bounded,
  read-only (`GetRole`), so a failed lookup never mutates cloud state and
  never blocks the correlate sweep.
- **No new edge type.** This is an additive join against an existing,
  already-loaded rel; the only `SchemaVersion` bump is for the
  extra rel properties described above.

Cites ADR 061 (IaC → graph correlation — the collector-supplies /
correlate-joins split this feature follows, and the `NeverSyncTypes`
intermediate-asset pattern), ADR 062 (cloud→Ladybug sync fidelity — the "silent
drop becomes a visible signal" principle, applied here to unmonitored
federation targets instead of collector 403s).
