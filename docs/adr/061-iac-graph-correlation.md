# ADR 061: IaC → graph correlation by deterministic join keys

**Status:** accepted (2026-07-17); amended 2026-07-18, 2026-07-31

## Context

The platform sees cloud/k8s **assets** but not **who defines them**. IaC lives in Git
(Terraform, JSON policies, Helm charts, k8s manifests) and none of it was correlated into the
graph. The existing GitHub collector (`internal/collect/github/iac.go`) parses Terraform only
for *misconfigurations*; its own comment records that linking a `.tf` resource to a live asset
was tried and abandoned ("needs tfstate … a manual resource-name-to-asset-name join found zero
matches"). So the graph had no `defined_in` ownership edge (the biggest triage gap: "who fixes
this?"), no drift signal, and no attack-path provenance ("this reachable role is defined in PR
X").

Correlation is tractable when the join key is stable: an identifier the declaration and the
live inventory both carry verbatim — a k8s `kind`/`namespace`/`name`, an ARN, a durable SSO
group or permission-set name.

## Decision

**Deterministic join keys are primary; the LLM adjudicator is not built.** Correlation
quality is a function of join-key strength. Exact keys (`kind`+`namespace`+`name` for
k8s manifests, SA annotations, durable names like SSO group/permission-set names) are
matched deterministically and never touch an LLM. The ADR 053 adjudicator is reserved for a
later slice as a confirm/refute **verifier on the low-confidence tail only**; it is never the
primary matcher, so the graph never carries a hallucinated edge from this pipeline.

**Slice 1 adds the SSO access graph** — who can reach which account through AWS IAM Identity
Center — as graph structure the later IaC slices can hang ownership off:

- This slice declares the node labels, edge types and Ladybug projection. Their producer is
  the Identity Center collector (`internal/collect/aws/identitycenter.go`), which emits the
  edges from the provisioned assignments it reads (second 2026-07-31 amendment).
- The projection adds new Ladybug node labels and loaded rels via the
  `internal/graphschema` registry (ADR 048), gated by a `SchemaVersion` bump
  (ADR 026/`graphstore/domain.go`) so stale PVC snapshots are rejected and
  rebuilt from ClickHouse.

### New node labels

| Label | Reuses existing type? | Notes |
|---|---|---|
| `Group` | No — new | SSO group. Named `Group` in the registry; the Ladybug Cypher DDL binds it as `` `Group` `` (backtick-escaped — bare `GROUP` collides with the Cypher `GROUP BY` keyword). `id`/`name`/`provider` only. |
| `PermissionSet` | No — new | SSO permission set. Carries `grants_admin` so Cypher can filter `p.grants_admin = true` directly. |
| `CloudAccount` | Yes — existing | Anchor for `GrantsAccessTo`/`GrantsAdmin`; no new node type needed. |

### New edge types (`internal/graphschema` registry)

| `edge_type` (ClickHouse) | Rel (Ladybug) | From → To | Meaning |
|---|---|---|---|
| `assigned_to` | `AssignedTo` | `Group → PermissionSet` | the group holds the permission set |
| `grants_access_to` | `GrantsAccessTo` | `PermissionSet → CloudAccount` | the permission set is provisioned to the account |
| `grants_admin` | `GrantsAdmin` | `PermissionSet → CloudAccount` | as above, when the permission set grants admin — a reach-eligible edge (BFS weight 0.8) |

All three are declared and derived exactly like every other edge type per ADR 048: tier,
Ladybug-load status, BFS weight/reach flag, and doc line live in the registry, and
`TestRegistryDerivationsMatchLegacy` / `TestLadybugRelSpecMatchesDDL` pin them the same as
any other edge.

### Provenance and confidence convention

Every edge this pipeline projects carries two rel properties:

- `provenance` — where the edge came from: `identity_center` for slice 1, `iac_manifest`,
  `iac_terraform`, `identifier_harvest` and the CI-workflow values as later sources come
  online.
- `confidence` — full confidence for a resolved deterministic join key; reduced only where
  the key itself is weaker (a manifest that resolves to several clusters, or omits its
  namespace, is `medium`).

The convention exists so the UI and Cypher can filter on trust level once multiple
provenance sources project into the same node/edge types.

### Phased slice plan

1. **Slice 1 (this ADR)** — the SSO access graph, described above.
2. **Slice 2** — k8s manifests correlated to live `k8s_*` assets by
   `kind`+`namespace`+`name` (exact join key), plus service-account annotations
   (`iam.gke.io/gcp-service-account`, `eks.amazonaws.com/role-arn`) wired into the
   existing `ExecutesAsK8sWorkload`/`FederatedAccess` edges. First drift diffs
   (declared-not-live / live-not-declared) land here.
3. **Slice 3** — generic multi-format ingest (JSON policies, tfstate-augmented Terraform)
   with the ADR 053 LLM adjudicator confirming or refuting the weak-key tail that
   deterministic joins can't resolve.

Drift detection and the LLM adjudicator are **not** part of slice 1.

## Consequences

- The SSO surface is queryable: `MATCH (g:Group)-[:AssignedTo]->
  (ps:PermissionSet)-[:GrantsAdmin]->(a:CloudAccount) RETURN g.name, ps.name, a.name`
  returns group and account names, not raw GUIDs.
- Additive only: no existing node/edge type changes shape, so the change is a pure
  `SchemaVersion` bump; existing queries and presets are unaffected.
- No new job lane, no new infra: the edges ride the existing collectors and correlate sweep.

Cites ADR 048 (graphschema registry), 026 (Ladybug disposable-projection model and the
`SchemaVersion` gate), 053 (adjudicator, reserved for slice 3), 044 (reach gating —
`grants_admin` is a reach-eligible edge under the same fail-open BFS invariant).

## Slice 2 (sub-slice 1): k8s-manifest ownership

Ships plain-YAML manifest ingest and a correlate rule joining declared k8s workloads to
the live k8s assets they define, the first drift-detection precondition from the phased
plan.

### What ships

- The GitHub collector parses plain (unrendered) `Deployment`/`StatefulSet`/`DaemonSet`/
  `Job`/`Service` manifests out of synced repos into a normalized `DeclaredK8sWorkload`
  shape, projected as `declared_k8s_workload` assets: metadata only (`manifest_key`,
  `live_type`, `namespace`, `repo`, `path`), never a live resource. The parser tolerates
  raw templated YAML (Helm/Kustomize placeholders) without panicking; it does not render
  it.
- `declared_k8s_workload` is a **correlation-only intermediate**: it is in
  `correlationTypes` (`internal/app/correlate/repo.go`, so the correlate sweep can
  read it) but also in `NeverSyncTypes`, so it is never synced into Ladybug as a node. Once the ownership edge is emitted the
  intermediate has no reason to be graph-traversable.
- **Why a correlate rule, not the collector:** live k8s asset IDs are
  `<cluster>/<kind>/<namespace>/<name>` but a manifest never names the cluster it will
  be applied to. Only the correlate sweep, which sees the full live inventory, can
  resolve which cluster(s) a manifest maps to. The `K8sManifestOwnership` rule
  (`internal/app/correlate/k8s_manifest_ownership.go`) joins on the cluster-agnostic
  suffix `<kind>/<namespace>/<name>` (falling back to `<kind>/<name>` when a manifest
  omits `namespace`), with a defensive type check (`live_type` must match) so a
  `Service` manifest can never join a `Deployment` sharing namespace/name.
- **Confidence model:** `high` when the suffix resolves to exactly one live asset in one
  cluster; `medium` when it resolves to more than one cluster or the namespace-agnostic
  fallback was used. Every emitted edge also carries `provenance=iac_manifest` and the
  manifest's file `path`, so triage can jump from a live asset to the declaring file.
- The rule emits the existing `defined_in` edge type (`EdgeDefinedIn`; no new edge type)
  from the **live asset** to the `github_repo` it is declared in:
  `(live asset)-[:defined_in]->(repo)`. It is a separate, higher-confidence, file-anchored
  edge from `DeploysTo` (repo → workload, the CI-lineage heuristic in `deploys.go`).
  Both coexist and answer different questions ("what deployed this" vs. "what declares
  this exact object").

### New rel tables (same `defined_in` edge_type, routed by source node label)

`defined_in` sources are not uniformly typed: live k8s workloads are
`K8sWorkload`-labelled nodes, while `k8s_service` (and other IaC-declared assets) are plain
`Asset`-labelled nodes. One rel table would silently drop a class of source at Ladybug's
`MATCH` node-label filter, so the edge_type routes to a Ladybug rel table by the source
asset's node label, the same pattern used for `ExecutesAs` / `ExecutesAsK8sWorkload` and
`DeploysTo`/`DeploysToService`:

| Rel table | From → To | Source assets |
|---|---|---|
| `DefinedInK8sWorkload` | `K8sWorkload → Repo` | live `k8s_deployment`/`k8s_statefulset`/`k8s_daemonset`/`k8s_job` |
| `DefinedInAsset` (the default) | `Asset → Repo` | `k8s_service`; other IaC-declared assets |
| `DefinedInIamRole` | `IamRole → Repo` | `iam_role` |

`DefinedInIamRole` came later: `iam_role` assets are `IamRole`-labelled, so a
role's `defined_in` edge would drop at the `DefinedInAsset` label filter. A dedicated table
keeps the routing explicit and lets Cypher query role ownership directly. Terraform-state
(ADR 065) and identifier-harvest (ADR 070) ownership route roles through it.

`DefinedInK8sWorkload` and `DefinedInAsset` carry `confidence`, `provenance`, and `path` as
rel properties; `DefinedInIamRole` carries `confidence` and `provenance`
(`internal/app/graphstore/schema.go`); routing lives in
`internal/app/graphstore/repo.go` (source node label → rel table at load time,
`copy_load.go` for the property mapping). `defined_in` remains **one edge type** in the
`internal/graphschema` registry (ADR 048).

### SchemaVersion

`SchemaVersion` bumps for the new `DefinedInK8sWorkload`/`DefinedInAsset` DDL,
per the rule that any Ladybug DDL or loading-set change forces a rebuild from ClickHouse.

### Later sub-slices

- Templated manifests (Helm charts, Kustomize overlays) are not rendered; only plain
  manifests join.
- **SA-annotation → cloud-identity correlation** is not wired into
  `FederatedAccess`/`ExecutesAsK8sWorkload` by this slice; the manifest join covers
  workload *ownership* only, not the identity a workload runs as.
- Live-vs-declared drift diffing is not implemented; this slice only adds the join.

## Amendment (2026-07-18): SchemaVersion bookkeeping

Two loading-set changes, each with its own `SchemaVersion` bump, had no ADR record:

- The SSO edge types were added to `securityEdgeTypes` so their
  endpoint nodes are retained in Ladybug; without it the slice 1 subgraph dropped before
  load.
- `k8s_service_account` mapped into `assetTypeToNode`
  (→ `NodeK8sWorkload`) so IRSA/GKE-Workload-Identity `executes_as` edges route to the
  typed `ExecutesAsK8sWorkload` rel instead of the generic `Asset→IamRole` table
  (affects reachability / must-fix).

## Amendment (2026-07-31): Okta group nodes and MFA evidence

The Okta collector emitted `member_of` edges to `okta:group:<id>` while
nothing created that node, so every membership edge dangled. Group nodes are now
emitted. Joining an Okta group to its `sso_group` node by name (so
`human → group → permission set → account` resolves) needs `member_of` synced into Ladybug
and a `SchemaVersion` bump; it is not done here (`member_of` remains `TierUnsynced`).

Also corrected: the Okta collector derived `mfa_enabled` from
`credentials.provider.type != "OKTA"`, which is the password provider and carries no
factor-enrollment information. `enrich.IdentityHygiene` treats
`mfa_enabled=="false"` as a scoring claim, so the value asserted something the API never
supported. The key is now omitted (unknown, which the consumer treats as "no claim") and
`credential_provider` records what the response actually says. Real enrollment needs
`GET /api/v1/users/{id}/factors`, one call per user, not yet wired.

## Amendment (2026-07-31, 2): the Identity Center API emits the graph

Until this amendment `collectIdentityCenter` collected permission sets, account grants and
group assignments but returned assets with no edges, so slice 1's edge types had no producer
and the authoritative source of who-can-reach-what contributed no topology. The collector now
emits, from data it already fetched:

- `grants_access_to` (permission set → `aws:<account>`)
- `grants_admin` for admin permission sets
- `assigned_to` (`sso_group:<name>` → permission set)
- `sso_group` nodes

Group nodes are keyed `sso_group:<name>` (the display name, not the GUID), which is the join
point for an identity provider whose groups are pushed to Identity Center by SCIM.

Only GROUP assignees produce edges: `AssignedTo` is `SSOGroup→SSOPermSet`, and a user
assignment has no node type yet.
