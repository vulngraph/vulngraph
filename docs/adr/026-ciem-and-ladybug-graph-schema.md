# ADR 026 — CIEM privilege escalation in the embedded Ladybug graph

**Status:** accepted · amended 2026-07-27 (cross-principal `CanEscalateTo` edges) · decision 5 withdrawn 2026-08-12 · decision 2 amended 2026-08-21

## Context

ADR 025 established that graph topology and reachability are first-class edges. The
graph engine (Ladybug, embedded in the worker pod) was wired to those topology edges, but
two categories of security-critical relationship were missing entirely:

**IAM privilege escalation (CIEM).** Inventory graphs commonly model IAM trust
policies as `CanAssume` edges (Vulngraph implements the same concept). What that does not
model is *permission-based* escalation: a role that holds `iam:AttachRolePolicy` can attach
admin access to itself or any other principal without going through a trust boundary. This
class of attack path — 66 documented techniques (28 AWS, 18 GCP, 20 Azure; see ADR 052) — was invisible
in the graph.

**Vulnerability risk propagation.** High-severity findings (nuclei, CSPM, KEV) were
stored as ClickHouse rows but had no influence on the graph. An internet-exposed EC2
instance running a vulnerable package had the same graph score as a clean one, so
blast-radius and attack-path queries did not weight by actual vulnerability.

Additionally, the original Ladybug schema had a latent correctness bug: `CanEscalateTo`
was declared `FROM Identity TO Identity`, but the `Identity` node table is never
populated — IAM principals are stored as `IamRole` nodes. Every CIEM-detected path
would have been silently dropped by Ladybug on insert.

## Decision

**1. CIEM detection runs inline with every connector sync.** After a sync writes assets
and edges to ClickHouse, `ciem.AnalyzeIAMAssets` runs as a pure function over the
collected IAM assets. It evaluates each principal's effective permissions (with AWS
policy boundary/SCP/deny logic, and a flat-permission shortcut for GCP service accounts
whose metadata format differs), detects all matching privesc paths, and bumps the
asset's `RiskScore` based on worst-case severity (critical→85, high→65, medium→45). The
bumped scores are re-ingested to ClickHouse so they are visible before the next Ladybug
sync.

**2. Risk propagates via BFS, not via self-loop edges.** An earlier design emitted a
`CanEscalateTo` self-loop to mark a principal as escalation-capable. Self-loops are
correctly stored but BFS ignores them (the center node is already in the visited set),
so they contributed zero risk propagation to adjacent assets. The correct model is a
score on the node itself: BFS then walks outward via `ExecutesAs`, `CanAssume`, and
`ConnectedViaSG` edges and attenuates (0.7 per hop, 4 hops max, 20-node budget). *(Edge
direction refined by the 2026-08-21 amendment.)*

**3. CanEscalateTo is `FROM IamRole TO IamRole`.** The `Identity` node type is reserved
for future human-identity connectors (Okta, Entra ID). Until then, all IAM principals
— roles, users, groups, GCP service accounts, Azure service principals — map to the
`IamRole` node table. `SchemaVersion` is bumped; the worker detects a mismatch at
startup and rebuilds the Ladybug graph from ClickHouse before accepting queries.

**4. Finding severity flows into graph scores post-correlate.** The `CorrelateWorker`
runs a `scoreAssetsFromFindings` step after the edge sweep and before the Ladybug rebuild.
It loads all critical and high findings, groups by ResourceID, and re-ingests the
affected assets with bumped scores. BFS then picks them up on the same rebuild cycle.
This keeps the finding pipeline decoupled from the graph pipeline while ensuring the
graph reflects actual vulnerability exposure.

**5. ~~`graph.nodes` ClickHouse table holds post-BFS risk scores.~~** *(Withdrawn
2026-08-12, see amendment.)* Ladybug is the traversal engine; `graph.nodes` was to be the
analytics persistence layer for post-BFS scores, letting ClickHouse queries join on node
risk without routing through the Ladybug RPC.

**6. `SharedSecurityGroup` emits edges between all asset pairs, not just EC2↔RDS.** *(Corrected
2026-10-26, see amendment: sharing a group is not itself a network path.)*
The original rule was scoped to one pair. Any two assets in the same security group have
a potential network path — Lambda↔RDS, ECS↔ElasticSearch, etc. The rule now emits a
`connected_via_sg` edge for every distinct pair sharing a group ID.

## Consequences

- Attack-path queries can traverse: internet exposure → `ExposedToInternet` →
  asset → `ExecutesAs` → `IamRole` → `CanEscalateTo` self-detected (score elevated) →
  `CanAssume` → admin role. The full escalation chain is graph-traversable.
- Risk scores on graph nodes are composite: CIEM privesc severity, finding severity, and
  BFS-propagated neighbor risk all contribute. An asset can be high-risk without having
  a direct finding if it is adjacent to a compromised or escalatable node.
- SchemaVersion bumps require a full Ladybug rebuild from ClickHouse on next deploy. The PVC
  holds a disposable cache; deleting it is safe.

## Not built

- **GCP / Azure policy evaluation.** AWS has full boundary/SCP/deny evaluation via
  `EvaluateEffectivePermissions`. GCP uses a flat-permission shortcut (no deny/boundary
  semantics for service accounts). Azure RBAC is collected (`internal/collect/azure/iam.go`)
  and evaluated per role assignment (`ciem/azure_rbac.go`, ADR 052 amendment 2026-07-30).
- **`Identity` node population.** The `Identity` table is declared in the Ladybug schema
  for human-identity connectors (Okta, Entra ID). `Owns` (Identity→Asset) and
  `UsesDevice` (Identity→Device) edges are live only once such a connector populates it.

Cites ADR 025 (topology and reachability this extends), ADR 013 (sync lifecycle),
ADR 010 (enforced layering — CIEM is a pure domain package, no infrastructure imports).

## Amendment (2026-07-27) — cross-principal `CanEscalateTo` edges (AWS)

Cross-principal `CanEscalateTo` edges had been deferred as needing "the IAM permission
graph correlated against the role inventory". That correlation already existed for triage
but was never read for the graph: `matchedResources` records the resource scopes each
required action was granted on, and for the principal-targeting actions
(`iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`,
`iam:PassRole`, `sts:AssumeRole`, the user- and group-targeting equivalents) those scopes
*are* the target principals. `resolveTargetPrincipals` (`ciem/privesc.go`) reads them into
`PrivescResult.TargetPrincipals`, and the sync writer emits one edge per concrete target.

Previously `TargetPrincipal` only ever held the `AnyPrincipal` sentinel or `""`, and the
edge writer skips both, so no usable `can_escalate_to` edges were produced and the CIEM
Cypher queries built on them (`ciem_escalation_paths`, `ciem_full_attack_chain`,
`ciem_vs_trust_comparison`) returned nothing. `/api/graph/queries/health` only checked that
a query did not error; it now reports emptiness separately.

Scope and limits:

- **AWS only.** `buildGCPPermissions` and `buildAzurePermissions` synthesise
  `EffectivePermission` with `Resource:"*"` — the GCP collector stores a flat
  comma-separated permission list and the Azure collector a flat action union, so neither
  carries per-binding resource scope and there is nothing to resolve a target from. GCP
  and Azure paths keep the sentinel until their collectors carry scope; that is now a
  collector gap with a named cause rather than a silently empty edge type.
- **Wildcard scopes are not resolved.** A grant on `*` means every principal, which is
  what `AnyPrincipal` already says; fabricating an edge per known role from it would
  invent topology the policy does not describe.
- **Targets outside the sweep's asset set are skipped and counted**, not written blind:
  an edge to an id that is not an asset is dropped at Ladybug load with no signal. Cross-account
  escalation targets are therefore still missing, and that is now a logged number.

## Amendment (2026-08-12) — decision 5 withdrawn: `graph.nodes` is deleted

Decision 5 was justified by two consumers: ClickHouse queries joining on node risk without
the Ladybug RPC, and a cheap graph-risk lookup for enrichment. **Neither was built.**
Enrichment reads `NodeSignals` through Ladybug plus the graphstore signal cache, and no
first-party SELECT — Go (including unqualified `FROM nodes`, since the ClickHouse client
defaults to the `graph` database), `frontend/src`, `openapi/`, the MCP seam, or the named
Cypher queries — reads the table. Meanwhile every rebuild re-upserted every node on the
rebuild's critical path, a large write volume with no reader.

The table also predated ADR 049's freshness discipline: an INSERT-only write path, no
delete path, and a 180-day TTL. When asset types were later removed from the Ladybug loading
set, their rows simply stayed, so the table accumulated orphans and could not even serve
reliably as an operator oracle for Ladybug/ClickHouse divergence. The supported replacement
for that purpose is the ADR 048/049 drift instrumentation
(`graph_ladybug_edges_loaded`/`_dropped`, `asset/drift.go`).

Deleted: `GraphNodeStore`, `GraphNode`, `CHGraphNodeStore`, `WithGraphNodeStore`,
`assetsToGraphNodes`, both `UpsertNodes` call sites, and `"nodes"` from
`asset.OptimizableTables` (the optimize job would otherwise FINAL-merge a table that no
longer exists). The table is gone from the schema. `TestNoGraphNodesWriter` is a source-level
guard, because an INSERT-only path with no reader breaks nothing when it drifts.

Decisions 1–4 and 6 are unaffected: risk is still a score on the node propagated by BFS,
and Ladybug remains the traversal engine. The post-BFS score now lives only where it is
read — in Ladybug — plus a `boosted` count on the rebuild log line.

## Amendment (2026-08-21) — decision 2 amended: BFS propagation is directed

Decision 2 said BFS "walks outward via `ExecutesAs`, `CanAssume`, and `ConnectedViaSG`
edges". The implementation indexed every edge in both directions
(`graphstore.buildAdjIndex`, to "treat the graph as undirected without double-querying"),
turning a query-cost optimisation into a statement about causation. Risk therefore flowed
against every directional edge: an internet-facing asset raised the account that owns it,
and a security group raised the hosts it merely permits ingress from.

The direction is now **declared per edge type** in the `graphschema` registry
(`EdgeType.Dir`, ADR 048's declare-once-derive-everywhere) and `buildAdjIndex` derives the
index from it. Three values:

- **forward** — a risky src raises dst (every exposure edge, the path by which an
  attacker arrives);
- **reverse** — the danger originates at dst (`exposed_to_internet`, `sg_allows_from`), dst
  is contents of src (`runs_image`/`runs_package`/`depends_on`), or dst is a capability of
  src (`accesses_secret`/`has_policy`/`allows_action`);
- **both** — `connected_via_sg` (member↔SG↔member lateral movement), `peered_with` (whose
  producer already emits the pair), `can_assume` and `can_escalate_to` (see below), and the
  fail-open answer for an edge type no registry entry covers.

**Decision 2 is narrowed, not reversed.** A workload no longer inherits the privilege risk
of the role it *runs as* (`executes_as`/`has_role` are forward: the role inherits the
exposure risk of the workloads holding its credentials). But a principal does still
inherit the privilege of what it can *assume, escalate to, or read*. Reachability and risk
score are different quantities: `reach.go` answers "can an attacker get here" and walks
edges src→dst; the score answers "how bad is it if this is compromised", which is blast
radius and runs against the direction of attack.

`can_assume` and `can_escalate_to` join `iam_role`→`iam_role`, so either single direction
discards half of a legitimately two-way signal (the source inherits the destination's
privilege; the destination inherits the source's exposure). Making these edges
all-forward or all-reverse would each demote a different set of high-scoring identities
below the score-60 band; `DirBoth` keeps both halves while still removing the spurious
boosts from other edge types.
`accesses_secret` joins different kinds and stays reverse: a secret inheriting its
reader's exposure adds nothing.

`capabilityReachTypes` in `graphschema_test.go` pins that a capability edge is never
`DirForward`, and leaves reverse-vs-both to the per-entry comment. Because `DirBoth` is
also the fail-open default, a deliberate `DirBoth` must justify itself in a comment on its
registry entry.

Directed adjacency is a strict subset of the undirected index, so a boost can only shrink
(except where the 20-node visit budget is freed for a genuine contributor further out).
Most scores move down at cutover; the removed boosts were largely saturated at the 30-point
cap and carried little discriminating information. Pinned by
`TestBFSRiskDoesNotFlowBackwards` and `TestBuildAdjIndexHonoursRegistryDirections`
(graphstore) and the `Dir` half of `TestRegistryConsistency` (graphschema). No
`SchemaVersion` or `SchemaDDLChecksum` bump: the adjacency index is built in memory from
the edge slice every sweep and is neither DDL nor part of the load set.

## Amendment (2026-10-26) — decision 6 corrected: sharing a security group is not a path

Decision 6 said any two assets in the same security group have a potential network path. In
AWS they do not: a security group admits a member's traffic only through an ingress rule that
names the member's group (the group itself, for a self-referencing rule) or a CIDR covering its
address. Only the default security group ships with a self-reference.

`connected_via_sg` stays the membership edge (asset → security group, spoke-hub). Reachability
is the allow rule between two memberships:
`(a)-[:ConnectedViaSG]->(s)`, `(t)-[:AllowsFrom]->(s)`, `(b)-[:ConnectedViaSG]->(t)` means `a`
reaches `b`. `SecurityGroupAllows` now emits a self-referencing rule as a self-loop
(`t = s`), which it used to drop. The named queries `lateral_movement_via_sg` and
`databases_reachable_from_internet`, the NL few-shot and the UI presets walk this shape;
`vpc_network_reachability` (a duplicate) and `sg_allows_internet_to_db` (which followed
`AllowsFrom` in the defender's direction and could not match) are removed, and the
one-direction movement queries no longer follow `AllowsFrom` outbound.

Blast radius and BFS risk still walk `connected_via_sg` both ways. For blast radius that is a
deliberate upper bound, since under-counting reach is the unsafe direction for a person
approving a change. CIDR-based rules are not modelled. No `SchemaVersion` bump: the DDL and the
loaded rel set are unchanged, and the load digest picks up the new self-loop rows.
