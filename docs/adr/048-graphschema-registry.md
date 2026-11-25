# ADR 048 — internal/graphschema: single source of truth for the edge pipeline

**Status:** accepted (implemented 2026-07-10) · amended 2026-07-27 (node-label gate; "healthy" vs "returns anything")

## Context

The graph edge pipeline has five layers: producers write snake_case `edge_type`
rows to ClickHouse `graph_edges` → `asset.SyncEdgeTypes` (two fetch tiers)
selects what the Ladybug rebuild reads → `graphstore.edgeTypeToRel` maps types to
PascalCase rel tables → `edgeUnwindQ`/`schemaDDL` define the tables →
`ladybugRelSpec` gates what is actually loaded (traversable). On top of that,
five more surfaces referenced edge/rel names by hand: `neighborRels` (expand),
`reachEdgeTypes` (ADR 044 internet_hops), `edgeWeight` (BFS), both NL prompts
in `internal/reason`, and frontend preset Cypher strings.

Tests locked the middle layers together, but the final gate and the query
surfaces were not pinned to anything. This allows a family of silent failures
that share one shape: a query referencing a rel that exists in the DDL but is
never loaded returns zero rows with no error. Examples of the drift this
permits:

- a UI tab querying an unloaded rel (`ContainsData`, addressed in ADR 047)
  renders empty;
- an NL prompt advertises a rel (`RunsIn`) that is never populated;
- `neighborRels` traverses a rel (`PeeredWith`) that the loader drops;
- frontend Cypher matches a rel against the wrong endpoint label
  (`(a:Asset)-[:FederatedAccess]->`, where `FederatedAccess` is Repo→IamRole);
- `edgeWeight` switches on PascalCase names against snake_case data, so every
  BFS weight collapses to the 0.5 default;
- edge types (`owns`/`has_policy`/`allows_action`) are fetched uncapped from
  ClickHouse and then discarded at the untested `ladybugRelSpec` gate.

## Decision

One dependency-free leaf package, `internal/graphschema` (same layering
precedent as `internal/graphquery`), declares the whole pipeline:

- `EdgeTypes []EdgeType` — every snake_case `edge_type` any producer writes:
  its rel table, fetch tier (`critical`/`bulk`/`unsynced`), reach flag
  (ADR 044), BFS weight, and doc line.
- `Rels []Rel` — every rel table: typed endpoints, `Loaded` (in
  `ladybugRelSpec`), `Expand` (in `neighborRels`), and — mandatory when a synced
  type feeds an unloaded rel — a `DropReason`. A dropped rel is therefore a
  declared, tested decision rather than a silent one.

All consumers derive at init: `asset` (tier lists), `graphstore`
(`edgeTypeToRel`, `ladybugRelSpec` endpoints, `neighborRels`, `reachEdgeTypes`;
prop columns stay local in `ladybugRelProps`, pinned to the DDL by test),
`reason` (prompt edge blocks), `explore` (Pascal↔snake translation for the
ClickHouse fallback), and the frontend via a generated, committed artifact
`frontend/src/generated/graph-schema.json` (`go run ./cmd/graphschema-gen`).

Enforcement:

- `TestRegistryConsistency` — the gate: synced+mapped+unloaded ⇒ `DropReason`
  required; loaded ⇒ must be fed; weights bounded; docs mandatory.
- `TestRegistryDerivationsMatchLegacy` — pins derived sets so a registry edit
  that changes graph behavior is a conscious diff in one reviewable place.
- `TestLadybugRelSpecMatchesDDL` — every loaded rel's endpoints and prop columns
  match its `CREATE REL TABLE`.
- `TestExportJSONIsFresh` — the committed frontend artifact matches the
  registry.
- `graphSchemaPin.test.ts` (vitest) — extracts every `[:Rel]` token from
  frontend Cypher template literals and asserts it is loaded.

## Consequences

- Adding an edge type or changing what Ladybug loads is a one-file registry edit
  plus conscious pin updates; the derived surfaces cannot drift individually.
- Node-conditional reroutes (`runs_in`+package→`RunsIn`, `deploys_to`+non-k8s→
  `DeploysToService`, `executes_as`+k8s→`ExecutesAsK8sWorkload`) remain code in
  `buildEdgeRows`; the registry documents them and the consistency test treats
  those rels as fed.
- `SchemaVersion` semantics are unchanged: bump it whenever a registry edit
  changes the loaded set or DDL, exactly as before.
- Follow-ups building on the registry: derive the NL prompt blocks and the
  ClickHouse-fallback name translation (drift class fixed structurally), and
  per-type bulk caps declared next to the tier.

## Amendment 2026-07-27 — the node-label gate, and "healthy" vs "returns anything"

The original decision closed the rel-level gate. Two adjacent gaps with the same
failure shape remained.

**1. The node-label gate.** A rel table declares typed endpoints, and the
loader's insert does `MATCH (s:Asset {id: r.src})`. `assetTypeToNode` promotes
some asset types onto their own label; when a producer emits an edge whose
endpoint type has been promoted off the label its rel expects, the engine discards the
row with no error, warning, or metric. The registry can be fully consistent and
the edge still never arrive. `TestProducerEdgeLabelsMatchRelTables` now checks
producer edge endpoint types against rel-table labels.

A `SchemaVersion` bump removes the root cause for most known mismatches by deleting
the `EC2Instance` and `SecurityGroup` labels: their column lists were identical
to Asset's and discriminated nothing `Asset.type` does not. Edges such as
`has_role` (a `Reach` edge, so "compromised EC2 → the role it runs as"),
`protected_by`, `in_vpc`, and `connected_via_sg` are affected by this class of
mismatch. `knownBrokenProducers` is empty and must stay empty. Promoting a type
onto its own label is a load-time hazard, justified only by columns Asset lacks.

**2. `healthy` meant "did not error".** `GET /api/graph/queries/health` probed
every named query and reported health from `err == nil`, so a query whose rel
table is empty — parses, runs, returns nothing — was indistinguishable from a
working one (this also hid the empty `CanEscalateTo` rel described in the ADR 026
amendment of the same date). The endpoint now reports `empty` separately, and
`probed: false` (and `healthy: false`) for the parameterised entries it cannot
measure, so an unmeasured entry never reads as a pass (ADR 095 removed the UDF-backed queries). Zero rows is a finding, not a
pass — the same principle as the `DropReason` gate.
