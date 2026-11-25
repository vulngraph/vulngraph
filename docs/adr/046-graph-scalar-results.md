# ADR 046 — Graph queries carry scalar/tabular results, not just graph shape

**Status:** accepted (implemented 2026-07-09)

## Context

The Explore graph query pipeline (Cypher endpoint, NL→Cypher, MCP `run_cypher`)
returned only graph shape: `Result{Nodes, Edges, Truncated}`. `execCypher`
(`internal/app/graphstore/repo_cypher.go`) mapped only `ladybug.Node` and
`ladybug.Relationship` columns from each row and **silently dropped every other
column**.

That made aggregate and bare-property queries appear to fail. The natural
question *"how many repositories deploy to public-facing assets?"* translates to
`RETURN count(DISTINCT r)` — a valid, read-only query the guard already permits,
which Ladybug runs correctly — but the scalar never left the backend, so the UI
rendered a blank graph. Every count / sum / avg / collect / `RETURN n.prop`
question (a common class of security questions) hit the same wall. The value
was there; the contract couldn't carry it.

## Decision

Extend the query result contract end-to-end to carry scalar/tabular rows
alongside graph shape.

1. **Domain type.** `explore.Result` gains `Columns []string` and
   `Rows []map[string]any`. `NonNil()` coalesces both to empty arrays so they
   marshal as `[]`, never `null`. A query populates one shape or the other:
   node/edge queries fill `Nodes`/`Edges`; aggregate/property queries fill
   `Rows`/`Columns`.

2. **Extraction.** `execCypher` adds a third per-row pass: any column that is
   neither a `ladybug.Node` nor a `ladybug.Relationship` is captured into a scalar row
   keyed by column name. Column order is the sorted union of scalar keys
   (deriving order from `GetColumnNames()` risks a SIGABRT on some Ladybug query
   shapes — see the existing `blastRadiusCount` notes).

3. **One return type through the chain.** `CypherRunner.RunCypher` and
   `graphstore.RunCypher`/`RunCypherBudget` now return `(explore.Result, error)`
   instead of the `([]Node, []Edge, bool, error)` 4-tuple — every implementation
   already built a `Result` internally. The worker↔serve RPC (`graphstore`
   `graphResponse`, `explore` `graphResp`) carries `columns`/`rows` across the
   wire.

4. **API + contract.** `GraphResult` and `NLResult` in
   `openapi/domains/explore.yaml` declare `columns`/`rows` as required arrays;
   the frontend client is regenerated from it. The integration server test
   validates real responses against the contract.

5. **NL prompt.** `cypherSystemPrompt` gains worked aggregate examples and a rule:
   "how many / count / total / average" questions use an aggregate with an `AS`
   alias and return a scalar, not whole nodes.

6. **Frontend.** Explore renders scalar rows in the Table view — a single value
   (one row, one column) as a big number, otherwise a generic columnar table —
   instead of the misleading "No results" empty state.

**Named queries are deliberately excluded.** `RunNamedQuery` still returns only
nodes/edges: named queries render as graphs, so they should return graph shape.
The scalar path is scoped to the ad-hoc Cypher / NL / MCP endpoints.

## Consequences

- Aggregate and property questions return a value instead of a blank graph, so
  the query surface answers counting and property questions, not only shape questions.
- The result contract is uniform: one `Result` type carries both shapes, one
  return signature through every `CypherRunner`, one JSON shape on the wire and in
  the OpenAPI contract.
- Read-only enforcement is unchanged — `graphquery.IsReadOnly` already allowed
  aggregate `RETURN`s; nothing about the write ceiling moved.
