# ADR 011 — MCP server in the binary; A2A deferred

**Status:** accepted (write-tool/RPC details superseded by ADR 015; A2A stays unimplemented; external agents use API keys — see note)

> **Superseded in part by ADR 015.** Three specifics below changed during implementation:
> there is **no ConnectRPC API** (the programmatic surface is plain REST + JSON plus the
> MCP seam), and MCP writes are **session-role-gated, not OPA-gated** (the policy gate of
> ADR 006 governs the autonomous decision pipeline, not the operator MCP seam). `suppress_finding`
> shipped; `trigger_scan` is deferred (`POST /api/scans` already covers it). The Explore tools
> shipped as `graph_query` (natural language to graph) and `run_cypher` (read-only Cypher,
> validated by `graphquery.IsReadOnly`), not `translate_graph_query`/`run_graph_query`.
>
> **The A2A (Agent2Agent) protocol is not implemented.** External agents authenticate with
> `Authorization: Bearer gph_<key>` (keys minted in Settings → API Keys, verified in
> `auth.RequireAuth` via `apikey.Service.Verify`, scoped read/write/admin) and use the *same*
> REST + MCP endpoints a human session does, with a key instead of a cookie. Other ADRs that
> say "A2A agent" or "A2A client" mean such a key-authenticated agent, not the protocol.

## Context

The system needs a programmatic seam: an external vulnerability manager queries Vulngraph for
asset context and blast radius, and operators want to talk to their security graph from
an AI assistant. Large MCP/A2A surfaces with many tools and skills, aimed at external
multi-tenant orchestrators, were considered unnecessary for a single-tenant deployment.

## Decision

An `internal/app/mcp/` domain served by the same binary (streamable HTTP on the existing
server, same session/token auth). Slim toolset: asset/finding/scan/compliance reads,
`get_asset_context` (asset + posture + blast radius — the vulnerability-manager seam),
`translate_graph_query`/`run_graph_query` (Explore over MCP), and OPA-gated writes
(`trigger_scan`, `suppress_finding`).

**A2A is not implemented, by choice:** its main use case is external multi-tenant
orchestrators; every consumer here is served by MCP tools or the REST API. An A2A layer
would sit over the same services additively.

## Consequences

- One auth model and one deployment for human UI, RPC, and machine access.
- The vulnerability-manager integration needs no Vulngraph-side lifecycle code: Vulngraph supplies
  context, the vulnerability manager owns SLA/tickets/fix-PRs.
