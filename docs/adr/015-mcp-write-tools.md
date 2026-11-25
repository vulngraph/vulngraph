# ADR 015 — MCP write tools: session-role-gated, no ConnectRPC

**Status:** accepted (revises ADR 011)

The policy gate this ADR calls OPA (ADR 006) is now the Go function `policy.Decide`; OPA is no longer a dependency.

## Context

ADR 011 sketched the MCP seam with "OPA-gated writes (`trigger_scan`, `suppress_finding`)"
and described the broader programmatic surface as a "ConnectRPC API." Neither survived the
build, and the gap had drifted into `CLAUDE.md` (a `## Proto-first` rule for `proto/` +
`buf generate` + `@/lib/rpc`, none of which exist). This ADR records what we actually built
so the docs and the code agree.

Two questions had to be answered to ship the first write tool (`suppress_finding`):

1. **What gates an MCP write?** OPA (ADR 006) governs the *autonomous* decision pipeline —
   whether the agent may act on a finding without a human. The MCP seam is the opposite:
   a human operator (or Claude acting on their behalf) issuing an explicit, authenticated
   command. Routing that through OPA would conflate two different trust models.
2. **Is there an RPC layer?** No. The API is REST + JSON; the MCP endpoint is JSON-RPC 2.0
   over the same HTTP server and session auth. There is no proto toolchain.

## Decision

- **MCP writes are session-role-gated, not OPA-gated.** The MCP endpoint is mounted behind
  `RequireAuth` but not `RequireRole` (it carries both read and write tools), so each write
  tool self-checks the role from `auth.UserFromContext`: a non-admin gets a JSON-RPC error
  (`codeForbidden = -32001`), and the service is never called. OPA stays scoped to the
  autonomous pipeline.
- **There are two write tools.** `suppress_finding` silences a
  finding (admin + a required reason) so it stops entering the decision pipeline. The actor
  is taken from the session, never the tool arguments. It shares the `suppress` domain with
  the REST routes (`POST`/`DELETE /api/findings/{id}/suppress`) — one service, two transports.
  `execute_action` (`internal/app/mcp/tools_cloud.go`, added later) runs cloud remediation
  actions. It also checks for an admin session, and a real run needs an `approval_token`
  minted by a different admin (`RequireGrant: true`); without a token only `dry_run` is
  accepted. See ADR 087.
- **`trigger_scan` is not built.** `POST /api/scans` (admin-gated REST) already covers
  on-demand scans; adding an MCP twin now would be duplication without a consumer. It would
  follow this same self-check pattern.
- **No ConnectRPC / proto.** The programmatic surface is REST + JSON plus the MCP seam.
  `CLAUDE.md`'s `## Proto-first` rule is replaced by `## HTTP API (REST + JSON)`.

## Consequences

- The operator trust model is uniform: the same session role gates a write whether it
  arrives over REST or MCP, and both paths carry a `NonAdmin_403` / non-admin-rejected test.
- New MCP write tools are cheap and consistent: implement the domain service, add a tool that
  self-checks admin, return `errForbidden` on failure. No new auth machinery.
- ADR 011's core decision (in-binary MCP server) is unchanged; only its write-gating and RPC
  specifics are superseded here. (The A2A protocol is still
  not implemented; agents use the same REST + MCP surface with API keys — see ADR 011's note.)
