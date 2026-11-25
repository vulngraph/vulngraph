# ADR 040 — Operator authentication, authorization, and SSO

**Status:** accepted. Okta OIDC sign-in implemented 2026-07-06 (`internal/app/auth/okta.go`,
routes `/api/auth/okta[/callback]`, env `OKTA_CLIENT_ID`/`OKTA_CLIENT_SECRET`/`OKTA_DOMAIN`).
Per-team RBAC data scoping is not built.

## Context

The operator (human + agent) auth model had never been written down, even though several
mechanisms exist in code. The pieces:

- **Session auth** — email/password sessions (`internal/app/auth`), plus Google OAuth and an
  oauth2-proxy path. `X-Auth-Request-Email` from oauth2-proxy is trusted only when it is backed
  by the IdP-signed ID token (`OAUTH2_PROXY_OIDC_ISSUER` + `_AUDIENCE`) or a shared secret
  (`OAUTH2_PROXY_SHARED_SECRET`); `serve` refuses `OAUTH2_PROXY=true` with neither
  (`cmd/graph/serve_auth.go`, docs/security-hardening.md).
- **`BYPASS_AUTH=true`** — serves every request as a synthetic admin. Intended only behind a
  network-level auth gate (ZTNA/oauth2-proxy); it logs a loud startup warning because, on an
  internet-reachable deploy, it would leave the platform unauthenticated. The synthetic admin
  identifies no person, so the executor refuses every state-changing run under it
  (`executor.ErrBypassAuth`, 403) and audit rows written under it name `admin@internal`.
- **Roles** — `admin` / `analyst` / `viewer`, enforced on write handlers via `auth.RequireRole`
  and re-checked in the MCP write tools by session role (ADR 015).
- **A2A / agents** — external agents authenticate with `Authorization: Bearer gph_<key>` (scopes
  `read`/`write`/`admin`), the same REST + MCP surface a human uses (ADR 011/015). Executor
  actions, respond decisions, suppressions and MCP/chat live cloud reads (`mcp.live_read` /
  `chat.live_read`) are written to `audit_events`. Other writes (connectors, API keys, users and
  roles, saved queries, notify channels) and ordinary read calls leave no `audit_events` row; they
  get only OpenTelemetry request spans, when OTLP export is configured.

What was missing: a single enterprise SSO story. Google-only sign-in blocks organizations
standardized on Okta/Entra, and there is no per-action-beyond-role or per-team data scoping.

## Decision

Record the model above as the baseline, and adopt **Okta (OIDC) as the first enterprise SSO
integration** — a standard OIDC authorization-code flow that maps Okta claims (email, groups) onto
the existing role model, sitting alongside (not replacing) Google OAuth and oauth2-proxy. SSO is a
configuration choice per deployment, not a hard dependency.

Guard rails that stand regardless of the identity source:

- Roles remain the authorization primitive; SSO only decides *who* the caller is, not *what* they
  may do. Write handlers stay `RequireRole`-gated with a `TestXxx_NonAdmin_403`.
- `BYPASS_AUTH` keeps its loud `SECURITY:` startup warning log line (no audit row is written) and
  never runs a cloud change; it is a break-glass/dev affordance, never a
  production auth strategy.
- Agent keys (`gph_`) are unchanged — SSO is for humans; agents use scoped keys.

## Consequences

- Deployments can front the platform with Okta without an oauth2-proxy sidecar.
- **Amendment 2026-07-06:** the Okta OIDC handler + group→role mapping shipped
  (`internal/app/auth/okta.go`, routes `/api/auth/okta[/callback]`). **Not built:**
  granular per-action permissions and per-team asset/finding data scoping (a larger RBAC effort).
- The auth chain is documented in one place, so future changes have a decision record to
  amend rather than reverse-engineering the middleware.

Cites ADR 015 (MCP write-tool role self-check), 011 (A2A scoped keys), 016 (cloud-side OIDC — a
different concern: how the platform authenticates to clouds, not how operators authenticate to it).
