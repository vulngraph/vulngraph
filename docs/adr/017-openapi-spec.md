# ADR 017 — OpenAPI spec as the API contract, kept honest by a contract test

**Status:** accepted · amended 2026-07 (route-coverage test)

## Context

The frontend's types lived in `frontend/src/lib/api.ts`, hand-maintained to "mirror the REST
JSON shapes." Nothing tied them to the Go `*Response` structs, so they drifted. Auditing the
two against each other turned up three mismatches the compiler could never have caught:

- `Connector.type` was missing `kubernetes` (the backend accepts it; `connector/domain.go`).
- `ComplianceCoverage` omitted `check_ids` (the wire emits it via `compliance.Control`).
- `Decision` omitted `target_type` (present on `decisionResponse`).

We want the frontend to be typed *from* the API, and we want a change to a Go response shape
to fail loudly rather than silently invalidate a TS type. Two options were ruled out:

- **Proto-first ConnectRPC.** `.proto` as the source, both Go and TS generated from it, zero
  drift. But Vulngraph chose plain REST + JSON and explicitly rejected proto/gRPC/ConnectRPC
  (ADR 015). Adopting the proto toolchain here would reverse that.
- **Generate the spec from Go.** Code-first OpenAPI in Go means either annotation comments on
  every handler (`swag`, which couples docs to comment syntax the linter cannot check) or a
  framework that owns the transport layer (`huma`), which would overturn the hand-rolled,
  linter-enforced handler layering of ADR 010.

We also evaluated `tygo` (Go structs → TS types). It only emits *exported* types, can't
express our literal-union enums (`severity`, `role`) — it coarsens them to `string` — and
covers only data types, not the endpoint contract. It would have *regressed* the type safety
we already had.

## Decision

A **hand-maintained OpenAPI spec under `openapi/` is the source of truth for the REST API**,
split one file per Go domain, and a **contract test keeps it honest**.

- **Spec is authored by hand, code-first in spirit.** When a handler's request/response shape
  changes, the spec changes in the *same commit* — exactly like the tests-with-code rule. The
  spec is not generated from Go (no annotations, no framework) and Go is not generated from the
  spec (handlers stay hand-rolled per ADR 010). They are kept in agreement by the test, below.
- **The frontend client is generated from the spec, never hand-written.** `openapi-typescript`
  emits types from `openapi/openapi.yaml`; the generated module is imported only through the
  `frontend/src/lib/api.ts` barrel. Components never import generated types directly
  (`frontend/src/lib/apiBarrel.test.ts` fails when any other source file names the module
  path in a string literal, which covers static, side-effect and dynamic imports).
- **A contract test enforces spec ⇆ code — in two halves.** The integration server test
  (`//go:build integration`) validates real HTTP responses against the spec with
  `kin-openapi` (`openapi3filter`, external refs allowed so it loads the split files): a Go
  response that diverges from the spec fails CI. That covers response *shapes* for the routes
  it drives, but not route *existence* — a registered endpoint with no spec entry would never
  be exercised and would escape the check.
  `TestSpecCoversAllRoutes` (`internal/httpsrv/openapi_coverage_test.go`, plain unit test)
  closes that half: it parses every `mux.HandleFunc` registration out of `server.go` and fails
  if a route is neither in the spec nor in its explicit exemption list (each exemption carries
  a reason: MCP/webhooks are different protocols, OAuth redirects and JIT email links are
  browser flows, chat/refine are SSE streams). Together these are the mechanism that makes a
  hand-maintained spec safe — without them the spec would drift just like `api.ts` did.
- **Scope is the session-authed REST surface the SPA consumes.** The MCP seam
  (`POST /api/mcp`, JSON-RPC 2.0 — ADR 015) and the provider webhook
  (`POST /api/webhooks/github/{id}`, HMAC-authed, provider-facing) are deliberately **not** in
  the spec; they are different protocols with different consumers.

### Rules for keeping it clean

1. **One file per Go domain; a thin root index; reuse via `components`.** The layout is:
   - `openapi/openapi.yaml` — the index. Holds only cross-cutting pieces: metadata, security,
     the path → operation map (each path `$ref`s a domain file), and shared `components` (the
     `Problem`/`FieldViolation` schemas, the `IdPath` parameter, the reusable error responses,
     the security schemes). Keep it thin.
   - `openapi/domains/<domain>.yaml` — one file per `internal/app/<domain>`. Holds that domain's
     operations (under `components.pathItems`) and its schemas/enums (under `components.schemas`),
     self-contained. A handler change and its spec change touch matching files.

   This split is deliberate and up-front: a single multi-thousand-line spec is hostile to
   targeted edits (by humans or AI tooling) — the whole file must be loaded to change one
   endpoint, and unique-match edits get error-prone. Per-domain files stay small enough to
   read and edit in isolation.

   Mechanics: a domain's path items live under `components.pathItems` with operation-name keys
   (OpenAPI 3.1-native; avoids JSON-pointer escaping of URL paths). The root wires them with
   `$ref: './domains/<domain>.yaml#/components/pathItems/<op>'`. Within a domain file, local
   schemas use `#/components/schemas/X`; shared pieces use
   `'../openapi.yaml#/components/responses/X'`. No build/bundle step: `openapi-typescript` and
   `kin-openapi` (`IsExternalRefsAllowed`) both resolve the external refs natively. New domain ⇒
   new `openapi/domains/<name>.yaml` + its paths added to the root index.
2. **`enum` only for genuinely closed sets** (`Severity`, `Role`, `ScoreBand`, `ConnectorType`,
   `SyncStatus`, `ScanStatus`, `Direction`). Open-ended strings (`source`, `title`, `region`,
   `edge_type`, `action`) stay `type: string`. Don't invent constraints the code doesn't have.
3. **Terse prose.** One-line `summary` per operation; a `description` only where the behaviour
   isn't obvious from the path. No `example` blocks — they bloat the file and go stale silently.
4. **Document only what you serve; serve only what you document.** A new endpoint is not done
   until it has a path entry with an `operationId`, reuses a shared response, and the
   regenerated client + contract test cover it. The spec edit lands in the handler's commit.
5. **The spec describes the wire, not the domain.** Required vs optional tracks the Go `json`
   tags (`omitempty` / pointer ⇒ optional). It never exposes a field the `*Response` struct
   doesn't.
6. **Lint in CI, but own the ruleset.** `redocly lint` runs against the spec; `recommended`
   minus the style defaults we don't want (tag-description, info-license, info-contact)
   is pinned in `openapi/redocly.yaml`, so the linter flags real problems (unresolved refs,
   invalid schemas, undefined responses) — not missing prose.

## Consequences

- The three drifts above (and any future one) become a **CI failure, not a latent UI bug.**
- The frontend gains what `tygo` couldn't give it: literal-union enums, the full endpoint
  contract (paths, params, status codes), and typed request bodies — generated, not transcribed.
- The cost is a hand-maintained YAML file plus the discipline of editing it with each handler
  change. That discipline is affordable for a small team *because the contract test enforces
  it* — forget to update the spec and the build breaks.
- This keeps the benefits of a schema-first approach — a single source of truth, a generated
  frontend client, one import barrel, and one regeneration command — without the proto
  toolchain rejected in ADR 015.
- `huma` and `tygo` are recorded here as rejected so the question isn't reopened from scratch:
  `huma` reverses ADR 010; `tygo` regresses enum precision and ignores the endpoint contract.

## Amendment (2026-07) — route-coverage test

The response-shape contract test alone did not detect endpoints missing from the spec.
`TestSpecCoversAllRoutes` was added so route existence is enforced as well as response shape.
