# ADR 010 — Layering: the linter enforces the import bans, review enforces the rest

**Status:** accepted

## Context

The codebase follows strict layering (handler → service → repo → storage). Layering that
is only documented and checked in code review tends to erode over time: violations are
easy to introduce and are noticed late, if at all.

## Decision

These rules, and only these, are encoded in `.golangci.yml` and fail the commit (lefthook) and CI:

- `**/domain.go` may not import transport, storage, or database drivers (depguard).
- `**/handler.go`, `**/handler_*.go` and `**/*_handler.go` may not import `internal/db` or
  database drivers (depguard).
- `internal/app/*/service.go` and `service_*.go` may not import `internal/db` or database
  drivers (depguard).
- LLM provider SDKs may only be imported by `internal/llm` (depguard).
- `github.com/projectdiscovery/*` may only be imported by `internal/scanner/nuclei`
  (depguard — ADR 009).
- `http.DefaultClient` and `fmt.Print*` are banned (forbidigo).
- Files are capped at 800 lines (revive; tests and generated code exempt). A short
  grandfathered list in `.golangci.yml` is tracked debt: the linter does not stop those
  files growing, so growing one should prompt splitting it, and each entry is removed once
  its file drops under the cap.

Constructing an `http.Client` outside `pkg/safenet` is banned as well, but by a unit test
(`TestNoHTTPClientConstructedOutsideSafenet`), not the linter: forbidigo matches names, not
composite literals, so a pattern for the literal never fires and one for the type would flag
every `*http.Client` parameter.

If the linter blocks a change, the design is wrong — the config does not get loosened.

## Consequences

- Drift in the files the rules cover surfaces as a red build. Everything else is review's
  job: other files in a domain (for example `asset/drift.go`, `finding/risk.go`,
  `scan/profile_service.go`, 13 in all, listed in CLAUDE.md) import storage without a red
  build, and "services hold interfaces" and "domains call each other's services, never their
  repos" have no lint at all.
- The depguard rules are the machine-readable form of the layering section in
  [CLAUDE.md](../../CLAUDE.md); they evolve together or not at all.
