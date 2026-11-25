# Contributing

Thanks for helping. This page is the human-facing summary of how the project
works; the detailed engineering rules are in [`CLAUDE.md`](CLAUDE.md) (also
available as `AGENTS.md`), which is also read by AI coding assistants. Read
the relevant section there before touching layering, ClickHouse, LadybugDB or
the job system.

Vulngraph was developed with AI coding assistants working under those same
rules and the same CI gates (lint, unit, guard-mutation, integration and Helm
jobs in [`.github/workflows/ci.yaml`](.github/workflows/ci.yaml)).
Contributions written with an assistant are welcome on the same terms: you are
responsible for the change, and it is reviewed like any other.

The public git history starts at the first public commit; earlier history is
not published. The ADRs in [`docs/adr/`](docs/adr/README.md) are the record of
why things are the way they are.

## Before you start

- **Open an issue first** for anything beyond a small fix, describing the
  problem and the shape of the change, so you don't build something the
  project won't take.
- **Larger changes start with an ADR or a spec.** A new feature, connector or
  graph capability, or a change to the data model, API contract or a
  cross-cutting convention, gets a short write-up before the implementation
  PR: an ADR in [`docs/adr/`](docs/adr/README.md) for a durable decision, or a
  spec from [`docs/specs/TEMPLATE.md`](docs/specs/TEMPLATE.md) when the design
  needs working out. Bug fixes, small refactors and dependency bumps don't.
- **Small, focused PRs.** One logical change per PR.

## Engineering standards in brief

The full rules, with the reasons behind them, are in `CLAUDE.md`, whose
"What enforces these rules" section says which are linted, which are tested
and which rest on review. The maintainer reviews outside pull requests; while
there is one maintainer, nobody else reviews the maintainer's own changes
([`GOVERNANCE.md`](GOVERNANCE.md)). The rules reviewers check most often:

- **Layering.** Each domain in `internal/app/<name>/` starts as `domain.go`
  (pure types and sentinel errors), `repo.go` (storage), `service.go`
  (business logic over interfaces it defines) and `handler.go` (transport
  only). golangci-lint blocks storage and driver imports in `domain.go`, in
  handler files, and in `service.go` / `service_*.go`; other files are not
  checked, and some existing ones (for example in `asset/` and `finding/`)
  query storage directly. Put new queries in repo files. If the lint blocks
  you, change the design rather than the lint config.
- **Errors.** Wrap with context (`fmt.Errorf("GetAsset: %w", err)`) wherever
  an error crosses a package or domain boundary. Review checks this, not a
  linter, and older code still has bare `return err` lines. HTTP errors go
  through `pkg/errs` (RFC 9457), never `http.Error`.
- **Unknown is not zero.** Missing data must surface as unknown or as an
  error, never as a clean zero value that reads like a measurement.
- **No autonomous remediation.** Only read-only `observe` actions run without
  a person (ADR 087). Don't add a path that changes cloud state without an
  explicit human approval.
- **API changes** update the matching `openapi/domains/*.yaml` file in the
  same commit; write routes are role-gated in the router (a route test fails
  on an ungated one).
- **Tests land in the same commit** as the code they cover.
- **Hygiene.** No commented-out code, placeholder stubs or speculative
  abstractions (checked in review). Go files stay at or under 800 lines
  (tests and generated code exempt; revive enforces it, and three legacy files
  are grandfathered in `.golangci.yml`). Frontend files have no length limit.

## Prerequisites

- **Platform** -- Linux or macOS, on x86_64 or arm64: those are the four
  builds of the graph engine library `scripts/fetch-ladybug.sh` fetches. On
  Windows, work inside WSL2 and follow the Linux steps.
- **C toolchain** -- the binary links the engine through cgo. Linux: gcc
  (Debian/Ubuntu: `build-essential`), plus OpenSSL 3 to link and run (`libssl3t64`
  on Debian 13 and Ubuntu 24.04, `libssl3` on older releases). macOS: the Xcode
  Command Line Tools (`xcode-select --install`) and `brew install openssl@3`.
  The macOS library loads OpenSSL from Homebrew's default prefix,
  `/opt/homebrew` on Apple silicon and `/usr/local` on Intel, and the fetch
  script warns when a path the library records is missing. With OpenSSL 3
  anywhere else, create each path the warning lists as a symlink to its copy
  there. Exporting `DYLD_FALLBACK_LIBRARY_PATH=<its lib directory>` works only
  when `go` is not started through a script such as an asdf shim: macOS strips
  `DYLD_*` variables when it runs `/usr/bin/env` or `/bin/bash`.
- **Go** -- the version pinned in [`.tool-versions`](.tool-versions)
  (`asdf install` / `mise install` picks it up).
- **bun** -- for the frontend (also pinned in `.tool-versions`).
- **Docker** (with Compose) -- runs Postgres and ClickHouse locally.
- **golangci-lint** -- version pinned in `.tool-versions`; required, since
  some layering rules (the storage-import bans and SDK quarantines) are
  enforced through it.
- *Optional:* an LLM API key (e.g. `ANTHROPIC_API_KEY`). LLM features are
  optional; the platform works without a key.

## Dev setup

Every `go run` / `go build` links the embedded graph engine,
[LadybugDB](https://github.com/LadybugDB/ladybug) (`liblbug`), which is
downloaded, not committed. Fetch it once after cloning, before anything else
(and again when the pinned version in the script changes):

```sh
brew install openssl@3        # macOS only: the release links OpenSSL 3 (see Prerequisites)
scripts/fetch-ladybug.sh      # pinned release, sha256-verified, ~seconds
```

Then start the datastores (`docker compose up -d`) and the rest:

```sh
docker compose up -d                                  # Postgres + ClickHouse
cp .env.example .env                                  # then set GRAPH_SECRET_KEY and LADYBUG_RPC_SECRET
set -a; . ./.env; set +a                              # export it (repeat in each new shell)
go run ./cmd/graph migrate
go run ./cmd/graph user create --email you@example.com --role admin  # prints a generated password
cd frontend && bun install && bun run build && cd ..
go run ./cmd/graph serve                              # keeps running
```

and, in a second terminal:

```sh
set -a; . ./.env; set +a
go run ./cmd/graph worker
```

`.env.example` explains how to generate both secrets and turns on the graph
engine (`LADYBUG_*`); without those variables the worker opens no graph, serve
has no Cypher, and both log a startup warning saying so. Every variable is
documented in [`docs/configuration.md`](docs/configuration.md).

`docker compose -f deploy/docker-compose/docker-compose.yml up` needs none of
this — the image fetches its own copy.

### Frontend development

`bun run build` bakes the UI into the binary, so a UI change otherwise means a
rebuild and a `graph serve` restart. For hot reload, keep `go run ./cmd/graph
serve` running on :8080 and, in another terminal:

```sh
cd frontend && bun install && bun run dev   # http://localhost:5173
```

Vite serves the UI and proxies `/api` to the local server on :8080, so you
sign in with the same account. [`frontend/.env.example`](frontend/.env.example)
covers pointing the proxy at another backend.

## Before opening a PR

```sh
go vet ./...
golangci-lint run                     # layering + standards enforced, not advisory
go test ./...                         # skips the nested ladybug module:
(cd internal/graphdb/ladybug && go test ./...)  # the cgo binding, its own Go module
go run ./cmd/graph migrate && go test -tags=integration -p 1 -count=1 ./...  # needs docker compose up
cd frontend && bun run lint && bun run test && bun run build  # typecheck, vitest, bundle
```

The integration tests run one package at a time (`-p 1`), as CI does: they all
share the one compose ClickHouse, and the default cross-package parallelism can
fail unrelated packages with dropped connections.

Some files are generated and committed, and CI fails when one is out of date.
If you touch what a file is derived from, regenerate it and commit the result:

| Generated file | Derived from | Regenerate with |
|---|---|---|
| `frontend/src/generated/graph-schema.json` | `internal/graphschema` registry | `go run ./cmd/graphschema-gen` |
| `frontend/src/generated/score-bands.json` | enrich score-band thresholds | `go run ./cmd/scoreband-gen` |
| `docs/cspm-coverage.md` | benchmark matrices and framework mappings in `internal/checks` | `go run ./cmd/cspm-coverage` |
| `internal/checks/required_keys_gen.go` | the checks' `Violates` predicates | `go run ./cmd/checkkeys-gen` |
| `frontend/src/lib/api.gen.ts` | `openapi/` | `cd frontend && bun run gen:api` |

`lefthook.yml` runs `golangci-lint run` and `go test ./...` on pre-commit
(`lefthook install` once, locally); run `go vet`, the integration tests and the
frontend build yourself.

## Finding something to work on

Look for issues labelled
[`good first issue`](../../issues?q=is%3Aopen+label%3A%22good+first+issue%22)
(small, well-scoped) or
[`help wanted`](../../issues?q=is%3Aopen+label%3A%22help+wanted%22). Comment on
the issue before starting so work isn't duplicated. See
[`.github/LABELS.md`](.github/LABELS.md) for the label set.

## Reporting bugs / requesting features

Open a GitHub issue. Include repro steps for a bug; for a feature, the
problem you're trying to solve (not just the API you imagine).

## Security issues

Do not open a public issue for a security vulnerability — see
[`SECURITY.md`](SECURITY.md).

## Developer Certificate of Origin (DCO)

Sign off each commit under the
[Developer Certificate of Origin](https://developercertificate.org/): by
adding a `Signed-off-by` trailer you certify that you wrote the change, or
otherwise have the right to submit it under this project's Apache-2.0 license. Add
it with `-s`:

```sh
git commit -s -m "asset: fix drift on renamed buckets"
```

which appends `Signed-off-by: Your Name <you@example.com>` using your git
`user.name` and `user.email`. To sign off commits you already made on a
branch, run `git rebase --signoff main`. Maintainers check for the trailer in
review; CI does not check it. There is no CLA.
