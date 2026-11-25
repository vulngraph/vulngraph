# Vulngraph — Coding Standards

Vulngraph is a single-tenant, single-binary, self-hosted security platform: one Go binary
+ Postgres + ClickHouse + a React frontend served by the binary.

These are the engineering rules for every change to this repository, whoever writes it. The
file is also published as `AGENTS.md` so that AI coding assistants load the same rules; none
of them apply to assistants only.

The overriding rule: **code must stay maintainable by a small team.** Boring, obvious Go beats clever
Go. Tests land in the same commit as the code they cover — never later. If something needs
a comment to be followed, simplify it first; comment only constraints the code cannot express.

## What enforces these rules

- **golangci-lint** (`.golangci.yml`; lefthook at commit, and CI): the storage and driver
  bans in `domain.go`, handler files and `service.go`/`service_*.go`; the nuclei and LLM
  SDK quarantines; `http.DefaultClient` and `fmt.Print*` outside tests;
  the 800-line Go file limit; gofmt and goimports.
- **Tests** (the unit suite, which lefthook and CI run): the guards named in the sections
  below, among them `TestEveryWriteRouteIsGatedOrExempt`,
  `TestGraphEdgesReadersApplyFreshness`, `TestAssetReadersApplyLiveness`,
  `TestNoGraphNodesWriter`, `TestRegistryDerivationsMatchLegacy`, the ADR 087 gate tests,
  `TestNoUnrecoveredGoroutines`, `TestNoHTTPClientConstructedOutsideSafenet` and the
  `queueWorkerCounts` checks. The OpenAPI contract is checked by the integration server
  test, in CI. The guard-mutation CI job proves the guards catalogued in
  `internal/guardmutation` fail when their bug is put back.
- **Review only**: everything else, including services holding interfaces, cross-domain
  calls through service interfaces, error wrapping, `pkg/errs` and no `http.Error`, no
  `log.Fatal` outside `main`, the ClickHouse and Postgres query rules (beyond the few
  packages whose tests pin their own queries, such as the filtered-`FINAL` checks in
  `asset` and `alertctx`), goroutine fan-out bounds and `ctx` use, River enqueue
  placement, tests in the same commit, and hygiene.
  The maintainer reviews outside pull requests. While there is one maintainer
  (`GOVERNANCE.md`), nobody else reviews the maintainer's own changes, so for those these
  rules are checked by the author alone.

## Layering

A domain in `internal/app/<name>/` is built bottom-up, usually starting with these four files
(some are leaner, e.g. `mcp`, `webhook`):

```
domain.go    pure domain types and sentinel errors — no infrastructure imports at all
repo.go      storage adapters — where new storage code goes (repo.go, repo_*.go, *_repo.go);
             returns domain types, never sqlc/ClickHouse row types
service.go   all business logic; depends on small repository interfaces it defines itself
handler.go   transport only: parse request → call service → map domain error to status
```

- Services hold **interfaces**, never concrete repo types.
- Domains talk to each other through service interfaces, never each other's repos.
- The nuclei SDK is imported ONLY by `internal/scanner/nuclei`.
- golangci-lint (depguard/forbidigo/revive) enforces the storage and driver bans in
  `domain.go`, handler files and `service.go`/`service_*.go` (other files, such as
  `scan/profile_service.go`, are not checked), and the nuclei and LLM SDK quarantines, at
  commit and in CI.
  The interface and cross-domain rules are checked in review only. Known exceptions: 13 non-repo
  files query storage directly (`asset/{drift,optimize,purge,staleness}.go`,
  `finding/{age,clusters,quality,reenrich,risk,source_activity,summary,unenriched}.go`,
  `scan/profile_service.go`); do not add to them. If the linter blocks you, fix the design —
  do not loosen the config.

## Errors

- Sentinels in `domain.go`: `var ErrNotFound = errors.New("asset: not found")`.
- Wrap with context: `fmt.Errorf("GetAsset: %w", err)`. This is a review rule, not a lint
  (no wrapcheck in `.golangci.yml`), and existing code still has a few hundred bare
  `return err` lines (sqlc-generated code accounts for some). Always wrap where an error
  crosses a package or domain boundary, and do not add new bare returns there.
- Handlers map domain errors via `errors.Is` switches using `pkg/errs` (RFC 9457 responses).
- Never `http.Error`, never naked status codes.

## Degraded input

A recurring bug shape to guard against: *a function receives degraded input, logs a
warning, and returns a value indistinguishable from a good one.*

- **A zero value is not a measurement.** Before returning one on a failure path, ask what
  the consumer does with it. `blast_radius = 0` reads as "touches nothing", so a ClickHouse
  error on the blast walk would show a human a fix as safer than a successful walk would.
  Missing data (no inventory, no advisory source, unread route tables) must surface as
  unknown, never as clean. Prefer returning the error.
- **Vulngraph never remediates on its own (ADR 087).** Only read-only `observe` actions run
  without a person; every state-changing action is proposed with guidance and runs only
  after an explicit human approval. `policy.Decide` grants `AllowAuto` only on the
  `observe` class (`TestAutoExecuteGateRequiresKnownEvidence`,
  `TestGate_NoStateChangingInputIsAutonomous`), and `executor.ExecutionRequest` is built
  only by human-driven transports (`TestOnlyHumanTransportsBuildExecutionRequests`).
  `policy.Input` carries no evidence fields today; one added later must be paired with a
  `<Field>Known bool` whose zero value is the safe value, and
  `TestAutoExecuteGateRequiresKnownEvidence` fails until it is.
- **No generic `Result[T]` wrapper and no repo-wide "must return an error" lint.** Both
  were considered and neither holds up: a caller can have the flag in the type and publish anyway,
  and the lint needs a long tail of exemptions
  because an AST cannot see that a zero value means unknown. Fix consequential paths at
  the chokepoint their evidence flows through.

## Logging

`pkg/log` only: `log.FromContext(ctx)` (zerolog). No `fmt.Print*`, no `log.Fatal` outside `main`.

## Postgres

- sqlc for queries, goose for migrations (`migrations/postgres/`).
- `db.PGIn` for IN clauses — never hand-rolled placeholder strings.
- Check `rows.Err()` after every iteration loop.

## ClickHouse

- Query strings are package-level consts, named for what they fetch.
- Every table: `ReplacingMergeTree` + `TTL` (audit tables: plain MergeTree, 7-year TTL).
- Never `FINAL` on large tables — use `argMax(col, ver) … GROUP BY`. FINAL is tolerable
  ONLY for full-table reads (list/summary); any filtered lookup (`WHERE id = ?` / `IN`)
  MUST use the argMax form: skip indexes don't apply under FINAL
  (`use_skip_indexes_if_final` is off), so a filtered FINAL full-scans the table
  (on large tables like `findings` and `assets` that can saturate CPU). No lint checks this.
  Known exceptions still on filtered FINAL: `asset` List (`assetSelect` in
  `asset/repo.go`), the type-filtered reads in
  `identity/repo.go`, and explore's `seedByMatch` (`explore/repo.go`). The last two filter
  on `type` (the leading column of the `assets` sort key, so primary-key pruning still
  applies under FINAL) or, in `seedByMatch`, on `provider`; neither column has a skip index
  for FINAL to disable. Do not add new ones.
- Scan `count()`/`uniq()` into `uint64`, downcast explicitly.
- Per-query `context.WithTimeout`; concurrency semaphore lives in the client layer only.
  That semaphore bounds query COUNT, not bytes: N slots × a multi-GiB aggregation can exceed
  the server memory cap. Query shapes must be small enough that all N slots fit.
- **`LIMIT` bounds a result set, not an aggregation.** When the filters are post-aggregation
  (`HAVING` over `argMax`), CH builds state for every group in the table before anything
  prunes, so a paged read must select the page's ids with only the columns it filters and
  sorts on, then hydrate them by id (`finding.selectFindingKeysArgMax` → `ByIDs` — far lower peak memory
  per query). Cache ceilings (`mark_cache_size` et al.) are charged to the same tracker as
  queries and their upstream defaults ignore `max_server_memory_usage` — cap them in the chart.
- `db.CHIn` for IN clauses.

## Ladybug (graph engine)

ClickHouse is the source of truth; Ladybug is an in-memory traversal engine in the worker pod.
Every correlate sweep re-reads its load set from ClickHouse: the graph is rebuilt in full when
the load set's content digest changes (below), and otherwise its scores and signals are
refreshed in place. An optional PVC snapshot only speeds up a restart. Treat it as a
disposable projection — never store anything in Ladybug that ClickHouse can't reproduce.

- **The engine is upstream LadybugDB, unmodified (ADR 095).** Vulngraph links the prebuilt
  `liblbug` of the release pinned (with sha256s) in `scripts/fetch-ladybug.sh`; no engine
  source is vendored and there are no engine patches or C++ extensions. An upgrade bumps
  the pin and checksums, replaces `internal/graphdb/ladybug/lbug.h`, and bumps `SchemaVersion`.

- **Bump `SchemaVersion` (`graphstore/domain.go`) on ANY Ladybug DDL or loading-set change.**
  It gates the PVC snapshot (stale snapshots are rejected and rebuilt from ClickHouse) —
  there is no in-place Ladybug migration, and there must not be one.
- **`internal/graphschema` is the single source of truth for the edge pipeline:**
  edge types, sync tiers, rel mappings, the loaded/traversable set, expand view, reach set,
  and BFS weights are all DECLARED there and derived everywhere else (asset tiers, graphstore
  maps, NL prompts, explore fallback translation, `frontend/src/generated/graph-schema.json`
  via `go run ./cmd/graphschema-gen`). Never hand-edit a derived list; edit the registry and
  update the conscious pins (`TestRegistryDerivationsMatchLegacy`). A synced type feeding an
  unloaded rel MUST declare a `DropReason` — that gate keeps edges from being dropped silently.
- **Every `graph_edges` reader applies `graphschema.EdgeFreshnessCond`** — sync never
  deletes edges, only re-stamps live ones (stale rows linger until the TTL drops them;
  the admin connector purge, `asset/purge.go`, is the one hard-delete path); an unfiltered
  reader resurrects topology that no longer exists. `TestGraphEdgesReadersApplyFreshness`
  enforces it per file (exemptions are listed with reasons in `freshness_test.go`).
- **Every UI-facing `assets` reader applies `asset.inventoryReadCond`** — the same
  rule one table over: sync never deletes asset rows either (again bar the connector purge),
  and IaC `declared_*` rows are not resources. An ungated read over-counts assets relative to the graph. Count with
  `uniqExact(id)`, never `count()`: the table's `ORDER BY (type, id)` makes
  `FINAL` dedupe on the tuple, so an asset whose type changes can hold two permanent rows.
  `TestAssetReadersApplyLiveness` enforces it for `repo.go`, `repo_packages.go` and `optimize.go`
  in `internal/app/asset` (exemptions are listed with reasons); readers in other domains must
  apply it by hand.
- The Ladybug rebuild is gated by a **content digest of the load set** (`loaddigest.go`),
  never by an edge count (edges are re-stamped
  unconditionally, so the count is always positive). The digest must stay
  order-independent: ClickHouse read order is not stable, and an order-dependent digest
  silently disables the gate rather than failing. Three halves, and every column a node
  row loads MUST be classified into exactly one: **Topo** (anything with no in-place
  writer — a sweep-unstable value here silently disables the gate, so it
  never fires), **Scores** (asset RiskScore — rewritten every sweep by
  construction, refreshed in place by `refreshScores` + in-memory BFS), or **Signals**
  (the rollup, refreshed by `applySignals`). Per-row hashes get a `mix64` avalanche
  before the additive combine — raw FNV sums are byte-linear and two trailing-byte
  changes can cancel.
- Risk is a **score on the node**, propagated by BFS (`graphstore/bfs.go`), never a self-loop
  edge — BFS ignores self-loops. The post-BFS score lives ONLY in Ladybug, which
  serves it; there is no ClickHouse copy of node scores (nothing would read one), and
  `TestNoGraphNodesWriter` keeps a `graph.nodes` write-back from appearing.
- Cypher exposed via the API is **read-only**: pre-baked entries in `named_queries.go`, validated
  by `graphquery.IsReadOnly`. Never expose write Cypher. Caller-supplied Cypher runs on the
  cypher pool, where the engine caps variable-length paths at `cypherMaxPathDepth`.
- Layering: `graphstore` is the only writer (worker pod); `explore` is the only reader (serve pod,
  over RPC, with a ClickHouse-BFS fallback). Other domains never touch Ladybug directly.

## HTTP clients

`safenet.New(timeout)` for anything touching user/connector-supplied URLs (SSRF-blocking),
`safenet.NewInternal(timeout)` for trusted internal calls. `http.DefaultClient` is
linter-banned. Constructing an `http.Client` (a literal or `new`) outside `pkg/safenet` is
banned by `TestNoHTTPClientConstructedOutsideSafenet`, not the linter: forbidigo matches
names, not composite literals.

## Goroutines

Every spawned goroutine: `defer recover()` logging the panic. Bounded fan-out via
semaphore. Use the caller's `ctx` — never `context.Background()` in request paths.

## Jobs (River)

- When the domain write is in Postgres, enqueue its follow-up job with `river.InsertTx` in
  the SAME transaction. ClickHouse cannot join that transaction, so after a ClickHouse write
  the enqueue is a separate `client.Insert`: make the job safe to run twice, and make sure a
  periodic sweep re-finds work whose enqueue was lost to a crash (ADR 002).
- No cloud mutation runs as a River job: state-changing actions run only synchronously
  through the executor, after a person's approval (ADR 087). The one exception is opt-in VM
  disk scanning (ADR 096): its volume and sweep jobs may create and delete tagged, ephemeral
  snapshots, only through `internal/scanner/diskscan/snapshotter`, only for a connector whose
  admin enabled `create_snapshots` with a separate disk-scan principal. Do not add another.
- A queue is a pod-affinity lane, not a concern (ADR 002). Routing is declared in
  `internal/jobs/routing.go` (each kind's `InsertOpts().Queue`, derived into the consumed
  set), and every queue has an explicit entry in `queueWorkerCounts` — never River's
  absent-means-1 default. Long jobs get their own lane so they cannot starve others.

## HTTP API (REST + JSON)

The API is plain REST over JSON — no proto/gRPC/ConnectRPC.

- A new endpoint is a method on a domain's `handler.go`, registered in `internal/httpsrv/server.go`.
- `openapi/` holds the API contract: `openapi/openapi.yaml` is the index, with one
  file per Go domain under `openapi/domains/`. Update the matching domain file in the SAME commit
  as any request/response shape change: the integration server test validates real responses
  against it (drift fails CI), and the frontend client is generated from it.
- JSON is snake_case; responses are shaped by a `*Response` struct in the handler, never the
  domain type directly (keeps credentials/internal fields off the wire).
- Errors use `pkg/errs` (RFC 9457) — never `http.Error` or naked status codes.
- Writes are role-gated with `auth.RequireRole(...)` in the router. `TestEveryWriteRouteIsGatedOrExempt`
  and the integration server test enforce it; add a `TestXxx_NonAdmin_403` for a handler that
  checks the role itself.
- The frontend calls the API through `frontend/src/lib/api.ts` + `queries.ts` (TanStack Query) —
  never a bare `fetch` in a component.
- The MCP seam (`internal/app/mcp`) is JSON-RPC 2.0, mostly read tools plus admin-gated writes
  that self-check the session role.

## Tests

- testify; table-driven where natural. Unit tests live next to the code.
- Real-infra tests: `//go:build integration`, run with `-tags=integration` against
  `docker compose up` services.
- A handler that checks the role itself gets a `TestXxx_NonAdmin_403`.
- Pure logic (scorer, decay math, query compiler) gets exhaustive table tests.

## Hygiene

- No commented-out code, no placeholder stubs, no `// removed`, no dead config, no
  speculative abstractions, no files/dirs created "for later". Review enforces this, not a
  linter.
- ≤800 lines per Go file (`*_test.go`, generated code exempt) — a ceiling, not a target. Three
  legacy files are grandfathered in `.golangci.yml`; do not add to that list. revive enforces
  it for Go only; frontend files have no length limit.
- Match the style of surrounding code; read before you write.
- `go vet` and `golangci-lint run` clean before every commit. lefthook's pre-commit runs
  `golangci-lint run` (its standard set includes `govet`) and `go test ./... -count=1`, at
  the root and in the `internal/graphdb/ladybug` module; it runs no standalone `go vet`, so
  run `go vet -tags=integration` on the packages you touched yourself.
