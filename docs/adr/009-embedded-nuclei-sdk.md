# ADR 009 — Nuclei embedded via its official Go SDK

**Status:** accepted

## Context

A common pattern is to pull external-facing assets from an asset-inventory graph (for
example one kept in Neo4j) and run nuclei over them via `projectdiscovery/nuclei/v3/lib`.
Vulngraph owns its asset graph instead, and makes active scanning a first-class domain, which
single-tenancy makes safe to do (a deployment only ever scans its own estate).

## Decision

Embed nuclei v3 through its official SDK (`nuclei/v3/lib`) — SDK surface only: no CLI
machinery and no cloud (PDCP) upload. What the SDK still contacts on its own is listed in
`internal/scanner/nuclei/egress.go`:

- The SDK's version check to api.pdtm.sh runs before any option is read, so no SDK option
  stops it. Vulngraph replaces the transport of the HTTP client it uses with one that never
  dials, in every mode (`TestVersionCheckIsAlwaysRefused`).
- The SDK's own template installer fetches the latest nuclei-templates release, unpinned and
  unchecksummed, so every engine turns it off. Scans run one pinned release instead:
  `internal/scanner/nuclei/templates.go` downloads its archive, checks the sha256, and unpacks
  it with path and size limits (`NUCLEI_TEMPLATES_VERSION` with `NUCLEI_TEMPLATES_SHA256`
  picks another release, `NUCLEI_TEMPLATES_DIR` an operator's own copy, and
  `NUCLEI_TEMPLATES_DOWNLOAD_DISABLED` or `OFFLINE_MODE` stops the download).
- Interactsh out-of-band testing against ProjectDiscovery's servers is off unless
  `NUCLEI_INTERACTSH_ENABLED=true`, and always off under `OFFLINE_MODE`.

- The SDK is imported **only** by `internal/scanner/nuclei` (depguard-enforced); the scan
  domain depends on a small `Engine` interface.
- Scan targets come from our own asset inventory. The one exception is the admin-only template
  test (`POST /api/scans/templates/test`), which runs one template against an admin-supplied
  http(s) URL. It is held to the same scan target policy: private addresses are refused unless
  `SCAN_ALLOW_INTERNAL_TARGETS=true`, and link-local and cloud metadata addresses are always
  refused.
- The template editor (`POST /api/scans/templates/validate` and `/test`) accepts every protocol
  the embedded SDK runs without an extra capability: `http` (and its deprecated `requests`
  key), `dns`, `network` (and `tcp`), `ssl`, `websocket`, `whois` and `javascript`. Nuclei
  loads a `javascript` template only when it is signed by a trusted key, so an unsigned one
  fails validation with that reason. `file`, `code`, `headless` and `workflows` templates are
  refused by name: Vulngraph runs templates against URLs, never runs commands on the scanner
  host, starts no browser, and takes one template at a time. Validation runs under the
  request's context, capped at 10 seconds.
- Template selection is by tags (`templateTagsFor` in `internal/scanner/nuclei/nuclei.go`): a
  scan profile's tags when it has any, otherwise tags chosen from the targets' asset types plus
  technology names found in asset tags (nginx, redis, …). Only medium, high and critical
  templates run, and a fixed exclusion list (`fuzzing`, `intrusive`, `dos`, …) applies either
  way. Credential-attempt templates (`default-login`, `brute-force`, `bruteforce`) are excluded
  too, so a scan nobody configured never tries a login; a profile opts in by naming the tag. There is no tech-detect pass and no selection by known CVEs; the fingerprint-to-template
  loop ADR 020 scoped was not built.
- Bounded concurrency, rate limits, per-scan timeouts. Results land in `findings` with
  `source=nuclei` and flow through scoring like every other finding.
- No template corpus is bundled (see ADR 020). Organisation-specific templates and config
  are mounted at deploy time — never committed to the OSS tree.

## Consequences

- The nuclei dependency tree is heavy; quarantining it in one package contains the cost
  and keeps it swappable.
- The single-binary property (ADR 001) holds — no scanner sidecar.
