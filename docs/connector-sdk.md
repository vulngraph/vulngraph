# Extending Vulngraph: in-tree extension points

The contracts below live under `internal/`, which Go does not let another module
import, so extensions are built in this repository. To feed findings from an
external tool without code changes, use `POST /api/scans/import` (one generic JSON
format, tagged by source).

Vulngraph has three extension points. Each is a small Go contract plus one registration
site, so a new source, rule, or scanner is added without changing the pipeline around
it:

| Extension | Contract | Registered in |
|---|---|---|
| **Collector** — inventory from a provider | `collect.Collector` (`internal/collect`) | `newCollectRegistry` in `cmd/graph/collect_registry.go` |
| **Check** — a posture rule over assets | `checks.Check` (`internal/checks`) | `checks.Default()` in `internal/checks/cis.go` |
| **Scanner** — a tool Vulngraph drives against targets | `scan.Scanner` (`internal/app/scan`) | `scan.NewMultiScanner` in `bundledScanner` (`cmd/graph/worker_deps.go`) |

Nuclei (`internal/scanner/nuclei`) is the one bundled `Scanner`. Other in-tree scanners
(`internal/scanner/iac`, `internal/scanner/imagevuln`) run as their own jobs rather than
through the `Scanner` contract; `internal/scanner/pkginventory` holds the package parsers they
and the VM inventory collectors share.

## `Collector` — inventory Vulngraph *pulls*

```go
type Collector interface {
    Collect(ctx context.Context, cfg map[string]string) (Result, error)
}
```

`cfg` is the connector's decrypted config. `Result` carries `Assets`, `Edges`, and
`Findings` (provider-native findings the provider already computed, such as GuardDuty or
SCC); the sync worker records all three and runs the check registry over the assets.

- **Completeness is explicit.** Set `Result.Partial` when collection was incomplete, and
  call `Result.MarkComplete(scope, types, n)` only for scopes whose enumeration you can prove
  was complete (every page read, no error swallowed). Absence of an asset is treated as
  deletion only under a proven-complete scope, so a transient API error must never look
  like an empty account.
- Wrap errors that retrying cannot fix (bad credentials, missing permissions) with
  `collect.ErrPermanent` so one unreachable connector does not starve the worker pool.
- A new provider also needs a `connector.Type` in `internal/app/connector/domain.go`
  (`Type.Valid` and its `requiredKeys`), then one line in `newCollectRegistry`:

```go
registry.Register(connector.TypeMyProvider, collectmyprovider.New())
```

Existing collectors under `internal/collect/` (`aws`, `gcp`, `azure`, `github`,
`kubernetes`, `okta`, `google`) are the reference implementations. Keep the provider SDK
behind an unexported interface so the mapping logic is unit-tested without network calls.

## `Check` — rules Vulngraph *evaluates*

A check is a value, not a type: an ID, metadata, a provider and optional asset type, and a
`Violates func(asset.Asset) bool` predicate. Add it to the `Register(...)` list in
`checks.Default()`.

- `RequiredKeys` and `ProbeValues` are generated, not hand-written: run
  `go run ./cmd/checkkeys-gen` after adding or changing a predicate. They let the lifecycle
  tell "the resource is clean" apart from "the collector did not observe the keys the
  predicate reads", so missing data never closes a finding as fixed.
- Use `SeverityFor`, `TitleFor`, and `EvidenceFor` when one rule covers materially different
  conditions or a responder needs the facts that made it fire.
- The finding id is derived from the check id and asset id, so keep `ID` stable.

## `Scanner` — tools Vulngraph *drives*

```go
type Scanner interface {
    Name() string                 // attribution, dedup, and config selection
    Capabilities() Capability     // CapWeb | CapNetwork (bitmask — a scanner may have several)
    Scan(ctx context.Context, targets []Target, templateTags []string) (ScanOutput, error)
}
```

`templateTags`, when non-empty, selects which templates or rules run (a scan
profile's tags); nil lets the scanner choose.

`ScanOutput` wraps `Results []Result` plus `TemplateTags []string` and
`TemplateCount int` (which templates were selected and how many produced at
least one match). The multi-scanner reads both, so a bare result slice isn't
enough.

- `Capabilities()` is how the multi-scanner routes: a target is handed only to
  scanners whose capability fits it (web scanners get `Target.URL`, network
  scanners get `Target.Host`). Declare what you actually consume.
- Return provider-neutral `Result`s. Set `Scanner` to your `Name()` so findings
  are attributed and deduped correctly; fill `Host/Port/CVE/CVSS` when you have
  them so nothing is lossy.
- Keep any third-party SDK or binary **behind a seam** (an unexported interface
  the adapter depends on), so the mapping logic is unit-tested without the tool.
  `internal/scanner/nuclei` is the reference implementation.

### Registering a scanner

Add it to the list passed to `scan.NewMultiScanner` in `bundledScanner`
(`cmd/graph/worker_deps.go`). The worker and the scanner pod both build their
scanner there:

```go
s, err := scan.NewMultiScanner(enabledScanners(getenv),
    nuclei.New(),
    mytool.New(getenv("MYTOOL_URL")), // <- your Scanner
)
```

`mytool.New` is the exported constructor shown in the example below. It builds
the production client itself, because the client seam is unexported and nothing
outside the package can implement it.

Operators choose what runs with `SCAN_SCANNERS` (comma-separated `Name()`s; empty
= all bundled). A name that matches no bundled scanner stops the pod at startup,
and a scan fails when one of its targets fits no enabled scanner's
`Capabilities()`, so neither case can pass for a clean scan.

### Example

```go
// internal/scanner/mytool/mytool.go
package mytool

import (
    "context"
    "fmt"

    "github.com/vulngraph/vulngraph/internal/app/scan"
)

// hit is one match as your tool reports it.
type hit struct{ RuleID, Title, Severity, CVE string }

// apiClient is your seam to the tool, faked in tests.
type apiClient interface {
    scan(ctx context.Context, url string, tags []string) ([]hit, error)
}

type Scanner struct{ api apiClient }

// New is what cmd/graph registers: it wires the production client, which
// implements apiClient over the tool's API with a safenet.New HTTP client
// (newHTTPClient, not shown). Tests build &Scanner{api: fake} instead.
func New(baseURL string) *Scanner { return &Scanner{api: newHTTPClient(baseURL)} }

func (s *Scanner) Name() string                  { return "mytool" }
func (s *Scanner) Capabilities() scan.Capability { return scan.CapWeb }

func (s *Scanner) Scan(ctx context.Context, targets []scan.Target, templateTags []string) (scan.ScanOutput, error) {
    var out []scan.Result
    for _, t := range targets {
        hits, err := s.api.scan(ctx, t.URL, templateTags) // your tool's call, behind the seam
        if err != nil {
            return scan.ScanOutput{}, fmt.Errorf("Scan: %w", err)
        }
        for _, h := range hits {
            out = append(out, scan.Result{
                Scanner: "mytool", TemplateID: h.RuleID, Name: h.Title,
                Severity: h.Severity, MatchedURL: t.URL, CVE: h.CVE,
            })
        }
    }
    return scan.ScanOutput{Results: out}, nil
}
```

Whichever extension you add, land its tests in the same commit and follow the layering
rules in `CLAUDE.md`.
