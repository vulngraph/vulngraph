# Extending Vulngraph: in-tree extension points

The contracts below live under `internal/`, so Go extensions are built in this
repository. External VM inventory can use the scoped
[package-inventory API](examples.md#bring-your-own-scanner-submit-a-vms-packages).
The retired generic scan-import API is unavailable.

| Extension | Contract | Registered in |
|---|---|---|
| Collector — inventory from a provider | `collect.Collector` | `cmd/graph/collect_registry.go` |
| Check — a posture rule over assets | `checks.Check` | `internal/checks/cis.go` |

Image, IaC and VM inventory analysis use their own jobs and parsers. There is no
embedded external scanner contract. See [ADR 097](adr/097-retire-external-scanning.md).

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

Extensions must include tests and follow the layering rules in `CLAUDE.md`.
