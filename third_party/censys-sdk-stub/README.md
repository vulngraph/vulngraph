# censys-sdk-stub

An inert, API-compatible stand-in for `github.com/censys/censys-sdk-go`,
substituted by a `replace` directive in the root `go.mod`.

**Why.** The upstream module ships no LICENSE file (only an MIT badge in its
README), so there is no clear grant to redistribute it inside this project's
binaries and images. It reaches this project only through
`nuclei/v3/lib` → `projectdiscovery/uncover` → uncover's Censys search agent.
Vulngraph never runs uncover's internet-search sources — it scans its own
collected inventory — so that agent is dead code here.

**What.** Written from scratch against the single call site in
`uncover/sources/agent/censys/censys.go` (MIT); it contains no code from the
upstream module. `GlobalData.Search` always returns `ErrDisabled`.

**Verify.**

```sh
go version -m bin/graph | grep -A1 censys-sdk-go   # => ./third_party/censys-sdk-stub
go test ./internal/scanner/nuclei -run TestUnlicensedCensysSDKIsReplaced
```

If upstream adds a LICENSE file with a compatible license, this stub and its
`replace` can be removed. If an uncover upgrade changes the calls it makes,
the build fails at compile time — extend the stub; never drop the `replace`.

License: MIT (this stand-in is under its own `LICENSE`, not the repository's).
