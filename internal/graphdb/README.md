# Vulngraph's graph engine: LadybugDB

Vulngraph's in-memory property graph is [LadybugDB](https://github.com/LadybugDB/ladybug),
the community-maintained successor of [Kùzu](https://github.com/kuzudb/kuzu),
used unmodified as a prebuilt library
(ADR 095, which also covers the Kùzu fork it replaced). This directory holds only the Go binding (`ladybug/`) and
LadybugDB's license.

## The library

`scripts/fetch-ladybug.sh` downloads the pinned LadybugDB release (version and
per-platform sha256 are in the script) into
`internal/graphdb/ladybug/lib/dynamic/<platform>/`. The library is downloaded,
never committed; run the script once after cloning and again whenever the pin
changes. The `Dockerfile` and CI use the same script.

The release links OpenSSL 3 dynamically: on macOS run `brew install openssl@3`,
on Debian 13 or Ubuntu 24.04 install `libssl3t64` (`libssl3` on older releases).

## The binding

`ladybug/` is a cgo binding over LadybugDB's C API (`lbug.h`, copied from the
same release). It started from the upstream Go binding and adds the tests in
`cgo_hardening_test.go`: native-heap leak checks on the string and STRUCT
parameter bind paths, NULL scans, and C++ exceptions surfacing as Go errors.
The binding is its own Go module, so the root `golangci-lint run` and
`go test ./...` do not reach it; CI and the lefthook pre-commit hook lint and
test it in separate steps run inside `ladybug/`. Every test in the module runs
on a fresh, empty database: the hardening tests and the upstream tests that
build their own data. Upgrading LadybugDB means: bump the pin and checksums
in `scripts/fetch-ladybug.sh`, replace `lbug.h` with the release's header, and
fix any C API signature the compiler flags.

## Attribution

LadybugDB and the upstream Go binding are licensed under the MIT License; the
copyright notice is in `LICENSE`.
