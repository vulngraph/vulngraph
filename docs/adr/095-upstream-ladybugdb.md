# ADR 095 — Run upstream LadybugDB, unmodified

**Status:** accepted (2026-10-22)

## Context

Vulngraph's in-memory graph engine was previously a fork of
[Kùzu](https://github.com/kuzudb/kuzu), which its authors have since archived.
It was built from source with the rest of the project. With no live upstream,
every engine fix was the project's to make, which a small team cannot sustain.

[LadybugDB](https://github.com/LadybugDB/ladybug) is Kùzu's community-maintained
successor: MIT-licensed, active (≈1,500 commits since the fork, releases every
few weeks), with nightly ASan/UBSan/TSan runs. Each release publishes prebuilt
shared and static libraries for linux and macOS on x86_64 and arm64.

Checked before deciding:

- **C API.** Every function the Go binding calls exists in `lbug.h` (v0.21.2)
  with the same signature under the `lbug_` prefix, except
  `lbug_value_get_blob`, which now returns the blob length (the old binding
  measured blobs with `strlen` and truncated any containing a NUL byte).
- **The fork's own engine patches.** A normalised diff of the fork against
  the Kùzu release it started from found two real patches: a misaligned-load
  fix in string hashing (present in LadybugDB) and a CSR-header null-column
  crash fix (its regression program passes against LadybugDB v0.21.2).
- **Crash shapes.** The same C program against both engines: `UNION ALL` with
  an `IN $param` list SIGSEGVs the fork and passes on LadybugDB; `label()`,
  dense variable-length paths, untyped relationship patterns and returning
  relationship objects pass on both at the sizes tried.
- **A shared correctness bug.** Both engines miss relationships on multi-hop
  and variable-length matches when a node table exceeds one node group
  (131,072 rows) and its last groups have no outgoing edges of the queried type
  ([ladybug#1341](https://github.com/LadybugDB/ladybug/issues/1341)). The
  fix, [#1342](https://github.com/LadybugDB/ladybug/pull/1342), was merged on
  2026-10-22 and is not yet in a release, so v0.21.2 still has the bug; the
  pin moves to the first release that contains the fix. The fork had the bug
  silently; on upstream it is tracked and fixed there. Until the bump, every
  load counts its node tables and the graph reports a table over the limit
  (`graphstore/node_group_guard.go`: API status, result flag, Explore banner,
  metric); [`known-limitations.md`](../known-limitations.md) lists those signals.

## Decision

1. Vulngraph links the prebuilt `liblbug` of a pinned LadybugDB release, used
   unmodified. `scripts/fetch-ladybug.sh` holds the version and per-platform
   sha256, and is the one fetch path for local development, CI and the
   Dockerfile. No engine source is vendored.
2. The engine is named Ladybug throughout: the Go binding
   (`internal/graphdb/ladybug`), code, configuration (`LADYBUG_*`), metrics
   (`graph_ladybug_*`), the chart and the docs.
3. The security extension is removed, not ported: plain Cypher on LadybugDB does
   what its functions did. `internet_exposed_assets` reads the `exposed` node
   property; `blast_radius_deep` ranks exposed assets by `count(DISTINCT m)` over a
   bounded variable-length path; `attack_path_check` returns the
   `* SHORTEST 1..4` path itself (execCypher flattens a returned path into its
   nodes and edges), where the function returned only a boolean. Both walk the
   relationship set the functions walked, and both have answer tests. A
   Cypher-callable function would need a C++ build pinned to each LadybugDB
   release, which is the cost this ADR removes.
4. `SchemaVersion` is bumped, so a snapshot written by the old engine is
   rejected and rebuilt from ClickHouse.
5. The query-shape restrictions written for the fork are lifted: variable-length
   paths, `label()`, untyped relationship patterns, `UNION` with `IN $param`,
   relationship objects and literals in `RETURN`, and `BOOL` parameters.
   `graphstore/engine_shapes_test.go` pins each one's answer on Vulngraph's real
   schema and loader, so an upgrade that regresses one fails there. The guard
   keeps only the read-only allowlist and the write/IO keyword block. Cost is
   bounded in the engine instead: the untrusted-Cypher connections set
   `var_length_extend_max_depth` to `cypherMaxPathDepth` (6), so a deeper path
   is a binder error and a bare `[*]` stops there — without it one dense
   `[*1..20]` fills the buffer pool and fails every concurrent query. Boolean
   node flags stay `INT32` (`= 1`) for compatibility with saved queries.

## Consequences

- No C++ toolchain anywhere: builds fetch a ~10 MB library in seconds.
- Engine fixes come from upstream. Upgrading means bumping the pin and
  checksums, replacing `lbug.h`, and fixing whatever C API signature the
  compiler flags.
- New runtime dependency: the release links OpenSSL 3 dynamically (`libssl3t64`
  in the Debian 13 runtime image; `brew install openssl@3` on macOS).
- Exposure to upstream pace: LadybugDB moves fast and one maintainer writes most
  commits. Pin exact releases and upgrade deliberately, after running the
  graphstore tests and the crash-shape probes.
- The binding keeps only the tests that run on an empty database (cgo hardening,
  database open/close, the driver, read-only statements). The upstream binding's
  other tests need its `tinysnb` fixture dataset, which this repository does not
  carry, so they are not part of it.
