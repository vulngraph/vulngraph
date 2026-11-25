# ADR 071 — The worker memory budget: GOMEMLIMIT bounds Go, the cgroup kills the process

**Status:** accepted (2026-08-04) · amended 2026-08-09 (`malloc_trim`), 2026-08-19 (file-backed Ladybug; engine footprint), 2026-08-21 (arithmetic re-derived; budget against the peak)

## Context

`graph-worker` can be OOMKilled even with `GOMEMLIMIT` set comfortably below the cgroup limit
and `internal/memlimit` reporting its budget as applied. The relevant measurements can only be
taken on a live worker, and one obvious way of taking them makes the problem worse, so this ADR
records the reasoning once.

It changes no code by itself; the values it justifies are set through chart values (see
`deploy/helm-values/example.yaml` and `deploy/helm-chart/graph/values.yaml`: `goMemLimit`,
`mallocArenaMax`) and `internal/memlimit`.

## Decision

**1. `GOMEMLIMIT` bounds only Go. The cgroup kills on Go + non-Go.**

A `GOMEMLIMIT` at, say, 80% of the cgroup limit reads like 20% headroom, but it caps only one of
two tenants. Non-Go resident memory (Ladybug's buffer pool, its allocator overhead, glibc arenas)
can exceed the remaining 20% by itself, in which case the setting is arithmetically incapable of
preventing the kill. Size it as: `GOMEMLIMIT = limit − measured non-Go resident − safety margin`,
with non-Go measured from `/proc/1/smaps` on a live worker.

**2. `internal/memlimit.Derive` models non-Go as `LADYBUG_BUFFER_MB + MEM_RESERVE_MIB`, and that
model under-reserves.**

The reserve (`DefaultReserveMiB = 1024`) covers Ladybug's buffer pool but not its allocator's
overhead, which can be larger than the pool. `Derive` takes whichever of the derived budget and
the explicit `GOMEMLIMIT` is tighter, so with an explicit value set the model is inert — which is
the only reason the under-reserve is not itself an outage. Do not "fix" it by raising
`MEM_RESERVE_MIB` and lowering `goMemLimit` in one step: tune one, re-measure, then the other.

**3. glibc sizes its arena cap from the node's core count, not the container's CPU limit.**

glibc caps non-main malloc arenas at `8 × nproc` and reads `sysconf(_SC_NPROCESSORS_ONLN)`,
which inside a container reports the host. On many-core nodes with a small CPU limit the cap is
hundreds of arenas. Each arena grows in 64 MiB heap segments (glibc `HEAP_MAX_SIZE` on x86-64)
and is returned to the OS only when its top chunk is free, so every rebuild's
allocate-and-free cycle ratchets each arena to its own high-water mark — a plateau rather than
a leak. `MALLOC_ARENA_MAX=2` is deployed alone so its effect can be attributed. Whether the
residue is live Ladybug data or freed-but-unreturned arena memory is settled by diffing
`/proc/1/smaps` across one full correlate sweep.

**4. Do not profile this pod with `/debug/pprof/heap?debug=1`.**

`debug=1` renders the whole profile as text into memory before writing it, which on a large
heap costs a substantial amount of Go memory per fetch. On a pod already near the kill line,
profiling to diagnose the OOM can cause it. Use `/proc/1/smaps` or the binary profile without
`debug=1`.

## Consequences

- The chart values carry the arithmetic at the point of use and this ADR carries the
  provenance. Both must move together.
- `internal/memlimit` keeps its tighter-of-two rule. It is a floor on correctness (a larger Ladybug
  pool can never silently eat Go's headroom), not an accurate model of the pod's non-Go
  footprint.
- Any change to the worker's CPU limit, node pool, or Ladybug buffer pool invalidates measured
  values. Re-measure via smaps; do not scale them.
- If the platform injects `GOMAXPROCS` (for example derived from the CPU request by a mutating
  webhook), it does not appear in this repo but changes GC behaviour (single-threaded marking at
  `GOMAXPROCS=1`). Check the pod's environment when reasoning about GC lag.

## Amendment (2026-08-09): `MALLOC_ARENA_MAX=2` alone was not sufficient

Capping `MALLOC_ARENA_MAX` bounds arena count, not each arena's unreturned high-water size, so
RSS still ratcheted toward the limit. §3 named the reason; this amendment acts on it.

**Fix:** `ladybug.TrimMemory()` (`internal/graphdb/ladybug/memtrim_linux.go`, a `malloc_trim(0)` cgo
call; `memtrim_other.go` is a no-op elsewhere) is invoked inside `(*ladybug.Database).Close()`
(`internal/graphdb/ladybug/database.go`), releasing freed arena segments immediately after
`ladybug_database_destroy`. It lives in `Database.Close()` rather than a caller-side wrapper because
review found that `OpenDatabase`'s GC finalizer and the `database/sql` driver's
`connector.Close()` (`internal/graphdb/ladybug/driver.go`) call `Database.Close()` directly,
bypassing any wrapper in `graphstore`. `MALLOC_ARENA_MAX=2` stays deployed; it was correct but not
sufficient.

Verification requires watching RSS across several correlate cycles; a fix that only delays the
ratchet looks identical to a real fix on the first cycle.

## Amendment (2026-08-19): file-backed Ladybug can work in containers

`graphstore.Open`'s doc comment (`internal/app/graphstore/service.go`) states that file-based
Ladybug fails in containers because `mmap(MAP_SHARED)` on a file fd is blocked by the container
security policy, and `Open` still uses in-memory mode unconditionally. File-backed mode can fail
in some container runtimes, but the claim is not universal and should be re-checked in the
target environment rather than inherited. Two probes, run inside a worker pod, settle it for a
given runtime:

1. A static Go probe doing `open` + `ftruncate` + `mmap(MAP_SHARED, PROT_READ|PROT_WRITE)` +
   write-through + `munmap` + read-back. On a runtime with `seccompProfile: RuntimeDefault`,
   `capabilities: drop: [ALL]`, `allowPrivilegeEscalation: false` and
   `readOnlyRootFilesystem: true`, none of those settings blocks `MAP_SHARED`.
2. A one-off engine probe, cross-built and executed in the pod, opened a file-backed database,
   applied DDL, wrote, closed, reopened, and read the data back.

Until `Open` is changed, its doc comment is the stale side of this disagreement; the code path
(in-memory only) is what runs.

A file-backed database is bounded by `BufferPoolSize`, not by the corpus, and reopening a file
is strictly better than replaying a gob snapshot (`WriteSnapshot`/`ReadSnapshot`, ADR 074's
warm-start seeding) through a full COPY. The probe proves the mechanism, not performance: COPY
throughput, traversal latency, behaviour when the working set exceeds the pool, PVC/restart
interaction, and `MaxDbSize` remain to be measured.

## Amendment (2026-08-19, second): the engine is a small fraction of the footprint

A one-off scale probe, run one mode per process against a realistic topology, showed process RSS flat
across an 8× change in buffer pool and flat between in-memory and file-backed modes. Most of the
footprint is Go-side — `[]asset.Asset` and `[]asset.Edge` for the whole corpus plus derived
copies — with the engine a small fraction.

**What this rules out:** neither file-backed mode nor moving the engine into its own process can
fix the OOM; both bound a small slice of the problem.

**What it confirms:** the lever is the Go-side corpus — fewer rows, and not materialising more
than needed per row. That is consistent with heap profiles (JSON decoding of metadata maps
dominating) and with the changes that actually helped: projecting metadata to a small fixed key
set and edge-gating signal-free `dns_record` nodes.

The same run showed the COPY load itself is fast, so rebuild-cost work should target the
ClickHouse read, BFS, digest pass and snapshot write rather than the loader. File-backed mode
remains worth adopting on its own merits (small on-disk footprint, faster point lookups,
reopen-on-restart), just not as a memory fix.

## Amendment (2026-08-21): the arithmetic re-derived

After arena capping and the scope reductions above, the non-Go term shrank, so the body's
formula would allow a higher `GOMEMLIMIT`. **Do not apply it.** Go takes its whole allowance
(`go_memstats_sys_bytes` sits at the ceiling) because nothing tells it otherwise; raising the
ceiling raises the resident total without adding capability. The ceiling is what keeps the
rebuild peak under the kill line, not a target to fill. It must also stay above the rebuild's
live-heap peak, or the pod trades an OOM for GC thrash.

What made the difference was scope, not tuning: cutting signal-free `dns_record` nodes, and
cutting what each row materialises in Go — metadata projection, dropping `Tags`, narrowing edge
properties, and fixing a substring-aliasing bug that kept every retained value pinning its whole
source document.

Node count is now a gauge with an alert (`graph_ladybug_node_budget`); treat it firing as the
trigger to re-measure rather than to raise the marker.

## Amendment (2026-08-21, second): budget against the peak, not a sample

A single sample sits near the bottom of a wide distribution. Size the budget from a pod's
whole life instead (cAdvisor `container_memory_*`, the pod's `go_memstats_*`, and cgroup
`memory.peak`): the rebuild peak recurs every few sweep cycles and is anonymous memory
(`memory.stat` `file` stays small, so nothing is reclaimable). Minute-granularity sampling
under-reports the top; prefer `memory.peak`.

**Arithmetic, redone.** Go fills `GOMEMLIMIT`, so the Go term in the sum is the ceiling, not the
live heap; the non-Go term is the *peak*, not the median. A limit sized from a sample can leave
that sum only a few percent spare — the same shape of finding as §1, from the other direction.

**Decision:** raise the cgroup limit and keep `GOMEMLIMIT` unchanged, for the reasons in the
previous amendment. As a rule of thumb, leave the non-Go peak at most 4/5 of the room between
`GOMEMLIMIT` and the cgroup limit, and plan on roughly 23 KiB of non-Go peak per graph node.
The example sizing in `internal/app/graphstore/node_budget_test.go` (`referenceLimitMiB`,
`referenceGoMemLimitMiB`) is one illustration of that rule, not a measurement to copy: a
deployment with a different node pool, CPU limit or corpus must measure its own non-Go peak
and set its own pair. The Ladybug buffer
pool is not reduced, because the scale probe showed RSS flat across pool size.
`MEM_RESERVE_MIB` stays at its default per §2; the under-reserve in `Derive` is still not fixed.

**Correction to the previous amendment:** comparing `heap_sys` with `heap_inuse` overstated how
much memory Go holds merely because it is permitted to; `heap_released` is not resident. Go's
resident share (`go_sys − heap_released`) exceeds live heap by a small amount — GC lag, plausibly
from `GOMAXPROCS=1` — not a lever worth risk.

**`NodeBudget` re-derived.** The earlier marker came from a prediction that subtracted a
ClickHouse-side `dns_record` population from a Ladybug-side count. A sibling change in the same
release restored many `depends_on` edges, and `depends_on` is in `retentionEdgeTypes`;
`filterLadybugAssets` retains any asset appearing in a retention edge, so restoring edges retained
assets the DNS prune would otherwise have dropped. Node count is an output of the edge set, so
no prediction that treats asset and edge changes independently can be right. Node count is also
a weak proxy for memory: `dns_record` was the cheapest cohort (no metadata, no edges, no score).

`NodeBudget` (`internal/app/graphstore/asset_filter.go`) is derived from the example
sizing rather than guessed: room above Go's ceiling (limit − `GOMEMLIMIT`) × 4/5 (alert with
20% of the room unspent) ÷ the per-node rule of thumb, rounded down. Both inputs are
illustrative; recompute them for your own deployment. The full table is in the constant's doc
comment.

Two mechanisms hold this together:

- `TestNodeBudgetFitsTheDeployedMemoryLimit` fails if `NodeBudget`, at the per-node rule of
  thumb, does not fit inside 4/5 of the room the example limit leaves above Go's ceiling, so the
  two cannot drift apart (mutation-checked by `internal/guardmutation`).
- `GraphWorkerMemoryPeakNearLimit` (`deploy/helm-chart/graph/alerts/rules.yaml`) alerts on
  `max_over_time(working_set / limit [6h]) > 0.85` — peak-based, because the peak lasts only
  minutes per cycle and an instantaneous threshold would rarely be true at scrape time.

**Still unknown.** The non-Go peak is much larger than the buffer pool accounts for, and the
scale probe puts the engine at a small fraction of it: either the probe does not reproduce the
rebuild's allocation pattern, or the residue is arena high-water that `malloc_trim` does not
reach at peak time. Settling it needs `/proc/1/smaps` sampled *during* a rebuild. A lead, not a
finding: the largest excursions coincided with an unusually long sweep cycle with a sawtoothing
`heap_inuse`, consistent with two overlapping units of work — which would make admission
control, not allocation, the lever.
