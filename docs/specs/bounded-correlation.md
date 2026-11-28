# Bounded correlation — implementation and evidence

**Status:** implemented; local component and integrated evidence below

**Date:** 2026-11-28

**Workload:** `graph.correlate` (PERF-05/11)

## Problem and result

The previous correlation service retained the whole relevant inventory, its
matching indexes and all output edges in Go. It refused a view with 600,000 or
more relevant assets. The refusal protected the worker but prevented a complete
analysis of larger inventories.

The new path captures one projected ClickHouse source read into temporary files,
replays bounded pages with the complete context each rule needs, and streams
relationships into a bounded output spool. It replaces the production row-count
breaker with separate index, context, page and disk budgets. The old materialized
reader remains an explicit test control. It is not a fallback after a new-budget
failure: silently running the old unbounded working set would defeat the limit.

## Data and failure boundaries

Source rows retain ID, name, type, account, IPs, domain, tags and projected metadata.
A private length-framed encoding avoids repeated JSON decoding. Its length/version
checks reject malformed input before allocating declared lengths. Decoded values
own their memory. Context/page charges retain the original JSON-equivalent sizes,
so a denser encoding does not silently admit a larger decoded context.

Type/account indexes contain file references. Replays merge already-ordered index
groups using one cursor per group; they do not copy every reference or query
ClickHouse once per page. Complete rule contexts are checked before construction.
Rules with indivisible context still refuse inputs exceeding that context budget.
An empty anchor can skip a rule only after the complete source has been captured.

The DNS rule makes three indexed passes. It preserves global, cross-account target
selection and the existing lowest-ID cap before target-type filtering. Generic
metadata indexes for role execution and shared security groups retain all types
in the captured view, including Azure VMs; the partial-activation declaration is
not used as an incomplete full-sweep input contract. Shared-group edges require
an actual security-group observation. Kubernetes exposure precedence remains
consistent across pages.

Rules yield each relationship before the service accumulates output. The spool
checks its row/index/byte budgets and deduplicates relationships before publication.
A source, context, rule or output-budget failure publishes nothing. Stateful CI
verification results become current only after complete successful publication.

Publication uses existing bounded writes. A failure after a successful batch can
leave a visible prefix and returns an error; this is **not atomic multi-batch
publication**. Retry and periodic reconciliation remain necessary. The temporary
snapshot is process-local and anonymous, removed on close or process exit. It is
not a durable ingestion generation or an atomic snapshot across source tables.

Cancellation is checked during source reads, replay, yielded output and publication.
This does not promise instant cancellation inside a long rule that yields nothing.

## Configuration and temporary storage

The worker reads positive integer MiB settings at startup:

| Setting | Default MiB | Purpose |
|---|---:|---|
| `CORRELATE_INDEX_MIB` | 512 | Logical charge for source references, groups and output deduplication indexes. |
| `CORRELATE_CONTEXT_MIB` | 16 | Maximum complete context required by an indivisible rule. |
| `CORRELATE_SPOOL_MIB` | 1024 | Combined source and output temporary-file bytes. |
| `CORRELATE_OUTPUT_MIB` | 768 | Output portion of the combined spool budget. |

Defaults match the explicitly sized million-asset validation below. Pages are limited
to 2,000 rows and 2 MiB; the source aggregation spills at 128 MiB. The output
budget must fit the total spool budget. Invalid configuration fails startup.
Budget exhaustion fails the job visibly; no truncated success is reported.

These are logical admission charges, **not hard Go-heap or RSS limits**. Driver
blocks, decoding, maps, slice growth, native graph memory and GC overhead must
also fit the worker. The input/output indexes still grow with the inventory and
unique relationship count, up to their explicit budgets.

Temporary files use `TMPDIR`/the operating-system temporary directory. The Helm
chart already mounts a disk-backed 2 GiB `/tmp`, shared with native graph CSV
staging. Size that storage for overlapping uses. An I/O or full-disk error fails
correlation; increasing the logical spool limit does not enlarge the pod volume.

## Matched component measurements

Synthetic observations use real deployed ClickHouse 26.8.34.13 with deployment
XML, Linux ARM64, Go 1.26.11 and the production memory governor. The worker has
one CPU and 4 GiB RAM with a separate 4 GiB swap allowance; ClickHouse has two
CPUs, a 3 GiB server cap and a 2 GiB query cap. These component runs used no swap.
They execute every registered rule but populate compute-role, IAM permission,
DNS and exposure paths; they are not capacity proof for every rule family.

Three alternating pairs at 100,200 logical assets include 200,200 physical asset
versions and exactly 202,600 independently verified persisted relationships.

| Metric | Previous materialized path | Bounded path |
|---|---:|---:|
| Median correlation/publication elapsed | 1.206 s | 2.578 s |
| Maximum sampled phase RSS | 530.05 MB | 101.98 MB |
| Total allocations per pass | about 1.54 GB | about 3.45 GB |
| Completed exact-output passes | 3/3 | 3/3 |

That is about 81% lower sampled peak RSS with a roughly 2.1x elapsed-time cost.
The bounded path improves capacity; it does not make this smaller case faster.
Sampling cannot establish an instantaneous maximum. Very short 5k phases have
missing samples, never zero-memory credit.

At 1,000,200 logical assets (2,000,200 physical versions), the previous path
refuses the view. With explicitly configured 512 MiB index and 768 MiB output
budgets, the bounded path completed three passes, each producing exactly
2,002,600 persisted relationships in 26.63–27.42 seconds. Their logical index
charge was 361.54 MB and combined source/output spool 847.20 MB. Sampled worker
RSS was 1.37 GB on the first pass after the refused control and about 734 MB on
the following two. Total allocations were about 34.28 GB per pass. These are
same-fixture repetitions in one store/process, not three fresh deployments.
An aborted control has no comparable successful latency.

The earlier 256 MiB-index cohort failed its budget before publication at
1,470,942 staged edges. That failure is retained; the larger explicitly configured
cohort does not rewrite its result. Logical memory limits and observed worker
headroom are reported separately.

## Integrated validation and limits

One current-source million-asset synthetic cohort completed all six waves: initial
load, unchanged sync, changed observations, partial omission, confirmed deletion
and reappearance. It used real ClickHouse/Postgres, River workers, native graph
COPY/BFS, enrichment and application reads. The production scheduler retained its
15-minute recurrence and 8-minute scheduling offset. Collectors returned modeled
results; this does not measure cloud SDK latency, permissions or throttling.

All 8,995 reads succeeded. The recovered query log contains 85,896 application
terminal records with no SQL exceptions, and the unique-job audit contains no
error attempts or terminal failures. Independent expected-ID checks found all
10,392 static severity factors current by 745.78 seconds after the changed wave,
within the predeclared 1,800-second diagnostic budget; deletion retained 9,880
matching active findings and reappearance restored 10,392. This certifies static
severity factors, not every graph-dependent scoring input. The harness explicitly
requests final graph reconciliation; it does not prove every periodic recovery path.

The fixture configures hundreds of synthetic provider scopes. Actual active
collection and retained-result concurrency both reached 20. There were 187 aligned
samples with ingestion, enrichment, full correlation and native COPY/BFS overlapping.
The measured whole-stack cgroup resident-plus-swap peak was **8.635 GB**, aligned
within 65.3 ms: worker 4.192 GB, ClickHouse 3.735 GB, Postgres 344.3 MB, plus 363.8 MB
swap at that instant. Cgroup memory includes file cache and the test observer. The
worker reached its 4 GiB RAM cap and used swap; this is **not a 4 GiB RAM-only
capacity result**. Component peaks must not be summed independently.

Private temporary storage peaked at 403.28 MB allocated, including anonymous
spools found through open descriptors. This excludes `/dev/shm` and scratch
outside the private temporary directory. Docker did not enforce the Helm 2 GiB
temporary-volume quota. Native shared-memory staging is charged through memory.

The original administrative query-log export exhausted memory while normalizing
and sorting the entire log; its empty export and failure are retained. An export
from the exact retained stores, after measurement, recovered all application
terminal records with bounded blocks and no sort. This recovery is not part of
measured workload time. The runner now uses that bounded export shape. The raw
report's 24-rule label is stale: its frozen source ran all 25 registered rules,
including CI access. No populated workflow/cloud-declaration capacity is claimed.

See the [compact component and integrated evidence](../performance/results/bounded-correlation-2026-11-28.json).
The integrated result is one cohort, not a matched whole-system before/after or
full-profile acceptance. No additional million run is inferred from the smaller
post-run guard checks.

## Regression checks and reproduction

Unit tests cover page-size invariance, global matching, Azure/SG relationships,
DNS precedence, retained-value ownership, malformed frames, bounded reference
replay, cancellation, logical-budget refusal, publication failure after a visible
prefix and stateful-rule commit boundaries. Real-CH fixtures check every persisted
relationship tuple/property, one terminal source query and publication costs.
Wall-clock timings are evidence, not shared-runner gates.

```sh
GOTOOLCHAIN=go1.26.11 go test ./internal/app/correlate
export PERF_LINUX_GO_CACHE=/absolute/path/to/isolated-linux-go-cache
export PERF_ENVELOPE_PACKAGE=./internal/app/correlate
export PERF_ENVELOPE_TEST='^TestBoundedCorrelationCosts$'
GOTOOLCHAIN=go1.26.11 scripts/benchmark-connector-envelope.sh target /fresh/output
CORRELATE_INDEX_MIB=512 CORRELATE_OUTPUT_MIB=768 GOTOOLCHAIN=go1.26.11 \
  scripts/benchmark-connector-envelope.sh million /another/fresh/output
```

A production rollback reverts the worker wiring; no schema migration or persistent
spool format is introduced. The legacy limit then applies again. Full-profile
coverage, all populated rule families, a 24-hour soak and the combined 5m-finding/
100m-package-membership workload remain separate, unaccepted scope.
