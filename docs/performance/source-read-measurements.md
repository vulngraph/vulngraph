# Correlation and graph source reads

These changes reduce source-query working memory and repeated correlation work.
They do not establish a million-asset production capacity profile. The default
correlation reader still refuses 600,000 or more relevant assets; staging remains
an unaccepted experiment outside production wiring.

The local comparisons use deployed ClickHouse 26.8.34.13 and deployment XML,
Linux ARM64 containers, two database CPUs, a 3 GiB server cap and a 2 GiB query
cap. The worker has one CPU and 4 GiB RAM with an additional 4 GiB swap allowance.
Each fixture has two observation versions, skewed wide payloads, tags and populated
derived risk. Three alternating attempts retain failures and independently check
returned fields, duplicates, counts and the refusal flag. Annotation set, clear
and changed-input behavior are checked through actual writes.

| Logical assets | Successful query peak, old → new | Successful elapsed median including oracle, old → new | Old / new successful attempts |
|---|---|---|---|
| 5,000 | 40.9 → 30.8 MB | 36.4 → 29.0 ms | 3/3 / 3/3 |
| 100,000 | 272.1 → 192.7 MB | 395.3 → 475.8 ms | 3/3 / 3/3 |
| 1,000,000 | 1,442.1 → 202.1 MB | 3.583 → 3.542 s | 2/3 / 3/3 |

The million-row case returns the same 600,000-row refusal signal; it is not a
complete correlation sweep. Its old query had one server-memory failure. The
100,000-row case trades about 20% elapsed time for lower query memory. Client
allocation remains substantial: the production reader still retains its result.
The query projects metadata before tuple aggregation, omits an unused finding-risk
join and spills at 128 MiB. It preserves the declaration annotation overlay.

The separate million-asset graph reader retains its existing five-million-row
limit and ordering. It selects narrow keys before wide hydration, applies current
risk, then restores ID order in Go. Its three retained-result replays pass, with
1.122 GB maximum query memory and 6.147 s median including the independent oracle;
all three prior wide-sort attempts fail. The new 1.122 GB peak still exceeds the
20% single-query headroom target under the 3 GiB server cap. This is an isolated loader improvement,
not proof that old/new native graphs and ingestion fit concurrently.

Partial jobs can share up to 10,000 IDs with a conservative 1 MiB argument bound;
seed SQL remains limited to 200 IDs and 128 KiB of escaped IDs per request. Seeds
activate rules; later complete observations supply matching fields. A busy lane
retains a bounded union for at most one minute before admission. Overflow requests
a full follow-up. A pending full may cover already committed changes; a running
full cannot absorb changes after its source snapshot. Enqueue failures retain a
retry flag, and shutdown forces admission. Process crashes still require a
successful boot or periodic sweep. Old jobs are never declared covered by age alone.
Queue-depth checks still read pending job arguments; large aged backlogs and
multiple worker replicas need separate memory and recovery measurements.

A real Postgres barrier test proves the running/queued boundary. The mixed harness
now runs the production five-second coalescer and counts buffered work and its age
when draining waves. Earlier drain-only diagnostics are retained as different
scheduling cohorts; they do not establish production cadence or a batching speedup.

The fixed query budget remains 512 MiB. Required native CI additionally uses a
224 MiB regression ceiling at 100,000 assets, with exact output checks and no
shared-runner wall-clock gate. A deliberate old-query regression measured 264.8 MB
and failed that guard; the restored reader passed all three attempts at 190.1 MB
maximum. Larger source, mixed-load, swap-disabled and aged
runs remain manual/scheduled work. All full-profile coverage credit remains zero.
See the [compact measurements](results/correlation-source-2026-11-27.json).
