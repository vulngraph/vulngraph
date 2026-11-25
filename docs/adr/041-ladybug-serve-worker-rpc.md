# ADR 041 — Ladybug serve/worker split and the internal RPC seam

**Status:** accepted (documents the implemented topology; amended 2026-07-21, 2026-08-21)

## Context

Ladybug (the in-memory Cypher engine, ADR 025/026/095) is a single-writer, in-process graph. Two
needs pull against that: the **worker** must own the single writer to rebuild the graph each
correlate sweep, while the **serve** pod must answer Cypher queries for the UI/API without going
dark whenever the worker restarts or is mid-rebuild. This split, and the RPC seam between the
pods, had never been captured in an ADR.

## Decision

A tiered read topology with a narrow, authenticated RPC seam:

1. **Worker Ladybug (primary, read+write).** The worker pod owns the writer and does the
   rebuild/BFS. `internal/app/graphstore` is the *only* writer.
2. **Serve Ladybug (optional replica, read-only).** Enabled by `SERVE_LADYBUG_ENABLED`, the serve pod
   runs its own independent replica synced from ClickHouse (30-minute sync ticker) so Cypher stays up
   across worker restarts. `internal/app/explore` is the only reader.
3. **Worker RPC (fallback).** When the serve replica is disabled or still doing its initial sync,
   the serve pod queries the worker's Ladybug over an internal HTTP RPC (`LADYBUG_INTERNAL_PORT`,
   default 8090), authenticated with a shared secret (`LADYBUG_RPC_SECRET`, constant-time compare;
   the readiness probe is exempt). If the secret is unset the listener refuses to start unless
   `LADYBUG_RPC_INSECURE=true` is explicitly set — fail-closed, not warn-and-continue.
4. **ClickHouse BFS (last resort).** If no Ladybug is reachable, `explore` falls back to a
   ClickHouse-native BFS — degraded (no full Cypher) but always available.

Readiness is gated on `Ready() = synced AND nodeCount > 0`, and rebuilds swap off-side then take
the write lock atomically, so a query never hits an empty or half-built graph.

## Consequences

- The Graph tab never goes dark on a worker restart when the serve replica is enabled; when it is
  not, the RPC + ClickHouse fallback still answer.
- The internal RPC is pod-internal and shared-secret-authenticated — not Ingress-reachable — so an
  in-cluster pod can't freely read the graph; an unauthenticated internal listener would expose
  the full graph to any workload with network reach.
- Layering holds: `graphstore` writes, `explore` reads, nothing else touches Ladybug directly (ADR 010).
- **Cost:** running the serve replica needs extra memory on the serve pod, so it is opt-in; and
  the two Ladybugs can be briefly inconsistent (serve replica ≤30 min stale) — acceptable for read
  queries, and the worker is authoritative for decisions.

Cites ADR 025/026 (the graph the seam serves), 095 (the engine), 010 (the writer/reader layering),
003 (ClickHouse as the reproducible source of truth behind both).

## Amendment (2026-07-21) — raw Cypher is intentionally 2-tier, not 3-tier

The tiered topology above (steps 1–4) is for **structured** graph queries (`/api/graph/query`,
`/api/graph/expand` — `explore.Repo`'s `MatchSeed`/`Neighbors`), which do reach the ClickHouse BFS
tier when both Ladybugs are down.

**Raw Cypher (`/api/graph/cypher`, `/api/graph/nl` — `explore.CypherRunner`) only has tiers 1–2:
serve Ladybug → worker RPC.** `TieredCypherRunner` has no ClickHouse arm, and this is deliberate, not
an oversight: ClickHouse cannot execute arbitrary Cypher (no query parser, no pattern matching, no
aggregation over free-form patterns — `CHRepo` implements only two fixed SQL templates for seed
lookup and single-hop expansion, which is what the structured tier's BFS actually uses). Building a
general Cypher-to-SQL translator was evaluated and rejected as disproportionate to the risk it
covers: both Ladybug tiers failing at once is a compound failure across independent pods, and raw
Cypher is the power-user/debugging query path, not the primary UI path (which already has full
3-tier coverage via the structured API).

Accepted risk: if both Ladybug tiers are down, `/api/graph/cypher` and `/api/graph/nl` fail outright
(no degraded mode). `TieredCypherRunner.RunCypher` logs `both_ladybug_tiers_exhausted: true` at error
level when this happens, so it's an observable, alertable event rather than a silent gap — that
signal is the trigger to revisit this decision if it ever fires, rather than building speculative
fallback machinery up front.

## Amendment (2026-08-21) — a tier that answers EMPTY has not answered

The tier chain switched on `err == nil` alone. That was written when Ladybug held
every asset ClickHouse held, so "zero rows" could only mean "no such node". It no
longer does: `filterLadybugAssets` prunes any asset with no retention edge and no
risk score, which typically includes many `dns_record` and `dns_zone` assets.
Ladybug's answer for
one of those ids is zero rows with a nil error, which is byte-identical to "no
such asset", and returning it **short-circuited the ClickHouse tier that still
holds the asset and its edges**. `GET /api/graph/expand?id=<pruned record>`
answered `200 {"nodes":[],"edges":[]}`, and a seeded view answered `400`
`ErrNoSeed`, for an asset the inventory lists.

So the rule is now: **for an ID-keyed lookup, an empty answer from a Ladybug tier is
a MISS.** `TieredRepo` and `FallbackRepo` both pass it down the chain
(`emptyIsMiss`, `explore/tiered_repo.go`), and ClickHouse — which is the source of
truth and never prunes — answers. `ErrNoSeed` consequently regains its meaning:
after this it can only be raised for an id that genuinely has no asset row.

Two deliberate boundaries:

- **Selector seeds are excluded.** A seed with types/provider and no ids that
  returns nothing is making a true statement about the *traversable graph*, and
  falling through would seed views with exactly the isolated, unreachable nodes
  the prune exists to keep out.
- **Raw Cypher is unchanged** — the 2026-07-21 amendment still holds, ClickHouse cannot
  execute it, and an empty result set from a pattern query is not a point lookup.

`graph_explore_tier_empty_fallthrough_total{op}` counts only the
emptiness-caused fall-through, never an ordinary tier error. It is not alerted on
(a nonzero rate is the expected steady state and there is no denominator); it is
the evidence the check is reached at all, and a flat zero on `graph-serve` means
the behaviour has regressed. `TestFallbackRepo_PrunedNodeReachesClickHouse` and
`TestLadybugBlastProvider_PrunedSeedFallsBackToClickHouse` are both mutation-verified
in `internal/guardmutation`.

The same "empty is not an answer" reading applies outside `explore`:
`ladybugBlastProvider.BlastRadius` (`cmd/graph/ladybug_blast.go`) treated a `MatchSeed`
miss as a one-asset, typeless, zero-edge blast radius **with a nil error**, and
`respond.blastRadiusFor` only retries on `err != nil` — so a high-severity finding on a
pruned `dns_record` (e.g. a subdomain-takeover candidate) could be sized as zero-blast. It now
delegates to the ClickHouse BFS, the same thing its not-ready branch already did.

Where the Ladybug answer for a pruned node is *correct* rather than merely empty, it
was deliberately left alone, because a ClickHouse fallback there would be worse
than the gap: `BlastRadiusCount` returns 0 for a node with no retention edge, and
that is the graph's own semantics — the CH BFS walks pure-topology adjacency
(`in_vpc`, `member_of_zone`, `runs_in`) and would re-inflate blast scores with the
zero-value clusters the filter removes, at the cost of a sequential CH BFS for every
open finding that sits on a pruned asset. Likewise the node-signal reads
(`NodeSignals`, `IsExposedEdge`, `InternetHops`, `ladybugPeerFindings`) are safe by
construction and not by luck: `prewarmSignalCache` is keyed by finding
`resource_id`, not by graph membership, so any id that carries a finding is
answered from the ClickHouse rollup; and every exposure/reach edge type is a
retention edge, so a node with one is never pruned in the first place.
