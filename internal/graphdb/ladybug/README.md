# Ladybug

Go binding for [LadybugDB](https://github.com/LadybugDB/ladybug), the embedded
property graph database Vulngraph uses as its in-memory security graph. See
`../README.md` for how the library is fetched and upgraded.

## Overview

Vulngraph's Ladybug instance stores assets, IAM roles, packages, repositories, and their relationships
as a typed, in-memory graph. It supports:

- **Cypher query language** for arbitrary graph traversal
- **Blast-radius BFS** — how many assets can be reached from a compromised resource
- **Attack path enumeration** — IAM escalation chains to admin
- **Supply-chain exposure** — repos deployed to internet-facing workloads
- **Topology signals** — pre-computed exposure/privesc counts projected onto nodes

## Architecture

The worker pod holds the primary Ladybug instance, embedded in-process. Each
correlate sweep (the 30-minute full correlate is the ground-truth cadence)
re-reads the load set from ClickHouse and rebuilds the projection only when
that set's content digest changes; otherwise it refreshes scores and signals in
place. A rebuild takes minutes on a large graph, with the live instance swapped
in behind a lock held only for the final moment. The instance serves other pods
over an authenticated internal RPC.

An optional serve-pod replica (`SERVE_LADYBUG_ENABLED`) is a second,
independent read-only instance: the serve pod syncs it from ClickHouse itself
with the same digest-gated sync, re-reading the load set every 30 minutes and
rebuilding only when its digest changes; nothing feeds it over RPC. The RPC runs the
other way: serve calls the worker's Ladybug, as the only engine when there is
no replica, or as the fallback behind the replica. Serve skips the replica
while it is not ready (no snapshot or first sync loaded yet, or zero nodes), and falls back to the worker when the
replica errors (a Cypher query the replica rejects as invalid is not retried)
and, for an explore lookup by asset id, when the replica answers empty
(`internal/app/explore/tiered_repo.go`).

The graph lives entirely in memory; there is no persistent storage (a PVC
snapshot just warm-loads a pod restart in seconds — ClickHouse remains the
source of truth). If Ladybug is down, a ClickHouse BFS fallback serves explore
and blast-radius traversal reads. Cypher queries (Explore, saved queries, chat,
MCP) fail until Ladybug is back.

```
worker pod:  ClickHouse → SyncFromSources() → Ladybug (primary)
                                                ↓ in-process
                                   enrichment workers → blast radius / attack paths
serve pod:   Explore / Cypher → serve replica (optional; synced from ClickHouse every 30 min)
                              → worker Ladybug over RPC (no replica, replica syncing, error or id miss)
                              → ClickHouse BFS (traversal reads only, no Cypher)
```

## Go package

```go
import ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"
```

## Tests

The tests cover native-heap leaks, NULL scans, C++ exceptions surfacing as Go errors,
verbatim engine errors, database open/close, the `database/sql` driver and read-only
prepared statements. `TestMultiHopAfterMissingRelationshipNodeGroup` loads 131,112 nodes
and checks the original upstream #1341 path-loss case against the actual linked library.
It runs in normal CI and lefthook, without a build tag or external services.

## Configuration

| Env var              | Default | Description                                   |
|----------------------|---------|------------------------------------------------|
| `LADYBUG_BUFFER_MB`     | 1280    | Buffer pool size in MB                          |
| `LADYBUG_INTERNAL_PORT` | unset (engine disabled) | Enables Ladybug on the worker and sets its internal RPC port (e.g. `8090`). If set and the engine fails to open, the worker stops at startup |
| `LADYBUG_RPC_SECRET`    | —       | Shared-secret auth on the internal RPC port     |
| `LADYBUG_RPC_INSECURE`  | off     | Exact `true` disables RPC auth (local dev only) |
| `SERVE_LADYBUG_ENABLED` | off (unset) | On/off switch (`1`/`true`/`yes`/`on` or `0`/`false`/`no`/`off`; anything else stops serve at startup): runs a read-only Ladybug replica in the serve pod. If on and the replica fails to open, serve stops at startup |
