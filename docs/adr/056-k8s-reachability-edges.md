# ADR 056 — Kubernetes internet-reachability: exposure-chain edges join the reach set

**Status:** accepted (implemented 2026-07-15)

## Context

The internet-hops BFS (`graphstore/reach.go`, ADR 044) starts from every
internet-exposed seed and walks the *reach* edge set — the edges an attacker
crosses after a foothold — to grade how reachable each resource is
(`maxReachDepth = 3`). A resource that lands within the cap qualifies as
must-fix; one that doesn't demotes to "contained". The gate that decides whether
reachability even runs for a resource type (`enrich.IsNetworkReachableResource`)
is widened to include the k8s workload types (`k8s_pod`, `k8s_service`,
`k8s_ingress`, `k8s_deployment/statefulset/daemonset/job`).

But the reach set held only IAM-movement edges (`can_assume`, `executes_as`,
`can_escalate_to`, `accesses_secret`, `has_role`). The Kubernetes exposure
topology — `internet →(exposed_to_internet)→ k8s_ingress →(routes_to)→
k8s_service →(targets)→ k8s_pod/workload` — was **not** in the set: `routes_to`
and `targets` were `Reach:false`. So the BFS reached an internet-facing ingress
seed and dead-ended there; the backend service and pods behind it were never
graded reachable. Widening the gate alone would have run the BFS on k8s
resources and found nothing.

A second gap compounded it. Exposure edges land on the **pod** — a public
`LoadBalancer` service selects pods (which carry its selector labels), not the
owning `Deployment` (whose top-level labels usually differ), so `service→pod`
`targets` edges are the common case and `service→deployment` edges are rare.
Yet per-pod
findings are aggregated onto the owning workload (`checks.workloadAggregator`),
whose node then carries no exposure or `targets` edge — so the aggregated
finding read as unreachable even when its pods are internet-facing.

## Decision

Two localized changes, gated behind one `SchemaVersion` bump — deliberately
**shared with ADR 057**, whose `runs_package` change ships in the same bump.

1. **k8s topology edges join the reach set (`internal/graphschema`).**
   `routes_to` (ingress→service) and `targets` (service→pod/workload) flip to
   `Reach:true`. Both point src→dst in the direction traffic (and an attacker)
   flows, matching the BFS's forward walk from the exposed seed: an exposed
   ingress seeds at hop 0, `routes_to` reaches the service at hop 1, `targets`
   reaches the pod/workload at hop 2 — comfortably within `maxReachDepth`.
   Because the ADR 044 invariant requires every reach edge to be fetched
   **uncapped** (a capped reach edge truncates silently and the BFS misses
   paths, as happened earlier with `has_role`), both move from the bulk tier to the
   critical tier. They already map to the loaded `Accesses` rel, so no DDL or
   checksum change — the version bump exists solely to reject PVC snapshots
   built with the old, dead-ended reach topology.

2. **Exposure propagates from an exposed pod up to its owning workload
   (`correlate/k8s.go`).** `K8sServiceTargets` now mirrors every `service→pod`
   edge onto the pod's owning workload, derived from the pod's
   `owner_kind`/`owner_name`/`namespace` metadata into the exact workload ID
   the collector and `workloadAggregator` use (`<cluster>/<kind>/<ns>/<name>`):
   a `targets` edge (so the internet→ingress→service→owner chain resolves at the
   correct hop) and, for a public `LoadBalancer`, an `exposed_to_internet` edge
   on the owner (so a directly-public workload seeds the BFS). Propagation is
   restricted to owner kinds collected as first-class assets
   (Deployment/StatefulSet/DaemonSet/Job) — a bare ReplicaSet owner has no
   asset, so an edge to it would be an unresolvable zombie. No new edge type:
   both reuse `targets`/`exposed_to_internet`, so the freshness contract
   (ADR 049) and the loaded `Accesses`/`ExposedToInternet` rels apply unchanged.

## Consequences

- An internet-facing ingress no longer dead-ends: its backend service and pods
  (and their owning workloads) grade reachable within the hop cap, so k8s
  workload findings promote to must-fix instead of silently staying contained.
- Reachability is uniform — the BFS crosses the k8s chain the same way it
  crosses IAM movement, with no special-casing in `reach.go`.
- The aggregated workload finding (the one the operator actually sees) carries
  the exposure/reach evidence, closing the pod-vs-workload addressing mismatch.
- `targets` is high volume; moving it to the uncapped critical tier
  raises the guaranteed-fetched edge count. This is the deliberate ADR 044
  trade-off (reach correctness over fetch cap) and is bounded by real service
  fan-out. Watch worker memory / `edge_cap_hit` after deploy.

Cites ADR 044 (must-fix reachability + uncapped-reach invariant), 048 (the
graphschema registry these flags live in), 049 (edge freshness, unchanged),
025/026 (graph + BFS lifecycle).
