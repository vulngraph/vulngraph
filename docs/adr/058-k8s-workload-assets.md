# ADR 058: Kubernetes workload assets — StatefulSet, DaemonSet, Job

**Status:** accepted (2026-07-14)

## Context

Checks generate findings against every Kubernetes workload kind, but the collector
only ever inventoried Deployments as first-class assets. The other controller kinds
were never listed, so findings on `k8s_statefulset`, `k8s_job` and
`k8s_daemonset` had no `graph.assets` row to anchor to. An orphaned finding has no attack-path scoring seed, no
lifecycle-sweep asset to auto-resolve against (ADR 054), and no UI drill-down target.

The findings were themselves a lifecycle artifact. `checks.workloadAggregator`
collapses per-pod findings onto their owning workload (pods are replicas of one
template, so a per-pod finding just multiplies one misconfiguration by the replica
count). An earlier revision aggregated onto *any* owner kind; a later one restricted
aggregation to Deployment-owned pods precisely because the other three kinds had no
collected asset to resolve against — leaving those findings addressed to workloads
that did not exist as assets.

## Decision

Collect StatefulSet, DaemonSet, and Job as first-class assets and let the aggregator
resolve to them.

- **`internal/collect/kubernetes/workloads.go`** adds `statefulSetAsset`,
  `daemonSetAsset`, and `jobAsset` alongside the existing `deploymentAsset`, wired
  into `Collect()` via new `k8sAPI` list methods. All four share one ID scheme —
  `"<cluster>/<lowercase kind>/<namespace>/<name>"` — which is load-bearing, not
  incidental: `checks.workloadAggregator` rebuilds that exact string from a pod's
  `owner_kind`/`owner_name`/`namespace` metadata to re-address an aggregated per-pod
  finding at its owning workload. The kinds carry kind-appropriate status metadata
  (replica counts for StatefulSet, `DesiredNumberScheduled`/`NumberAvailable` for
  DaemonSet, active/succeeded/failed pod counts for Job, which has no replica count).

- **`internal/checks/checks.go`** widens `workloadAggregator.absorb`'s
  `aggregatableOwnerKinds` from Deployment-only to
  `{Deployment, StatefulSet, DaemonSet, Job}` — the four kinds now collected as
  assets. Aggregation stays restricted to exactly those kinds on purpose: a bare
  ReplicaSet owner has no collected asset, so an aggregated finding there would be
  an unresolvable zombie (no drill-down, and the lifecycle reconcile — which only
  sees collected asset IDs — could never auto-resolve it). Those stay per-pod.

- **`internal/app/graphstore/domain.go`** maps `k8s_job` into `assetTypeToNode`
  (→ `NodeK8sWorkload`), joining the already-present `k8s_daemonset`/
  `k8s_statefulset` mappings, and bumps `SchemaVersion` to force a Ladybug
  rebuild rather than load a snapshot from before these workload kinds existed in
  the graph. No DDL change.

No Deployment→Pod ownership edge exists in `graphschema` to mirror for the new
kinds, so none was added — a speculative edge type with no existing analog would
add a relationship nothing consumes.

## Consequences

- StatefulSet/DaemonSet/Job findings anchor to a real asset: attack-path scoring
  seed, lifecycle auto-resolution, and UI drill-down all work for them.
- Per-workload finding collapse now applies to all four controller kinds, so
  previously orphaned findings become a bounded per-workload set instead of per-pod
  noise.
- Ships additively and takes effect on the next k8s collection cycle; the collector
  change is exercised against fixtures.

Cites ADR 054 (finding lifecycle — the sweep that needs a collected asset ID),
048 (the graphschema registry checked for a mirror edge), 025/026 (graph + node
lifecycle the SchemaVersion bump gates), 031 (Kubernetes as an inventory source).
