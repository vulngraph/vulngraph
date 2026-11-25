# ADR 072 — A cluster's identity is discovered, not configured

**Status:** accepted (implemented 2026-08-05)

## Context

Every Kubernetes asset ID is prefixed with the k8s connector's `cfg["cluster_name"]`,
defaulting to the literal `"in-cluster"` (`internal/collect/kubernetes/client.go`). Nothing
compares that operator-typed string with the cluster actually being collected, and it can
easily differ from the name the cloud provider uses for the same cluster.

Two joins assume the prefix is the cloud provider's cluster name, and both fail silently when
it is not:

- any reconciliation of cloud cluster inventory (`eks_cluster` / `gke_cluster`) against
  collected Kubernetes workloads — a name join reports every cluster as having no workloads,
  including the one being collected;
- the GuardDuty EKS container join, which builds
  `"<EksClusterDetails.Name>/pod/<ns>/<pod>/container/<name>"` and whose source comment
  concedes it only resolves if `cfg["cluster_name"]` is set to the real EKS cluster name.

"Configure it correctly" is not a remedy; it is the failure mode. A recurring defect class in
this codebase is a knob nobody sets and nothing checks (METRICS_PORT, IMAGE_SCAN_ROOT,
`scan_profiles`).

## Decision

**The cluster states its own identity; configuration supplies a label.**

1. The collector reads the API server's OpenID discovery document
   (`/.well-known/openid-configuration`) and takes its `issuer`. That string is already emitted
   on the cloud side, so the join is exact string equality:

   | provider | issuer | joins to |
   |---|---|---|
   | EKS | `https://oidc.eks.<region>.amazonaws.com/id/<id>` | `eks_cluster.metadata["oidc_issuer"]` (`collect/aws/eks.go`) |
   | GKE | `https://container.googleapis.com/v1/projects/<p>/locations/<l>/clusters/<c>` | `<p>/gke/<l>/<c>` — the `gke_cluster` asset ID (`collect/gcp/gke.go`) |

2. One `k8s_cluster` asset per sweep publishes it: `configured_name`, `oidc_issuer`,
   `kube_system_uid` (a rename-proof cluster fingerprint, taken from the namespace list already
   fetched), and the derived `cloud_provider`, `discovered_name`, `cloud_cluster_id`. Every
   derived key is omitted when not observed — the collector convention the checks depend on.

3. The disagreement is a finding: `k8s-cluster-identity-mismatch` fires when the cluster states
   a name that is not the configured one. An undiscovered name is unknown, never a mismatch, so
   it cannot fire across an estate because of a permission gap.

4. **Asset IDs keep using the configured name.** Re-keying on the discovered name would make
   all existing Kubernetes assets look deleted in one sweep (ADR 054 prune plus auto-resolution
   of every open k8s finding), then recreate them under new IDs — and would repeat on the next
   rename. Identity is published as a property to join on, not promoted to a primary key.

## Consequences

- Cluster-inventory reconciliation gets a key no configuration can break. It has to run where
  both connectors' assets are visible (correlate, or a job reading ClickHouse); the check
  registry evaluates one connector's assets at a time and cannot express the join.
- The GuardDuty EKS container join is not fixed by this ADR: an EKS issuer carries an opaque
  id, not the cluster name, so the name cannot be recovered from inside the cluster. Resolving
  it needs the issuer↔`eks_cluster` join from a cross-connector reader. What changed is that
  the dependency is now observed and published instead of assumed.
- A failed issuer read is not `result.Partial`: one unobserved metadata key must not disable
  deletion reconciliation for the whole connector.
- New asset type `k8s_cluster` (one row per cluster). It is not in `asset.NeverSyncTypes`, so it
  becomes one generic Ladybug `Asset` node per cluster; add it there if that node is unwanted.
