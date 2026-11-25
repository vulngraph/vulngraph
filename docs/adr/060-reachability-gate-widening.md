# ADR 060: Reachability gate widening — run the internet-hops BFS for network resources

**Status:** accepted (2026-07-15)

## Context

ADR 044 gave enrich a reachability axis: the `InternetReach` source reads the Ladybug
internet-hops BFS (`graphstore/reach.go`) to promote transitively-reachable resources
and strongly demote definitively-unreachable ones. But the source runs only when
`reachabilityMeaningful` (`enrich/sources_reach.go`) says reachability is the dominant
risk driver — and that gate keyed *only* on privesc and internet-exposure check-id/
type strings.

A plain infrastructure misconfiguration — an EC2 in a public subnet, a wide-open
security group, a Lambda — is neither privesc nor an "exposure"/"public" check by
string. So the gate skipped it, even though the internet-hops BFS exists precisely to
reason about those network-addressable asset types. EC2 findings, for example, were
never evaluated for reachability, so the most concrete class of "can an attacker actually reach this?" was dark.

## Decision

Widen `reachabilityMeaningful` to also return true for any finding on a
network-addressable resource type, via `IsNetworkReachableResource` (`mustfix.go`):

```go
func reachabilityMeaningful(f finding.Finding) bool {
    return isPrivesc(f) || isExposure(f) || IsNetworkReachableResource(f.ResourceType)
}
```

`IsNetworkReachableResource` (`internal/app/enrich/mustfix.go`, the authoritative list)
enumerates the asset types the internet-hops BFS exists to reason about: `ec2_instance`,
`gce_instance`, `lambda_function`, `security_group`, `load_balancer`, `rds_instance`, the
k8s workload types (`k8s_pod`, `k8s_service`, `k8s_ingress`,
`k8s_deployment/statefulset/daemonset/job`), and the managed-service producers
`cloud_function`, `cloudsql_instance` and `api_gateway`.
A supply-chain or config-hygiene finding on a non-network resource still doesn't hinge
on a reverse internet path, so those are left alone.

The widening inherits ADR 044's load-bearing invariant unchanged: **absence of
evidence never demotes.** A newly-eligible resource type still contributes nothing
unless the graph actually returns a path — unknown reachability is a no-op
(fail-open), and a definitive-unreachable demotion requires positive `ReachNone`
evidence. So the gate can only *add* a real verdict where there was none; it can never
manufacture a demotion from missing data.

This is Phase 1a of a two-part change and is deliberately kept distinct from ADR 056:

- **ADR 056** added the graph *edges* (`routes_to`/`targets` join the reach set, pod→
  workload exposure propagation) that make k8s reachability actually traversable by
  the BFS. Without those edges an internet-facing ingress dead-ended and k8s resources
  graded unreachable.
- **ADR 060** (this) is the enrich *gate* that decides *when* to run the BFS. Widening
  the gate to k8s types is only meaningful because 056 made the traversal terminate
  correctly; widening it to EC2/SG/Lambda/etc. surfaces a class that was always
  traversable but never evaluated.

## Consequences

- EC2 findings (and the security-group/Lambda/RDS/k8s classes) now get a real
  reachability verdict: internet-reachable ones promote, definitively-internal ones
  demote with the reason shown, and unknown ones are untouched.
- No new scoring math and no new BFS — `InternetReach.Evaluate` and `reach.go` are
  unchanged; this only removes a gate that was excluding the resource types the BFS
  was built for.
- Volume: the reachability lookup now runs for a much larger finding set. It is the
  cached per-node `TryNodeSignals` read (ADR 044), not a per-finding BFS, so the cost
  is a map lookup per finding — bounded and already paid by the graph rebuild.

Cites ADR 044 (must-fix — the reach signal this gate feeds, and the fail-open
invariant), 056 (the k8s reach edges that make k8s traversal terminate; kept distinct —
056 = edges, 060 = the enrich gate), 025/026 (the graph + node-signal cache the BFS
writes to), 010 (layering — enrich reads reachability through the provider interface,
never importing graphstore).
