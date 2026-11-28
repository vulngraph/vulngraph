package correlate

import (
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// EdgeTargets links a k8s_service to the workloads its selector matches.
const EdgeTargets = "targets"

// aggregatableOwnerKinds are the pod-owner kinds collected as first-class k8s
// workload assets (kubernetes.go). It MUST match checks.workloadAggregator's
// set: per-pod findings collapse onto the owning workload's ID, so exposure has
// to reach that same workload node or the aggregated finding looks unreachable.
// A bare-ReplicaSet owner has no asset, so we do not propagate to it.
var aggregatableOwnerKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true,
}

// K8sServiceTargets links a Kubernetes Service to the workloads it selects (same
// namespace, workload labels ⊇ the service selector) and — when the Service is
// a public LoadBalancer — marks those workloads exposed_to_internet. This is the
// last hop of the supply-chain → cloud path: a vulnerable package in a repo that
// deploys_to a workload fronted by a public Service is genuinely internet-reachable.
//
// Services select pods, not the owning Deployment, so exposure edges land on
// the matched pod. But per-pod findings aggregate onto the owning workload
// (checks.workloadAggregator), whose node then carries no exposure/targets
// edge and reads as unreachable even when its pods are internet-facing. To
// keep exposure attached to the node the finding actually points at, every
// service→pod edge is mirrored onto the pod's owning workload.
type K8sServiceTargets struct{}

func (K8sServiceTargets) Name() string { return "k8s_service_targets" }

func (K8sServiceTargets) InterestedIn() []string {
	return []string{"k8s_service", "k8s_pod", "k8s_deployment"}
}

func (r K8sServiceTargets) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (K8sServiceTargets) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		workloads := g.Workloads()
		index := newWorkloadSelectorIndex(workloads, g.K8sServices())
		// Retain one winner per workload, bounded by the input context rather than
		// service/workload fanout. Targets are emitted before this map can grow.
		exposed := map[string]asset.Edge{}
		var exposureOrder []string
		addExposure := func(e asset.Edge) {
			current, seen := exposed[e.SrcID]
			switch {
			case !seen:
				exposureOrder = append(exposureOrder, e.SrcID)
				exposed[e.SrcID] = e
			case betterExposure(e, current):
				exposed[e.SrcID] = e
			}
		}
		for _, svc := range g.K8sServices() {
			selector := parseSelector(svc.Metadata["selector"])
			if len(selector) == 0 {
				continue // a selector-less service (e.g. ExternalName) targets nothing
			}
			ns := svc.Metadata["namespace"]
			cluster, ok := namespacedClusterOf(svc.ID)
			if !ok {
				continue // cannot tell which cluster's pods it selects
			}
			public := svc.PublicIP != "" && svc.Metadata["type"] == "LoadBalancer"
			tier := k8sServiceTier(svc)
			targetedOwners := map[string]bool{} // owner IDs already given a targets edge from THIS service

			for _, i := range index.candidates(cluster, ns, selector) {
				w := workloads[i]
				if !labelsMatch(w.Tags, selector) {
					continue
				}
				if !yield(targetsEdge(svc.ID, w.ID, w.Type)) {
					return
				}
				if public {
					addExposure(exposureEdge(w, "k8s_public_service", tier, map[string]string{
						"service": svc.ID,
					}))
				}

				ownerID, ownerType, ok := ownerWorkloadRef(w)
				if !ok {
					continue // not a pod, or owner not collected as a workload asset
				}
				if !targetedOwners[ownerID] {
					targetedOwners[ownerID] = true
					if !yield(targetsEdge(svc.ID, ownerID, ownerType)) {
						return
					}
				}
				if public {
					addExposure(exposureEdge(asset.Asset{ID: ownerID, Type: ownerType}, "k8s_public_service", tier, map[string]string{
						"service": svc.ID,
						"via_pod": w.ID,
					}))
				}
			}
		}
		for _, id := range exposureOrder {
			if !yield(exposed[id]) {
				return
			}
		}
	}
}

// k8sServiceTier grades a public LoadBalancer Service's exposure. It is
// possible when loadBalancerSourceRanges admit only specific clients (the
// address is off the open internet wherever the provider enforces them), or
// when an AWS controller chose the scheme and the Service does not say which.
func k8sServiceTier(svc asset.Asset) string {
	if svc.Metadata["source_restricted"] == "true" || svc.Metadata["scheme_assumed"] == "true" {
		return asset.PublicAccessPossible
	}
	return asset.PublicAccessConfirmed
}

// betterExposure reports whether exposure edge e should replace cur for the
// same workload: a confirmed tier beats a possible one, and between equal
// tiers the lower service, then pod, ID wins so the choice is stable.
func betterExposure(e, cur asset.Edge) bool {
	eConf := e.Properties[asset.EdgePropPublicAccess] == asset.PublicAccessConfirmed
	curConf := cur.Properties[asset.EdgePropPublicAccess] == asset.PublicAccessConfirmed
	if eConf != curConf {
		return eConf
	}
	if e.Properties["service"] != cur.Properties["service"] {
		return e.Properties["service"] < cur.Properties["service"]
	}
	return e.Properties["via_pod"] < cur.Properties["via_pod"]
}

// targetsEdge builds a service→workload targets edge (k8s_service → pod/workload).
func targetsEdge(svcID, dstID, dstType string) asset.Edge {
	return asset.Edge{
		SrcID: svcID, SrcType: "k8s_service",
		DstID: dstID, DstType: dstType,
		EdgeType:   EdgeTargets,
		Properties: map[string]string{"origin": edgeOrigin, "rule": "k8s_service_targets"},
	}
}

// ownerWorkloadRef returns the (id, type) of the workload owning a pod, derived
// from the pod's owner_kind/owner_name/namespace metadata. The ID format mirrors
// the collected workload asset ID and checks.workloadAggregator exactly
// ("<cluster>/<kind>/<ns>/<name>"), so the propagated edge lands on the node the
// aggregated finding is addressed to. ok is false for non-pods and owner kinds
// with no first-class workload asset (e.g. a bare ReplicaSet).
func ownerWorkloadRef(w asset.Asset) (id, typ string, ok bool) {
	if w.Type != "k8s_pod" {
		return "", "", false
	}
	kind, name := w.Metadata["owner_kind"], w.Metadata["owner_name"]
	if name == "" || !aggregatableOwnerKinds[kind] {
		return "", "", false
	}
	lower := strings.ToLower(kind)
	// Take the cluster prefix from the pod's OWN id rather than re-deriving it
	// from w.Region: Region is not guaranteed to hold the cluster name, and an
	// owner id built from an empty one matches no asset. Deriving the prefix
	// from the pod id makes the owner id share one source of truth with the
	// asset it must match.
	cluster, ok := clusterPrefixOf(w.ID)
	if !ok {
		// No usable prefix: emit nothing rather than an edge pointing at an id that
		// cannot resolve. A missing edge is visible in coverage; a dangling one is not.
		return "", "", false
	}
	id = fmt.Sprintf("%s/%s/%s/%s", cluster, lower, w.Metadata["namespace"], name)
	return id, "k8s_" + lower, true
}

// clusterPrefixOf returns the cluster segment of a k8s pod id — everything before
// "/pod/". Empty prefix is rejected: an id starting with "/" matches no asset.
func clusterPrefixOf(podID string) (string, bool) {
	i := strings.Index(podID, "/pod/")
	if i <= 0 {
		return "", false
	}
	return podID[:i], true
}

// namespacedClusterOf returns the cluster segment of a namespaced k8s asset id
// ("<cluster>/<kind>/<namespace>/<name>"). The cluster is taken as everything
// before the last three segments because it may itself contain "/" (an EKS
// cluster ARN does).
func namespacedClusterOf(id string) (string, bool) {
	end := len(id)
	for range 3 {
		i := strings.LastIndex(id[:end], "/")
		if i <= 0 {
			return "", false
		}
		end = i
	}
	return id[:end], true
}

// parseSelector turns a "k=v,k2=v2" selector string back into a label map.
func parseSelector(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := map[string]string{}
	for pair := range strings.SplitSeq(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && k != "" {
			out[k] = v
		}
	}
	return out
}

// labelsMatch reports whether every selector label is present (with the same
// value) in the workload's labels — Kubernetes service-selection semantics.
func labelsMatch(labels, selector map[string]string) bool {
	for k, v := range selector {
		if value, present := labels[k]; !present || value != v {
			return false
		}
	}
	return true
}
