package correlate

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// K8sManifestOwnership joins declared_k8s_workload intermediates (parsed from
// plain manifests by the IaC collector, projected by the GitHub collector) to
// the LIVE k8s assets they declare, and emits a file-anchored ownership edge
// (live asset)-[:defined_in]->(github_repo).
//
// The join is cluster-agnostic: a live asset's ID is <cluster>/<kind>/<ns>/<name>
// but a manifest never names the cluster, so the match is on the suffix
// <kind>/<ns>/<name>. One manifest may legitimately deploy to several clusters —
// every live match gets its own edge, and confidence drops to "medium" when >1
// cluster matches or when the manifest omitted the namespace (name-key fallback).
//
// This is higher-confidence and file-anchored, complementing (not duplicating)
// the image/label-heuristic DeploysTo edge (deploys.go): DeploysTo says "CI ships
// this repo here"; defined_in says "this exact object is declared in this file".
type K8sManifestOwnership struct{}

func (K8sManifestOwnership) Name() string { return "k8s_manifest_ownership" }

func (K8sManifestOwnership) InterestedIn() []string {
	return []string{
		"declared_k8s_workload",
		"k8s_deployment", "k8s_statefulset", "k8s_daemonset", "k8s_job",
		"k8s_service",
	}
}

func (K8sManifestOwnership) Correlate(g Graph) []asset.Edge {
	var edges []asset.Edge
	for _, d := range g.DeclaredK8sWorkloads() {
		repoID := d.Metadata["repo"]
		if repoID == "" {
			continue
		}
		matches, confidence := liveMatchesFor(g, d)
		if len(matches) == 0 {
			continue
		}

		for _, m := range matches {
			edges = append(edges, asset.Edge{
				SrcID: m.ID, SrcType: m.Type,
				DstID: repoID, DstType: "github_repo",
				EdgeType: EdgeDefinedIn,
				Properties: map[string]string{
					"origin":     edgeOrigin,
					"rule":       "k8s_manifest_ownership",
					"confidence": confidence,
					"provenance": "iac_manifest",
					"path":       d.Metadata["path"],
				},
			})
		}
	}
	return edges
}

// driftDeclaredNotLive is the metadata value CorrelateAssets stamps on a
// declared_k8s_workload with zero live matches (the drift model: "a
// signal on the asset, not a hard finding" — an orphaned manifest has no
// live node to anchor a defined_in edge to, so it can't be surfaced as one).
const driftDeclaredNotLive = "declared_not_live"

// CorrelateAssets annotates declared_k8s_workload assets with a `drift`
// metadata signal: "declared_not_live" when the manifest currently resolves
// to zero live k8s assets (orphaned manifest, or not yet deployed to any
// cluster we see). The annotation is cleared (re-ingested without it) if a
// live match later appears, and left untouched when nothing changed, so a
// full sweep only re-ingests the assets whose drift status actually flipped.
func (K8sManifestOwnership) CorrelateAssets(g Graph) []asset.Asset {
	var out []asset.Asset
	for _, d := range g.DeclaredK8sWorkloads() {
		matches, _ := liveMatchesFor(g, d)
		hasDrift := d.Metadata["drift"] == driftDeclaredNotLive

		switch {
		case len(matches) > 0 && hasDrift:
			out = append(out, withMetadata(d, "drift", "")) // resolved — clear the signal
		case len(matches) == 0 && !hasDrift:
			out = append(out, withMetadata(d, "drift", driftDeclaredNotLive))
		}
	}
	return out
}

// withMetadata returns a copy of d whose Metadata is the single-key map
// {key: value} — the write-back INTENT only, not a copy of d's (partial,
// correlation-view) metadata. writeAnnotations merges this one key onto the
// asset's authoritative full row; a full-map copy here would re-inject
// every key the correlation view happened to load, silently regressing any
// key this rule never intended to touch. An empty value signals "delete
// this key", by the same "" -means-absent convention used throughout this
// package. d itself is never mutated — it is shared by every rule in the
// sweep via the Graph.
func withMetadata(d asset.Asset, key, value string) asset.Asset {
	d.Metadata = map[string]string{key: value}
	return d
}

// liveMatchesFor resolves the live k8s assets a declared workload's manifest
// key joins to, and the confidence of that match. Shared by Correlate (which
// emits a defined_in edge per match) and CorrelateAssets (which flags drift
// when there are none).
func liveMatchesFor(g Graph, d asset.Asset) (matches []asset.Asset, confidence string) {
	key := d.Metadata["manifest_key"]
	liveType := d.Metadata["live_type"]
	ns := d.Metadata["namespace"]

	var candidates []asset.Asset
	nsAgnostic := ns == ""
	if nsAgnostic {
		// Manifest omitted the namespace — fall back to the <kind>/<name> key.
		candidates = g.LiveK8sByNameKey(nameKeyFromSuffix(key))
	} else {
		candidates = g.LiveK8sBySuffix(key)
	}
	if len(candidates) == 0 {
		return nil, ""
	}

	// Defensive type check: the manifest_key's kind segment should already
	// agree with live_type, but a declared object never gets an edge to a
	// live asset of a different kind (e.g. a Service manifest must not
	// join a Deployment that happens to share namespace/name).
	matches = make([]asset.Asset, 0, len(candidates))
	for _, c := range candidates {
		if c.Type == liveType {
			matches = append(matches, c)
		}
	}
	if len(matches) == 0 {
		return nil, ""
	}

	// Confidence: exact single-cluster match is "high"; >1 cluster or a
	// namespace-agnostic fallback is "medium". Cluster is derived from the
	// first segment of the live asset's ID (<cluster>/<kind>/<ns>/<name>),
	// not m.Region, since the correlate LoadView SELECT never scans region.
	clusters := map[string]bool{}
	for _, m := range matches {
		clusters[clusterFromID(m.ID)] = true
	}
	confidence = "high"
	if nsAgnostic || len(clusters) > 1 {
		confidence = "medium"
	}
	return matches, confidence
}

// nameKeyFromSuffix turns a "<kind>/<ns>/<name>" suffix key into the
// namespace-agnostic "<kind>/<name>" name key.
func nameKeyFromSuffix(suffix string) string {
	parts := strings.SplitN(suffix, "/", 3)
	if len(parts) != 3 {
		return suffix
	}
	return parts[0] + "/" + parts[2]
}

// clusterFromID returns the cluster segment of a live k8s asset ID
// (<cluster>/<kind>/<ns>/<name>) — the first "/"-delimited segment. Falls
// back to the whole ID if it isn't slash-delimited.
func clusterFromID(id string) string {
	if i := strings.IndexByte(id, '/'); i >= 0 {
		return id[:i]
	}
	return id
}
