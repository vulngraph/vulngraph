package iac

import (
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// k8sKindToLiveType maps a manifest kind to the live k8s asset type the
// kubernetes collector emits, so the correlate rule can restrict its
// suffix-join to the right node type.
var k8sKindToLiveType = map[string]string{
	"Deployment":  "k8s_deployment",
	"StatefulSet": "k8s_statefulset",
	"DaemonSet":   "k8s_daemonset",
	"Job":         "k8s_job",
	"Service":     "k8s_service",
}

// ProjectDeclaredK8s turns parsed manifests from one repo into
// declared_k8s_workload assets. It emits NO edges: the manifest carries only a
// cluster-agnostic suffix key (<kind>/<namespace>/<name>), and the join to a
// live cluster asset needs the full inventory, so that happens later in a
// correlate rule (mirroring the DeploysTo collector-supplies / correlate-joins
// split). Each asset's Metadata carries the join inputs: manifest_key (the
// suffix), live_type (the k8s asset type to match against), namespace, repo,
// and the manifest path for provenance.
func ProjectDeclaredK8s(decls []DeclaredK8sWorkload, repo string, now time.Time) []asset.Asset {
	assets := make([]asset.Asset, 0, len(decls))
	for _, d := range decls {
		key := d.SuffixKey()
		assets = append(assets, asset.Asset{
			// Unique per (repo, path, object) — the same workload declared in two
			// files must not collapse to one asset.
			ID:           "declared_k8s_workload:" + repo + ":" + d.Path + ":" + key,
			Name:         d.Name,
			Type:         "declared_k8s_workload",
			DiscoveredAt: now,
			LastSeen:     now,
			Metadata: map[string]string{
				"manifest_key": key,
				"live_type":    k8sKindToLiveType[d.Kind],
				"namespace":    d.Namespace,
				"repo":         repo,
				"path":         d.Path,
			},
		})
	}
	return assets
}
