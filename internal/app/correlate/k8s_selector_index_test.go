package correlate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestK8sSelectorIndexPreservesCompleteMatches(t *testing.T) {
	var workloads, services []asset.Asset
	for i := range 1000 {
		cluster, ns := fmt.Sprintf("org/cluster-%d", i%3), fmt.Sprintf("ns-%d", i%7)
		tags := map[string]string{"common": "yes", "app": fmt.Sprint(i % 11)}
		if i%5 == 0 {
			tags["empty"] = ""
		}
		workloads = append(workloads, asset.Asset{ID: fmt.Sprintf("%s/pod/%s/p-%d", cluster, ns, i), Tags: tags, Metadata: map[string]string{"namespace": ns}})
	}
	for i := range 70 {
		cluster, ns := fmt.Sprintf("org/cluster-%d", i%3), fmt.Sprintf("ns-%d", i%7)
		selector := fmt.Sprintf("common=yes,app=%d", i%11)
		if i%3 == 0 {
			selector += ",empty="
		}
		if i%13 == 0 {
			selector += ",missing=no"
		}
		services = append(services, asset.Asset{ID: fmt.Sprintf("%s/service/%s/s-%d", cluster, ns, i), Metadata: map[string]string{"namespace": ns, "selector": selector}})
	}
	index := newWorkloadSelectorIndex(workloads, services)
	for _, service := range services {
		selector := parseSelector(service.Metadata["selector"])
		cluster, _ := namespacedClusterOf(service.ID)
		var want, got []string
		for _, workload := range workloads {
			wc, valid := namespacedClusterOf(workload.ID)
			matches := valid && wc == cluster && workload.Metadata["namespace"] == service.Metadata["namespace"]
			for k, v := range selector {
				value, present := workload.Tags[k]
				matches = matches && present && value == v
			}
			if matches {
				want = append(want, workload.ID)
			}
		}
		candidates := index.candidates(cluster, service.Metadata["namespace"], selector)
		require.LessOrEqual(t, len(candidates), 5, "use the selective label, not every workload in the namespace")
		for _, i := range candidates {
			if labelsMatch(workloads[i].Tags, selector) {
				got = append(got, workloads[i].ID)
			}
		}
		require.Equal(t, want, got, service.ID)
	}
}

func TestK8sSelectorEmptyValueRequiresPresentLabel(t *testing.T) {
	service := asset.Asset{ID: "org/cluster/service/ns/s", Type: "k8s_service", Metadata: map[string]string{"namespace": "ns", "selector": "app="}}
	missing := asset.Asset{ID: "org/cluster/pod/ns/missing", Type: "k8s_pod", Metadata: map[string]string{"namespace": "ns"}}
	present := missing
	present.ID, present.Tags = "org/cluster/pod/ns/present", map[string]string{"app": ""}
	edges := (K8sServiceTargets{}).Correlate(NewGraph([]asset.Asset{service, missing, present}))
	require.Len(t, edges, 1)
	require.Equal(t, present.ID, edges[0].DstID)
}
