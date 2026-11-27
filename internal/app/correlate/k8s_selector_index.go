package correlate

import "github.com/vulngraph/vulngraph/internal/app/asset"

// Index only label values requested by a service, scoped to its cluster and
// namespace. Entries reference the shared workload slice rather than copying
// assets or indexing unrelated labels.
type workloadSelectorKey struct {
	cluster, namespace, label, value string
}
type workloadSelectorIndex map[workloadSelectorKey][]int

func newWorkloadSelectorIndex(workloads, services []asset.Asset) workloadSelectorIndex {
	index := workloadSelectorIndex{}
	for _, service := range services {
		cluster, ok := namespacedClusterOf(service.ID)
		if !ok {
			continue
		}
		for label, value := range parseSelector(service.Metadata["selector"]) {
			index[workloadSelectorKey{cluster, service.Metadata["namespace"], label, value}] = nil
		}
	}
	if len(index) == 0 {
		return index
	}
	for i, workload := range workloads {
		cluster, ok := namespacedClusterOf(workload.ID)
		if !ok {
			continue
		}
		for label, value := range workload.Tags {
			key := workloadSelectorKey{cluster, workload.Metadata["namespace"], label, value}
			if _, wanted := index[key]; wanted {
				index[key] = append(index[key], i)
			}
		}
	}
	return index
}

// The smallest posting list is a superset of all matches. The caller checks
// every selector term before emitting an edge; a missing term has no matches.
func (index workloadSelectorIndex) candidates(cluster, namespace string, selector map[string]string) []int {
	var smallest []int
	for label, value := range selector {
		candidates := index[workloadSelectorKey{cluster, namespace, label, value}]
		if len(candidates) == 0 {
			return nil
		}
		if smallest == nil || len(candidates) < len(smallest) {
			smallest = candidates
		}
	}
	return smallest
}
