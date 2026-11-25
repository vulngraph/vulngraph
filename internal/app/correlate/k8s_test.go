package correlate

import (
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestK8sServiceTargets_PublicServiceExposesWorkload(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "c/service/prod/web", Type: "k8s_service", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}},
		{ID: "c/pod/prod/web-1", Type: "k8s_pod",
			Metadata: map[string]string{"namespace": "prod"}, Tags: map[string]string{"app": "web"}},
		{ID: "c/pod/prod/db-1", Type: "k8s_pod",
			Metadata: map[string]string{"namespace": "prod"}, Tags: map[string]string{"app": "db"}},
	})

	edges := K8sServiceTargets{}.Correlate(g)
	var targets, exposed int
	for _, e := range edges {
		switch e.EdgeType {
		case EdgeTargets:
			require.Equal(t, "c/pod/prod/web-1", e.DstID)
			targets++
		case EdgeExposedToInternet:
			require.Equal(t, "c/pod/prod/web-1", e.SrcID)
			require.Equal(t, "k8s_public_service", e.Properties["via"])
			exposed++
		}
	}
	require.Equal(t, 1, targets, "only the app=web pod is selected")
	require.Equal(t, 1, exposed, "selected workload behind a public LB is exposed")
}

func TestK8sServiceTargets_ClusterIPServiceNotExposed(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "c/service/prod/internal", Type: "k8s_service",
			Metadata: map[string]string{"namespace": "prod", "type": "ClusterIP", "selector": "app=web"}},
		{ID: "c/pod/prod/web-1", Type: "k8s_pod",
			Metadata: map[string]string{"namespace": "prod"}, Tags: map[string]string{"app": "web"}},
	})
	for _, e := range (K8sServiceTargets{}).Correlate(g) {
		require.NotEqual(t, EdgeExposedToInternet, e.EdgeType, "ClusterIP service must not expose workloads")
	}
}

func TestK8sServiceTargets_PropagatesExposureToOwnerWorkload(t *testing.T) {
	// A public LoadBalancer selects a pod; the pod is owned by a Deployment.
	// Findings aggregate onto the Deployment, so exposure must reach it too
	// expect a targets edge AND an exposed_to_internet edge on the
	// owning deployment, not only on the pod.
	g := NewGraph([]asset.Asset{
		{ID: "example-cluster/service/prod/web", Type: "k8s_service", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}},
		{ID: "example-cluster/pod/prod/web-abc", Type: "k8s_pod", Region: "example-cluster",
			Metadata: map[string]string{"namespace": "prod", "owner_kind": "Deployment", "owner_name": "web"},
			Tags:     map[string]string{"app": "web"}},
	})
	const ownerID = "example-cluster/deployment/prod/web"

	var podTargeted, ownerTargeted, podExposed, ownerExposed bool
	for _, e := range (K8sServiceTargets{}).Correlate(g) {
		switch {
		case e.EdgeType == EdgeTargets && e.DstID == "example-cluster/pod/prod/web-abc":
			podTargeted = true
		case e.EdgeType == EdgeTargets && e.DstID == ownerID:
			ownerTargeted = true
			require.Equal(t, "k8s_deployment", e.DstType)
		case e.EdgeType == EdgeExposedToInternet && e.SrcID == "example-cluster/pod/prod/web-abc":
			podExposed = true
		case e.EdgeType == EdgeExposedToInternet && e.SrcID == ownerID:
			ownerExposed = true
			require.Equal(t, "k8s_deployment", e.SrcType)
		}
	}
	require.True(t, podTargeted, "pod should be targeted")
	require.True(t, ownerTargeted, "owning deployment should be targeted (reach chain)")
	require.True(t, podExposed, "pod behind public LB should be exposed")
	require.True(t, ownerExposed, "owning deployment should inherit exposure")
}

func TestK8sServiceTargets_OwnerPropagationOnlyForCollectedKinds(t *testing.T) {
	// A bare ReplicaSet owner has no first-class workload asset, so no owner
	// edge is emitted (it would be an unresolvable zombie).
	g := NewGraph([]asset.Asset{
		{ID: "example-cluster/service/prod/web", Type: "k8s_service", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}},
		{ID: "example-cluster/pod/prod/web-abc", Type: "k8s_pod", Region: "example-cluster",
			Metadata: map[string]string{"namespace": "prod", "owner_kind": "ReplicaSet", "owner_name": "web-abc"},
			Tags:     map[string]string{"app": "web"}},
	})
	for _, e := range (K8sServiceTargets{}).Correlate(g) {
		require.NotContains(t, e.DstID, "replicaset", "no edge to a non-collected owner kind")
		if e.EdgeType == EdgeExposedToInternet {
			require.Equal(t, "example-cluster/pod/prod/web-abc", e.SrcID, "only the pod is exposed, no phantom owner")
		}
	}
}

func TestK8sServiceTargets_NamespaceIsolation(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "c/service/prod/web", Type: "k8s_service", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}},
		{ID: "c/pod/staging/web-1", Type: "k8s_pod",
			Metadata: map[string]string{"namespace": "staging"}, Tags: map[string]string{"app": "web"}},
	})
	require.Empty(t, K8sServiceTargets{}.Correlate(g), "selector matches but namespace differs")
}

// TestOwnerWorkloadRef_DerivesClusterFromPodID guards a real-world defect: the
// owner workload id was built from w.Region, but the collector builds workload asset
// ids from the CLUSTER name. Where Region was empty this emitted
// "/deployment/<ns>/<name>" — an id no asset has.
//
// Such edges, all exposed_to_internet and including ingress controllers, were
// rewritten every sweep. They dangle, are pruned at Ladybug load as endpoint_missing, and inflate the drop counters.
// Internet exposure is the single most important signal in the platform; it must never
// be attached to an id that cannot resolve.
func TestOwnerWorkloadRef_DerivesClusterFromPodID(t *testing.T) {
	ownerMeta := func(ns string) map[string]string {
		return map[string]string{"namespace": ns, "owner_kind": "Deployment", "owner_name": "web"}
	}

	t.Run("cluster comes from the pod id, not Region", func(t *testing.T) {
		// Region deliberately disagrees with the pod id's cluster prefix. The pod id
		// wins, because that is what the deployment asset's id was built from.
		pod := asset.Asset{ID: "example-connector-cluster/pod/prod/web-abc", Type: "k8s_pod",
			Region: "somewhere-else", Metadata: ownerMeta("prod")}

		id, typ, ok := ownerWorkloadRef(pod)
		require.True(t, ok)
		require.Equal(t, "example-connector-cluster/deployment/prod/web", id)
		require.Equal(t, "k8s_deployment", typ)
	})

	t.Run("empty Region no longer yields an unprefixed id", func(t *testing.T) {
		pod := asset.Asset{ID: "example-connector-cluster/pod/prod/web-abc", Type: "k8s_pod",
			Region: "", Metadata: ownerMeta("prod")}

		id, _, ok := ownerWorkloadRef(pod)
		require.True(t, ok)
		require.Equal(t, "example-connector-cluster/deployment/prod/web", id)
		require.NotEqual(t, "/deployment/prod/web", id, "this is the orphan id shape the old code produced")
		require.False(t, strings.HasPrefix(id, "/"), "an id starting with / matches no asset")
	})

	t.Run("a pod id with no usable cluster prefix emits nothing", func(t *testing.T) {
		for _, badID := range []string{"/pod/prod/web-abc", "pod/prod/web-abc", "web-abc", ""} {
			_, _, ok := ownerWorkloadRef(asset.Asset{
				ID: badID, Type: "k8s_pod", Metadata: ownerMeta("prod")})
			require.False(t, ok,
				"%q has no cluster prefix — emit no edge rather than a dangling one", badID)
		}
	})
}

func TestClusterPrefixOf(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{"example-connector-cluster/pod/ns/name", "example-connector-cluster", true},
		{"a/b/pod/ns/name", "a/b", true},
		{"/pod/ns/name", "", false}, // empty prefix must be rejected
		{"no-pod-segment", "", false},
		{"", "", false},
	} {
		got, ok := clusterPrefixOf(tc.in)
		require.Equal(t, tc.ok, ok, "input %q", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}
}

// A LoadBalancer limited by loadBalancerSourceRanges, or on a scheme an AWS
// controller chose, is exposed only as possible. When an unrestricted Service
// also selects the workload, the pod and its owner each keep one exposure
// edge, the confirmed one, whatever order the Services are read in.
func TestK8sServiceTargets_SourceRestrictedServiceIsPossible(t *testing.T) {
	pod := asset.Asset{ID: "example-cluster/pod/prod/web-abc", Type: "k8s_pod", Region: "example-cluster",
		Metadata: map[string]string{"namespace": "prod", "owner_kind": "Deployment", "owner_name": "web"},
		Tags:     map[string]string{"app": "web"}}
	lb := func(name, ip string, md map[string]string) asset.Asset {
		m := map[string]string{"namespace": "prod", "type": "LoadBalancer", "selector": "app=web"}
		maps.Copy(m, md)
		return asset.Asset{ID: "example-cluster/service/prod/" + name, Type: "k8s_service", PublicIP: ip, Metadata: m}
	}
	restricted := lb("a-office", "1.2.3.4", map[string]string{"source_restricted": "true", "scheme_assumed": "false"})
	assumed := lb("c-nlb", "nlb.example.com", map[string]string{"source_restricted": "false", "scheme_assumed": "true"})
	open := lb("b-open", "5.6.7.8", map[string]string{"source_restricted": "false", "scheme_assumed": "false"})
	owner := "example-cluster/deployment/prod/web"

	// exposure returns each workload's exposure edges after correlate.dedupe.
	exposure := func(assets ...asset.Asset) map[string][]asset.Edge {
		out := map[string][]asset.Edge{}
		for _, e := range dedupe((K8sServiceTargets{}).Correlate(NewGraph(assets))) {
			if e.EdgeType == EdgeExposedToInternet {
				out[e.SrcID] = append(out[e.SrcID], e)
			}
		}
		return out
	}
	only := func(t *testing.T, got map[string][]asset.Edge, id, tier, service string) {
		t.Helper()
		require.Len(t, got[id], 1, id)
		require.Equal(t, tier, got[id][0].Properties[asset.EdgePropPublicAccess], id)
		require.Equal(t, service, got[id][0].Properties["service"], id)
	}

	for _, svc := range []asset.Asset{restricted, assumed} {
		got := exposure(svc, pod)
		only(t, got, pod.ID, asset.PublicAccessPossible, svc.ID)
		only(t, got, owner, asset.PublicAccessPossible, svc.ID)
	}

	orders := [][]asset.Asset{
		{restricted, assumed, open, pod}, {open, restricted, assumed, pod}, {assumed, open, restricted, pod},
		{pod, open, assumed, restricted}, {restricted, open, pod, assumed},
	}
	for _, order := range orders {
		got := exposure(order...)
		only(t, got, pod.ID, asset.PublicAccessConfirmed, open.ID)
		only(t, got, owner, asset.PublicAccessConfirmed, open.ID)
	}

	// Two possible Services: the same one wins in either order.
	first, second := exposure(restricted, assumed, pod), exposure(assumed, restricted, pod)
	require.Equal(t, first[pod.ID], second[pod.ID])
	require.Equal(t, first[owner], second[owner])
}
