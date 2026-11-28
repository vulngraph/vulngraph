package correlate

import (
	"iter"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// defaultServiceAccountName is the ServiceAccount a pod runs under when its spec
// names none. The collector copies spec.ServiceAccountName verbatim, and the API
// server leaves it empty on pods that never set it, so the default has to be
// applied here or every such pod loses its identity edge.
const defaultServiceAccountName = "default"

// K8sPodServiceAccount links a running pod to the in-cluster ServiceAccount it
// executes as. This closes the one hop that both RBAC (ServiceAccount
// -[binds]-> (Cluster)RoleBinding -[binds]-> Role) and IRSA/GKE WIF
// (ServiceAccount -[federated_access]-> cloud role) sit behind: without it,
// nothing could say that a compromised pod reaches either chain.
//
// # Why executes_as rather than a new edge type
//
// executes_as means "workload runs under this identity", which is exactly what a
// ServiceAccount is to a pod, and it is already a Reach type in the uncapped
// critical tier — an internet-exposed pod propagates hops into its
// ServiceAccount and from there across binds into the RBAC privileges it
// actually holds. A new edge type would have needed its own tier, weight and
// Reach decision to arrive at the same three values.
//
// Both endpoints promote to the K8sWorkload node label, so graphstore reroutes
// these rows to ExecutesAsK8sServiceAccount (K8sWorkload→K8sWorkload); the
// default ExecutesAs table is Asset→IamRole and would silently discard every one
// of them.
//
// # Why nothing is emitted for an uncollected ServiceAccount
//
// Same reasoning as IRSATrust: the edge is only emitted when the ServiceAccount
// is a real asset. A synthesised SA node would be permanently dangling and
// would buy no reachability, since a cluster whose ServiceAccounts are dark has
// dark pods too — this self-completes with no code change as clusters come
// online.
type K8sPodServiceAccount struct{}

func (K8sPodServiceAccount) Name() string { return "k8s_pod_service_account" }

func (K8sPodServiceAccount) InterestedIn() []string {
	return []string{"k8s_pod", "k8s_service_account"}
}

func (r K8sPodServiceAccount) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (K8sPodServiceAccount) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		sas := g.K8sServiceAccounts()
		if len(sas) == 0 {
			return
		}
		byID := make(map[string]bool, len(sas))
		for _, sa := range sas {
			byID[sa.ID] = true
		}

		for _, w := range g.Workloads() {
			// Pods only. A Deployment's spec.template carries a ServiceAccount too, but
			// the collector does not record it, and inferring the parent's identity from
			// its pods would invert the direction this edge is meant to run in.
			if w.Type != "k8s_pod" {
				continue
			}
			saID, ok := serviceAccountIDFor(w)
			if !ok || !byID[saID] {
				continue
			}
			if !yield(asset.Edge{
				SrcID: w.ID, SrcType: "k8s_pod",
				DstID: saID, DstType: "k8s_service_account",
				EdgeType: EdgeExecutesAs,
				Properties: map[string]string{
					"origin": edgeOrigin,
					"rule":   "k8s_pod_service_account",
				},
			}) {
				return
			}
		}
	}
}

// serviceAccountIDFor rebuilds the ID the kubernetes collector gives the
// ServiceAccount a pod runs under: "<cluster>/namespace/<ns>/serviceaccount/<name>"
// (collect/kubernetes/rbac.go serviceAccountAsset). The cluster comes from the
// pod's own ID via clusterPrefixOf, not pod.Region: this package's correlation
// view (repo.go's loadView/loadByIDs) never selects the region column at all, so
// pod.Region is "" for every asset in every Graph this rule ever sees.
func serviceAccountIDFor(pod asset.Asset) (string, bool) {
	cluster, ok := clusterPrefixOf(pod.ID)
	if !ok {
		return "", false
	}
	ns := strings.TrimSpace(pod.Metadata["namespace"])
	if ns == "" {
		ns = "default"
	}
	name := strings.TrimSpace(pod.Metadata["service_account"])
	if name == "" {
		name = defaultServiceAccountName
	}
	return cluster + "/namespace/" + ns + "/serviceaccount/" + name, true
}
