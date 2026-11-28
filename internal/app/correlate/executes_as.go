package correlate

import (
	"iter"
	"slices"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// EdgeExecutesAs links a workload (lambda_function, gce_instance, ecs_service, …)
// to the IAM identity it runs as. Combined with can_assume / has_role, this is
// the missing hop that makes an attack chain traversable in one query:
// internet → exposed workload -[executes_as]-> role -[can_assume]-> admin.
const EdgeExecutesAs = "executes_as"

// ExecutesAs emits a workload -[executes_as]-> principal edge for every asset
// that declares the identity it runs as (Metadata["exec_role"], set by the
// collectors to the target principal's node ID — a role ARN for AWS, a
// "serviceAccount:<email>" for GCP). The edge is only emitted when the target
// principal is actually in inventory, so there are no dangling stubs.
type ExecutesAs struct{}

func (ExecutesAs) Name() string { return "executes_as" }

func (ExecutesAs) InterestedIn() []string {
	return []string{
		"lambda_function", "gce_instance", "ecs_service", "cloud_function",
		"cloudrun_service", // Cloud Run — exec_role populated by the collector
		// k8s_service_account carries its IRSA role annotation as exec_role
		// (collect/kubernetes/rbac.go), so an annotation change must recompute.
		"k8s_pod", "k8s_deployment", "k8s_service_account", "azure_webapp", "azure_function", "azure_vm",
		"iam_role", "gcp_service_account", "azure_service_principal", "azure_managed_identity",
	}
}

func (r ExecutesAs) Correlate(g Graph) []asset.Edge { return slices.Collect(r.Edges(g)) }

func (ExecutesAs) Edges(g Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {

		for _, w := range g.ExecWorkloads() {
			target := w.Metadata["exec_role"]
			if target == "" || target == w.ID || !g.IsPrincipal(target) {
				continue
			}
			if !yield(asset.Edge{
				SrcID: w.ID, SrcType: w.Type,
				DstID: target, DstType: principalDstType(target),
				EdgeType: EdgeExecutesAs,
				Properties: map[string]string{
					"origin": edgeOrigin,
					"rule":   "executes_as",
				},
			}) {
				return
			}
		}
	}
}

// principalDstType labels the edge's destination. GCP service-account node IDs
// are prefixed "serviceAccount:"; everything else is an IAM role ARN.
func principalDstType(id string) string {
	if len(id) >= 15 && id[:15] == "serviceAccount:" {
		return "gcp_service_account"
	}
	return "iam_role"
}
