package graphstore

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// The ServiceAccount half of every K8s RBAC chain must survive the load. binds
// from a ServiceAccount source has to reroute to BindsK8sWorkload, because
// k8s_service_account is K8sWorkload-labeled while the default Binds table
// is Asset→Asset — so every SA→ClusterRoleBinding row was silently dropped at
// COPY, leaving each ClusterRole apparently bound to nobody. Same label-mismatch
// bug class as executes_as, defined_in and targets.
func TestBindsFromServiceAccountReroutesToK8sWorkloadTable(t *testing.T) {
	rows := buildEdgeRows([]asset.Edge{
		// ServiceAccount → ClusterRoleBinding: K8sWorkload-labeled source.
		{SrcID: "c1/namespace/team/serviceaccount/app", SrcType: "k8s_service_account",
			DstID: "c1/clusterrolebinding/b", DstType: "k8s_cluster_role_binding", EdgeType: "binds"},
		// ClusterRoleBinding → ClusterRole: both generic Asset, stays on Binds.
		{SrcID: "c1/clusterrolebinding/b", SrcType: "k8s_cluster_role_binding",
			DstID: "c1/clusterrole/r", DstType: "k8s_cluster_role", EdgeType: "binds"},
	})

	require.Len(t, rows[RelBindsK8sWorkload].rows, 1,
		"the ServiceAccount-sourced binds edge must route to the K8sWorkload table")
	require.Len(t, rows[RelBinds].rows, 1,
		"the binding→role edge stays on the Asset→Asset table")
}
