package kubernetes

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// The chart's opt-in collector ClusterRole (kubernetesRBAC.collectorRead) grants
// list on every resource realK8s and the cert-manager read list, and nothing a
// read-only inventory does not need. A resource read here but missing from the
// grant fails the sync with Forbidden on a fresh install.
func TestCollectorChartRBACMatchesReads(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/helm-chart/graph/templates/kubernetes-collector-rbac.yaml")
	require.NoError(t, err)
	tpl := string(raw)

	for _, rule := range []string{
		`apiGroups: [""]`,
		`resources: ["namespaces", "pods", "services", "serviceaccounts", "configmaps"]`,
		`apiGroups: ["apps"]`,
		`resources: ["deployments", "statefulsets", "daemonsets"]`,
		`apiGroups: ["batch"]`,
		`resources: ["jobs"]`,
		`apiGroups: ["rbac.authorization.k8s.io"]`,
		`resources: ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]`,
		`apiGroups: ["networking.k8s.io"]`,
		`resources: ["ingresses", "networkpolicies"]`,
		`apiGroups: ["` + certGVR.Group + `"]`,
		`resources: ["` + certGVR.Resource + `"]`,
		`nonResourceURLs: ["` + openIDConfigurationPath + `"]`,
	} {
		require.Contains(t, tpl, rule)
	}
	require.NotContains(t, tpl, "secrets", "the collector never reads Secrets")
	require.NotContains(t, tpl, `"*"`)
	for _, verb := range []string{"watch", "create", "update", "patch", "delete"} {
		require.NotContains(t, tpl, `"`+verb+`"`)
	}
}
