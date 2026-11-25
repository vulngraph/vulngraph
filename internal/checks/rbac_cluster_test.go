package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// privilegedRoleRef was applied to two of its three call sites. The one it was
// left off is k8s-default-service-account-bound — the CLUSTER-scoped, and
// therefore higher-blast-radius, twin of the RoleBinding check that did get the
// gate. Its own Description says "binds a PRIVILEGED role"; without the gate it
// fired on any ClusterRoleBinding naming ServiceAccount/default, including the
// read-only `view` ClusterRole, which is not a privilege-escalation path.
//
// Typical ClusterRoleBindings naming ServiceAccount/default are silenced — one
// binding the built-in `view` role (platform_managed, read-only), another a
// Helm-chart-managed role whose single rule is pods: get/watch/list. Neither is
// a true positive; the check stays armed for the cases it was written for.
func TestK8sDefaultServiceAccountBoundRequiresPrivilege(t *testing.T) {
	crb := func(md map[string]string) asset.Asset {
		return asset.Asset{
			ID: "crb-1", Type: "k8s_cluster_role_binding",
			Provider: asset.ProviderKubernetes, Metadata: md,
		}
	}
	tests := []struct {
		name string
		md   map[string]string
		want bool
	}{
		{"cluster-admin bound to default SA", map[string]string{
			"role_ref": "cluster-admin", "subjects": "ServiceAccount/default"}, true},
		{"admin bound to default SA", map[string]string{
			"role_ref": "admin", "subjects": "ServiceAccount/default"}, true},
		{"edit bound to default SA", map[string]string{
			"role_ref": "edit", "subjects": "ServiceAccount/default"}, true},
		{"collector-graded dangerous role bound to default SA", map[string]string{
			"role_ref": "custom-secret-reader", "dangerous_perms": "true",
			"subjects": "ServiceAccount/default"}, true},
		{"collector-graded wildcard role bound to default SA", map[string]string{
			"role_ref": "custom-wildcard", "wildcard_verbs": "true",
			"subjects": "ServiceAccount/default"}, true},

		// The typical benign pair, both silenced.
		{"read-only view bound to default SA", map[string]string{
			"role_ref": "view", "subjects": "ServiceAccount/default"}, false},
		{"ungraded custom role bound to default SA", map[string]string{
			"role_ref": "helm-managed-role", "dangerous_perms": "false",
			"wildcard_verbs": "false", "subjects": "ServiceAccount/default"}, false},

		// The pre-existing exact-match guard must survive the new gate.
		{"privileged role bound to default-backend", map[string]string{
			"role_ref": "cluster-admin", "subjects": "ServiceAccount/default-backend"}, false},
		{"privileged role bound to a named SA", map[string]string{
			"role_ref": "cluster-admin", "subjects": "ServiceAccount/prometheus"}, false},
		{"no subjects observed at all", map[string]string{"role_ref": "cluster-admin"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, k8sDefaultServiceAccountBound.Violates(crb(tt.md)))
		})
	}
}

// The gate must behave identically on both binding types — the whole point of
// the fix is that the two siblings agree. A namespaced RoleBinding naming the
// same read-only role is silent for the same reason.
func TestDefaultSAChecksAgreeAcrossScopes(t *testing.T) {
	md := map[string]string{"role_ref": "view", "role_ref_kind": "ClusterRole", "subjects": "ServiceAccount/default"}
	cluster := asset.Asset{ID: "crb", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes, Metadata: md}
	namespaced := asset.Asset{ID: "rb", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes, Metadata: md}
	require.False(t, k8sDefaultServiceAccountBound.Violates(cluster))
	require.False(t, k8sRoleBindingDefaultServiceAccountBound.Violates(namespaced))

	md["role_ref"] = "cluster-admin"
	require.True(t, k8sDefaultServiceAccountBound.Violates(cluster))
	require.True(t, k8sRoleBindingDefaultServiceAccountBound.Violates(namespaced))
}

// Cluster-wide RBAC grants are posture, not alerts: a permission set or a
// cluster-admin binding is graded Low/Medium, and urgency comes from who holds
// it (the must-fix classifier's external-subject reading). In a production org
// every equivalent CSPM issue (984) was excepted at High/Critical. No RBAC
// capability check or binding check may exceed Medium.
func TestK8sRBACGrantsArePostureSeverity(t *testing.T) {
	for _, c := range []Check{k8sRBACSecretsAccess, k8sRBACPodCreate, k8sRBACPodExec, k8sRBACPVCreate,
		k8sRBACNodeProxy, k8sRBACCSRApprove, k8sRBACWebhookConfig, k8sRBACTokenCreate, k8sRBACEscalate,
		k8sClusterAdminBinding, k8sClusterRoleBindingAdminEdit, k8sBindingSystemMasters,
		k8sBindingToUnauthenticated, k8sBindingToAuthenticated} {
		require.LessOrEqual(t, severityRank(c.Severity), severityRank(finding.SeverityMedium), c.ID)
		if c.ID == k8sClusterAdminBinding.ID {
			continue // its grade only ever LOWERS a platform-shipped binding to Info, below
		}
		require.Nil(t, c.SeverityFor, "%s: a per-asset grade could lift it past posture", c.ID)
	}
	for _, pm := range []string{"true", "false"} {
		got := k8sClusterAdminBinding.SeverityFor(asset.Asset{Metadata: map[string]string{"platform_managed": pm}})
		require.LessOrEqual(t, severityRank(got), severityRank(finding.SeverityMedium))
	}

	crb := asset.Asset{ID: "crb", Type: "k8s_cluster_role_binding", Provider: asset.ProviderKubernetes,
		Metadata: map[string]string{"role_ref": "cluster-admin", "subjects": "User/alice", "platform_managed": "false"}}
	f, ok := k8sClusterAdminBinding.eval(crb, fixedTime)
	require.True(t, ok)
	require.Equal(t, finding.SeverityMedium, f.Severity)
}

// A namespace-scoped admin/edit grant never outranks the same grant
// cluster-wide: both are posture, and the must-fix classifier decides urgency
// from their subjects.
func TestK8sNamespacedRBACGrantsNeverOutrankClusterWide(t *testing.T) {
	for _, ref := range []string{"cluster-admin", "admin", "edit"} {
		rb := asset.Asset{ID: "rb", Type: "k8s_role_binding", Provider: asset.ProviderKubernetes,
			Metadata: map[string]string{"role_ref": ref, "role_ref_kind": "ClusterRole", "subjects": "User/alice"}}
		f, ok := k8sRoleBindingAdminBinding.eval(rb, fixedTime)
		require.True(t, ok, ref)
		require.LessOrEqual(t, severityRank(f.Severity), severityRank(finding.SeverityMedium), ref)
	}
}
