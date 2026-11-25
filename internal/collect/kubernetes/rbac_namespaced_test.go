package kubernetes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Namespaced RBAC: Roles and RoleBindings are a detection blind spot when only
// ClusterRole(Binding) objects are collected, and many RoleBindings reference a
// ClusterRole rather than a Role.

func TestRoleAsset_IDAndMetadataMirrorClusterRole(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "billing", Labels: map[string]string{"team": "billing"}},
		Rules:      []rbacv1.PolicyRule{rule([]string{""}, []string{"secrets"}, []string{"get"})},
	}
	a := roleAsset(role, "cluster-1", now)

	require.Equal(t, "cluster-1/namespace/billing/role/reader", a.ID)
	require.Equal(t, "k8s_role", a.Type)
	require.Equal(t, "billing", a.Metadata["namespace"])
	require.Equal(t, "true", a.Metadata["dangerous_perms"])
	require.Equal(t, dangerCategorySecretsRead, a.Metadata["dangerous_perms_detail"],
		"dangerousPermissionCategories reused verbatim from the ClusterRole path")
	require.Equal(t, "false", a.Metadata["wildcard_verbs"])
	require.Equal(t, map[string]string{"team": "billing"}, a.Tags)
}

// A namespaced Role legitimately named "admin" (a common convention) must not
// be confused with the built-in ClusterRole "admin" that k8s-cluster-admin-binding
// treats as cluster-wide-admin-equivalent. That distinction lives entirely in
// role_ref_kind, which this pins.
func TestRoleBindingAsset_RoleRefKindDistinguishesAdminRoleFromAdminClusterRole(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()

	// Case 1: RoleBinding → namespaced Role named "admin" (harmless, team-scoped).
	toRole := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-role", Namespace: "billing"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "admin"},
	}
	a1, edges1 := roleBindingAsset(toRole, "cluster-1", now, nil, saInventory{}, nil)
	require.Equal(t, "Role", a1.Metadata["role_ref_kind"])
	require.Equal(t, "admin", a1.Metadata["role_ref"])
	require.Len(t, edges1, 1)
	require.Equal(t, "cluster-1/namespace/billing/role/admin", edges1[0].DstID)
	require.Equal(t, "k8s_role", edges1[0].DstType)

	// Case 2: RoleBinding → built-in ClusterRole "admin" (namespace-scoped grant
	// of the powerful built-in role — the dangerous case).
	toClusterRole := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb-cr", Namespace: "billing"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "admin"},
	}
	a2, edges2 := roleBindingAsset(toClusterRole, "cluster-1", now, nil, saInventory{}, nil)
	require.Equal(t, "ClusterRole", a2.Metadata["role_ref_kind"])
	require.Len(t, edges2, 1)
	require.Equal(t, "cluster-1/clusterrole/admin", edges2[0].DstID,
		"ClusterRole dispatch must point at the EXISTING clusterrole asset ID, not a namespaced one")
	require.Equal(t, "k8s_cluster_role", edges2[0].DstType)
}

// The Kind dispatch both ways: Role stays namespace-local, ClusterRole points
// at the cluster-wide asset ID regardless of the binding's own namespace.
func TestRoleBindingAsset_KindDispatch(t *testing.T) {
	now := time.Now()
	rb := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "core"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "deployer"},
	}
	_, edges := roleBindingAsset(rb, "c1", now, nil, saInventory{}, nil)
	require.Equal(t, "c1/namespace/core/role/deployer", edges[0].DstID)

	rb.RoleRef = rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"}
	_, edges = roleBindingAsset(rb, "c1", now, nil, saInventory{}, nil)
	require.Equal(t, "c1/clusterrole/edit", edges[0].DstID)
}

// A common case: a ServiceAccount subject in a RoleBinding names a SA in a
// DIFFERENT namespace than the binding. The edge
// must follow subject.Namespace, never the binding's own namespace.
func TestRoleBindingAsset_CrossNamespaceServiceAccountSubject(t *testing.T) {
	now := time.Now()
	rb := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "billing"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "edit"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "worker", Namespace: "other-ns"},
		},
	}
	_, edges := roleBindingAsset(rb, "c1", now, nil, saInventory{}, nil)
	require.Len(t, edges, 2)
	saEdge := edges[1]
	require.Equal(t, "c1/namespace/other-ns/serviceaccount/worker", saEdge.SrcID,
		"the SA edge must point at the subject's OWN namespace, not the binding's namespace")
	require.Equal(t, "k8s_service_account", saEdge.SrcType)
	require.Equal(t, "c1/namespace/billing/rolebinding/rb", saEdge.DstID)
}

// Empty subject.Namespace falls back to the binding's own
// namespace — never "default", which is only correct for a cluster-scoped
// ClusterRoleBinding and is not defined as a default here by rbacv1.
func TestRoleBindingAsset_EmptySubjectNamespaceFallsBackToBindingNamespace(t *testing.T) {
	now := time.Now()
	rb := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "billing"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "reader"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "local-sa", Namespace: ""},
		},
	}
	_, edges := roleBindingAsset(rb, "c1", now, nil, saInventory{}, nil)
	require.Len(t, edges, 2)
	require.Equal(t, "c1/namespace/billing/serviceaccount/local-sa", edges[1].SrcID,
		"empty subject namespace falls back to the BINDING's namespace, not \"default\"")
}

// dangerousPermissionCategories and hasWildcard are reused verbatim on a
// namespaced Role — both already take []rbacv1.PolicyRule, which Role.Rules
// and ClusterRole.Rules share.
func TestRoleAsset_DangerousPermissionReuseOnNamespacedRole(t *testing.T) {
	now := time.Now()
	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-execer", Namespace: "core"},
		Rules: []rbacv1.PolicyRule{
			rule([]string{""}, []string{"pods/exec"}, []string{"create"}),
		},
	}
	a := roleAsset(role, "c1", now)
	require.Equal(t, "true", a.Metadata["dangerous_perms"])
	require.Equal(t, dangerCategoryPodExec, a.Metadata["dangerous_perms_detail"])
}

// Only a stock namespaced Role (exact namespace and name) is excluded from the
// reporting signal; a system namespace, label or prefix confers nothing.
func TestRoleAsset_PlatformManagedExcludedFromSignal(t *testing.T) {
	now := time.Now()
	rules := []rbacv1.PolicyRule{rule([]string{""}, []string{"secrets"}, []string{"get"})}

	stock := roleAsset(rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "system:controller:token-cleaner", Namespace: "kube-system"}, Rules: rules}, "c1", now)
	gradePlatformRole(&stock, nil, nil)
	require.Equal(t, "false", stock.Metadata["dangerous_perms"])
	require.Equal(t, "true", stock.Metadata["platform_managed"])

	for _, r := range []rbacv1.Role{
		{ObjectMeta: metav1.ObjectMeta{Name: "team-reader", Namespace: "kube-system"}, Rules: rules},
		{ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "billing", Labels: map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}}, Rules: rules},
		{ObjectMeta: metav1.ObjectMeta{Name: "system:controller:token-cleaner", Namespace: "billing"}, Rules: rules},
	} {
		a := roleAsset(r, "c1", now)
		gradePlatformRole(&a, nil, nil)
		require.Equal(t, "true", a.Metadata["dangerous_perms"], r.Namespace+"/"+r.Name)
		require.Equal(t, "false", a.Metadata["platform_managed"])
	}
}

// bindingGrades builds the role index the collector passes to the binding
// constructors, from the same asset constructors the collector uses.
func bindingGrades(t *testing.T, clusterRoles []rbacv1.ClusterRole, roles []rbacv1.Role) roleGrades {
	t.Helper()
	now := time.Now()
	g := roleGrades{}
	for _, cr := range clusterRoles {
		a := clusterRoleAsset(cr, "c1", now)
		g[a.ID] = a
	}
	for _, r := range roles {
		a := roleAsset(r, "c1", now)
		g[a.ID] = a
	}
	return g
}

// The join this whole path exists for: checks.privilegedRoleRef reads
// dangerous_perms ON THE BINDING, and nothing ever wrote it there — no
// ClusterRoleBinding or RoleBinding carried the key, so a
// binding to a custom Role granting `secrets: get` was invisible and only three
// hardcoded built-in ClusterRole names were recognised.
func TestRoleBindingInheritsTheReferencedRolesGrade(t *testing.T) {
	role := rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "app"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"},
		}},
	}
	rb := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "app"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "secret-reader"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: "app"}},
	}

	a, _ := roleBindingAsset(rb, "c1", time.Now(), bindingGrades(t, nil, []rbacv1.Role{role}), saInventory{}, nil)

	require.Equal(t, "true", a.Metadata["role_ref_resolved"])
	require.Equal(t, "true", a.Metadata["dangerous_perms"],
		"a binding to a Role that grants secrets:get must carry the grade the check reads")
	require.Contains(t, a.Metadata["dangerous_perms_detail"], dangerCategorySecretsRead)
}

// A platform-managed role's wildcard verbs must NOT propagate: a stock role
// whose baseline carries verbs: ["*"] (system:kubelet-api-admin, on
// nodes/proxy) must not make every binding to it privileged. A stock role
// given {*,*,*} beyond its baseline is no longer the platform's, and its
// binding inherits the excess.
func TestRoleBindingWildcardInheritanceFollowsTheBaseline(t *testing.T) {
	rb := func(role string) rbacv1.RoleBinding {
		return rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "app"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: role},
			Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: "app"}},
		}
	}
	graded := func(cr rbacv1.ClusterRole) roleGrades {
		a := clusterRoleAsset(cr, "c1", time.Now())
		gradePlatformRole(&a, nil, nil)
		return roleGrades{a.ID: a}
	}

	stock := clusterRole("system:kubelet-api-admin", nil, rule(core, []string{"nodes/proxy"}, []string{"*"}))
	a, _ := roleBindingAsset(rb(stock.Name), "c1", time.Now(), graded(stock), saInventory{}, nil)
	require.Equal(t, "false", a.Metadata["dangerous_perms"])
	require.Equal(t, "false", a.Metadata["wildcard_verbs"],
		"a bootstrap ClusterRole's by-design wildcards must not make every binding to it privileged")
	require.Equal(t, "true", a.Metadata["role_platform_managed"])

	injected := clusterRole("system:kube-controller-manager", nil, starRule)
	a, _ = roleBindingAsset(rb(injected.Name), "c1", time.Now(), graded(injected), saInventory{}, nil)
	require.Equal(t, "true", a.Metadata["wildcard_verbs"])
	require.Equal(t, "false", a.Metadata["role_platform_managed"])
}

// A roleRef that resolves to nothing is UNKNOWN, not safe. The collector's own
// ClusterRole may not list roles in every namespace, and a missing grade that
// reads as "not privileged" is the same absent-means-clean trap this key was
// added to close.
func TestRoleBindingWithUnresolvedRoleRefCarriesNoGrade(t *testing.T) {
	rb := rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "app"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "never-collected"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "default", Namespace: "app"}},
	}

	a, _ := roleBindingAsset(rb, "c1", time.Now(), roleGrades{}, saInventory{}, nil)

	require.Equal(t, "false", a.Metadata["role_ref_resolved"])
	require.NotContains(t, a.Metadata, "dangerous_perms",
		"an unresolved roleRef must leave the grade absent, not stamp a clean one")
}

// ClusterRoleBindings get the same treatment — the arm was equally inert there.
func TestClusterRoleBindingInheritsTheReferencedRolesGrade(t *testing.T) {
	cr := rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "app-secret-reader"},
		Rules: []rbacv1.PolicyRule{{
			APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"},
		}},
	}
	crb := rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "crb"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "app-secret-reader"},
		Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:authenticated"}},
	}

	a, _ := clusterRoleBindingAsset(crb, "c1", time.Now(), bindingGrades(t, []rbacv1.ClusterRole{cr}, nil), saInventory{}, nil)

	require.Equal(t, "true", a.Metadata["dangerous_perms"])
}
