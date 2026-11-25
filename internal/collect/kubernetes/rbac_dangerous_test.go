package kubernetes

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func rule(groups, resources, verbs []string, names ...string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{
		APIGroups: groups, Resources: resources, Verbs: verbs, ResourceNames: names,
	}
}

// The capability that motivated wiring this up: a ClusterRole with no wildcard
// anywhere, granting only cluster-wide `get secrets`. It steals every
// ServiceAccount token in the cluster and used to produce no finding at all.
func TestDangerousPermissions_ClusterWideSecretsRead(t *testing.T) {
	got := dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{""}, []string{"secrets"}, []string{"get", "list"}),
	})
	require.Equal(t, []string{dangerCategorySecretsRead}, got)
}

// API groups are honoured: a CRD coincidentally named "secrets" in a vendor
// group is not credential theft.
func TestDangerousPermissions_NonCoreGroupSecretsIsNotCredentialTheft(t *testing.T) {
	require.Empty(t, dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{"vendor.example.com"}, []string{"secrets"}, []string{"get"}),
	}))
}

// resourceNames confines the grant to named objects — still reported (reading one
// credential-bearing Secret is still credential theft) but marked scoped so a
// responder can see the difference.
func TestDangerousPermissions_ResourceNamesMarkedScoped(t *testing.T) {
	got := dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{""}, []string{"secrets"}, []string{"get"}, "my-own-config"),
	})
	require.Equal(t, []string{dangerCategorySecretsRead + dangerSuffixScoped}, got)
}

// Kubernetes ignores resourceNames for list/watch, so such a rule is not really
// scoped and must not be reported as if it were.
func TestDangerousPermissions_ResourceNamesIgnoredForList(t *testing.T) {
	got := dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{""}, []string{"secrets"}, []string{"list"}, "my-own-config"),
	})
	require.Equal(t, []string{dangerCategorySecretsRead}, got)
}

// The privesc primitives that were previously undetected entirely.
func TestDangerousPermissions_PreviouslyMissedPrimitives(t *testing.T) {
	cases := []struct {
		name string
		rule rbacv1.PolicyRule
		want string
	}{
		{"create pods mounts any SA", rule([]string{""}, []string{"pods"}, []string{"create"}), dangerCategoryPodCreate},
		{"ephemeral containers exec", rule([]string{""}, []string{"pods/ephemeralcontainers"}, []string{"create"}), dangerCategoryPodExec},
		{"mint SA token", rule([]string{""}, []string{"serviceaccounts/token"}, []string{"create"}), dangerCategoryTokenMint},
		{"kubelet API via node proxy", rule([]string{""}, []string{"nodes/proxy"}, []string{"get"}), dangerCategoryNodeProxy},
		{"deployment create makes pods", rule([]string{"apps"}, []string{"deployments"}, []string{"create"}), dangerCategoryWorkloadWrite},
		{"cronjob create makes pods", rule([]string{"batch"}, []string{"cronjobs"}, []string{"create"}), dangerCategoryWorkloadWrite},
		{"rbac write is escalation", rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterrolebindings"}, []string{"create"}), dangerCategoryRBACEscalate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, []string{tc.want}, dangerousPermissionCategories([]rbacv1.PolicyRule{tc.rule}))
		})
	}
}

// escalate/bind/impersonate are privesc wherever they are attached.
func TestDangerousPermissions_EscalateVerbs(t *testing.T) {
	for _, verb := range []string{"escalate", "bind", "impersonate"} {
		got := dangerousPermissionCategories([]rbacv1.PolicyRule{
			rule([]string{"*"}, []string{"*"}, []string{verb}),
		})
		require.Contains(t, got, dangerCategoryRBACEscalate, verb)
	}
}

// A genuinely read-only role must stay clean — this check has to be quiet on the
// large population of view-style ClusterRoles or it is just noise.
func TestDangerousPermissions_BenignReadOnlyRoleIsClean(t *testing.T) {
	require.Empty(t, dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{""}, []string{"pods", "services", "configmaps"}, []string{"get", "list", "watch"}),
		rule([]string{"apps"}, []string{"deployments"}, []string{"get", "list", "watch"}),
	}))
}

// Categories are distinct and stable, so the finding evidence is deterministic.
func TestDangerousPermissions_DeduplicatesCategories(t *testing.T) {
	got := dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{""}, []string{"secrets"}, []string{"get"}),
		rule([]string{""}, []string{"secrets"}, []string{"list"}),
		rule([]string{""}, []string{"pods/exec"}, []string{"create"}),
	})
	require.Equal(t, []string{dangerCategorySecretsRead, dangerCategoryPodExec}, got)
}

// The asset carries both the boolean the check reads and the detail the finding
// quotes as evidence.
func TestClusterRoleAsset_EmitsDangerousDetail(t *testing.T) {
	a := clusterRoleAsset(rbacv1.ClusterRole{
		Rules: []rbacv1.PolicyRule{rule([]string{""}, []string{"secrets"}, []string{"get"})},
	}, "cluster-1", time.Unix(1700000000, 0).UTC())

	require.Equal(t, "true", a.Metadata["dangerous_perms"])
	require.Equal(t, dangerCategorySecretsRead, a.Metadata["dangerous_perms_detail"])
	require.Equal(t, "false", a.Metadata["wildcard_verbs"])
}

// Adversary emulation: well-known cluster-takeover primitives.
// Each of these gives cluster compromise with no wildcard anywhere in the rule.
func TestDangerousPermissions_RedTeamTakeoverPrimitives(t *testing.T) {
	cases := []struct {
		name string
		rule rbacv1.PolicyRule
		want string
	}{
		// Self-approve a CSR with O=system:masters → client cert the API server
		// authorises as cluster-admin, outside RBAC entirely.
		{"csr approval subresource", rule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}), dangerCategoryCSRApprove},
		{"csr signers approve", rule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"create"}), dangerCategoryCSRApprove},
		// Intercept and rewrite every API object cluster-wide.
		{"mutating webhook", rule([]string{"admissionregistration.k8s.io"}, []string{"mutatingwebhookconfigurations"}, []string{"create"}), dangerCategoryWebhookHijack},
		{"validating webhook", rule([]string{"admissionregistration.k8s.io"}, []string{"validatingwebhookconfigurations"}, []string{"patch"}), dangerCategoryWebhookHijack},
		// Equivalent reach into a running pod by other mechanisms than exec.
		{"pod portforward", rule([]string{""}, []string{"pods/portforward"}, []string{"create"}), dangerCategoryPodExec},
		{"pod proxy", rule([]string{""}, []string{"pods/proxy"}, []string{"get"}), dangerCategoryPodExec},
		{"service proxy", rule([]string{""}, []string{"services/proxy"}, []string{"get"}), dangerCategoryPodExec},
		// hostPath PV → node filesystem → every pod's SA token.
		{"hostPath persistent volume", rule([]string{""}, []string{"persistentvolumes"}, []string{"create"}), dangerCategoryHostMount},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, []string{tc.want}, dangerousPermissionCategories([]rbacv1.PolicyRule{tc.rule}))
		})
	}
}

// Patching an existing Deployment's serviceAccountName or image assumes any SA in
// the namespace just as effectively as creating one. Requiring literal `create`
// missed the very common "editor"-shaped role that grants patch/update only.
func TestDangerousPermissions_PatchOnlyWorkloadTakeover(t *testing.T) {
	for _, verb := range []string{"patch", "update"} {
		got := dangerousPermissionCategories([]rbacv1.PolicyRule{
			rule([]string{"apps"}, []string{"deployments"}, []string{verb}),
		})
		require.Equal(t, []string{dangerCategoryWorkloadWrite}, got, verb)
	}

	// Read-only on the same resource stays clean.
	require.Empty(t, dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{"apps"}, []string{"deployments"}, []string{"get", "list", "watch"}),
	}))
}

// Non-core groups must not trip the core-group categories, so a vendor CRD named
// like a sensitive resource stays quiet.
func TestDangerousPermissions_WrongGroupStaysQuiet(t *testing.T) {
	require.Empty(t, dangerousPermissionCategories([]rbacv1.PolicyRule{
		rule([]string{"vendor.example.com"}, []string{"mutatingwebhookconfigurations"}, []string{"create"}),
		rule([]string{"vendor.example.com"}, []string{"certificatesigningrequests/approval"}, []string{"update"}),
	}))
}

// A stock ClusterRole granting no more than its stock baseline is excluded
// from the reporting signal: dangerous by design, and recreated if deleted.
// A label or a platform-looking prefix confers nothing, and neither does the
// stock name once the rules exceed the baseline.
func TestDangerousPermissions_PlatformManagedExcludedFromSignal(t *testing.T) {
	rules := []rbacv1.PolicyRule{rule([]string{""}, []string{"secrets"}, []string{"get"})}
	now := time.Unix(1700000000, 0).UTC()
	graded := func(cr rbacv1.ClusterRole) asset.Asset {
		a := clusterRoleAsset(cr, "c1", now)
		gradePlatformRole(&a, nil, nil)
		return a
	}

	// admin's stock baseline includes Secrets access.
	stock := graded(rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "admin"}, Rules: rules})
	require.Equal(t, "false", stock.Metadata["dangerous_perms"])
	require.Equal(t, "true", stock.Metadata["platform_managed"])
	require.Equal(t, dangerCategorySecretsRead, stock.Metadata["dangerous_perms_detail"],
		"the detail is still recorded so a responder can see what a system role grants")

	// system:kube-scheduler's does not: the stock name no longer suppresses.
	exceeded := graded(rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:kube-scheduler"}, Rules: rules})
	require.Equal(t, "true", exceeded.Metadata["dangerous_perms"])
	require.Equal(t, "false", exceeded.Metadata["platform_managed"])

	for _, cr := range []rbacv1.ClusterRole{
		{ObjectMeta: metav1.ObjectMeta{Name: "team-reader", Labels: map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}}, Rules: rules},
		{ObjectMeta: metav1.ObjectMeta{Name: "gke-lookalike"}, Rules: rules},
		{ObjectMeta: metav1.ObjectMeta{Name: "system:lookalike"}, Rules: rules},
		{ObjectMeta: metav1.ObjectMeta{Name: "team-platform-reader"}, Rules: rules},
	} {
		a := graded(cr)
		require.Equal(t, "true", a.Metadata["dangerous_perms"], cr.Name)
		require.Equal(t, "false", a.Metadata["platform_managed"], cr.Name)
	}
}

// A role stock only on a distribution the cluster is not known to run is the
// organisation's.
func TestGradePlatformRole_DistroGated(t *testing.T) {
	cr := clusterRole("eks:certificate-controller-approver", nil,
		rule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}))
	on := clusterRoleAsset(cr, "c1", time.Now())
	gradePlatformRole(&on, platformEnv{distroEKS: true}, nil)
	require.Equal(t, "true", on.Metadata["platform_managed"])
	off := clusterRoleAsset(cr, "c1", time.Now())
	gradePlatformRole(&off, nil, nil)
	require.Equal(t, "false", off.Metadata["platform_managed"])
	require.Equal(t, "true", off.Metadata["dangerous_perms"])
}

// RBAC wildcards cover every resource, subresource and verb, so a "*" rule
// grants every capability — it used to yield only the Secrets categories, and
// the per-capability CIS controls read the most permissive role as passing.
func TestDangerousPermissions_WildcardsCoverEveryCapability(t *testing.T) {
	all := []string{
		dangerCategorySecretsRead, dangerCategorySecretsWrite, dangerCategoryPodExec, dangerCategoryPodCreate,
		dangerCategoryWorkloadWrite, dangerCategoryCSRApprove, dangerCategoryWebhookHijack, dangerCategoryHostMount,
		dangerCategoryTokenMint, dangerCategoryNodeProxy, dangerCategoryRBACEscalate,
	}
	got := dangerousPermissionCategories([]rbacv1.PolicyRule{rule([]string{"*"}, []string{"*"}, []string{"*"})})
	require.ElementsMatch(t, all, got)

	cases := []struct {
		name string
		rule rbacv1.PolicyRule
		want []string
	}{
		{"wildcard resources in apps only yields workload writes", rule([]string{"apps"}, []string{"*"}, []string{"*"}),
			[]string{dangerCategoryWorkloadWrite}},
		{"*/exec covers exec on every resource", rule([]string{""}, []string{"*/exec"}, []string{"create"}),
			[]string{dangerCategoryPodExec}},
		{"pods/* is not an RBAC wildcard form", rule([]string{""}, []string{"pods/*"}, []string{"create", "get"}), nil},
		{"list-only exec reaches nothing", rule([]string{""}, []string{"pods/exec"}, []string{"list"}), nil},
		{"verbs * on serviceaccounts includes impersonate", rule([]string{""}, []string{"serviceaccounts"}, []string{"*"}),
			[]string{dangerCategoryRBACEscalate}},
		{"read-only wildcard in core reads secrets but grants nothing else", rule([]string{""}, []string{"*"}, []string{"get", "list"}),
			[]string{dangerCategorySecretsRead, dangerCategoryPodExec, dangerCategoryNodeProxy}},
		{"approve verb on signers", rule([]string{"certificates.k8s.io"}, []string{"signers"}, []string{"approve"}),
			[]string{dangerCategoryCSRApprove}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			require.ElementsMatch(t, tt.want, dangerousPermissionCategories([]rbacv1.PolicyRule{tt.rule}))
		})
	}
}
