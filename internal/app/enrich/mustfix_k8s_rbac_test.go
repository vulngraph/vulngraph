package enrich

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeRBACBindings struct {
	edges    []asset.Edge
	assets   []asset.Asset
	edgesErr error
	byIDsErr error
	calls    int
}

func (f *fakeRBACBindings) EdgesInto(context.Context, string, string) ([]asset.Edge, error) {
	f.calls++
	return f.edges, f.edgesErr
}

func (f *fakeRBACBindings) ByIDs(context.Context, []string) ([]asset.Asset, error) {
	return f.assets, f.byIDsErr
}

func rbacFinding(resourceType, id string) finding.Finding {
	return finding.Finding{
		ID: "f1", Source: "cspm", Type: "rbac",
		CheckID: "k8s-role-dangerous-permissions", Severity: finding.SeverityHigh,
		ResourceType: resourceType, ResourceID: id,
	}
}

// ── isK8sRBACGrant: the predicate must not repeat the title-match accident ──

func TestIsK8sRBACGrant_MatchesOnlyRBACObjects(t *testing.T) {
	tests := []struct {
		name         string
		findingType  string
		resourceType string
		want         bool
	}{
		{"role", "rbac", "k8s_role", true},
		{"cluster role", "rbac", "k8s_cluster_role", true},
		{"role binding", "rbac", "k8s_role_binding", true},
		{"cluster role binding", "rbac", "k8s_cluster_role_binding", true},

		// The pod-hardening checks also carry type="rbac" (k8s-privileged-container,
		// k8s-dangerous-capabilities). They are NOT
		// permission grants and must never enter the privesc path.
		{"privileged container on pod", "rbac", "k8s_pod", false},
		{"privileged container on deployment", "rbac", "k8s_deployment", false},

		// And the misconfiguration that started it all.
		{"pod allows privilege escalation", "misconfiguration", "k8s_pod", false},
		{"cloud privesc keeps its own path", "ciem_privesc", "iam_role", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding.Finding{Type: tt.findingType, ResourceType: tt.resourceType}
			require.Equal(t, tt.want, isK8sRBACGrant(f))
		})
	}
}

// ── bindings: subjects come straight off the seed ──

func TestAssessK8sRBACMustFix_ExternalSubjectElevates(t *testing.T) {
	f := rbacFinding("k8s_role_binding", "example-connector-cluster/namespace/activities/rolebinding/admin-binding")
	seed := asset.Asset{Metadata: map[string]string{
		"subjects": "User/worker-deployment@example-project-c.iam.gserviceaccount.com,Group/platform-team@example.com",
	}}

	class, reason := assessK8sRBACMustFix(context.Background(), f, seed, nil)

	require.Equal(t, MustFixElevated, class)
	require.Contains(t, reason, "outside the cluster")
}

func TestAssessK8sRBACMustFix_InClusterOnlyIsContained(t *testing.T) {
	f := rbacFinding("k8s_role_binding", "rb")
	seed := asset.Asset{Metadata: map[string]string{
		"subjects": "ServiceAccount/tiller,ServiceAccount/deployer",
	}}

	class, reason := assessK8sRBACMustFix(context.Background(), f, seed, nil)

	require.Equal(t, MustFixContained, class)
	require.Contains(t, reason, "cluster foothold")
}

// Many in-cluster holders is its own blast signal, mirroring mustFixBlastThreshold.
func TestAssessK8sRBACMustFix_ManyInClusterSubjectsElevates(t *testing.T) {
	f := rbacFinding("k8s_role_binding", "rb")
	seed := asset.Asset{Metadata: map[string]string{
		"subjects": "ServiceAccount/a,ServiceAccount/b,ServiceAccount/c,ServiceAccount/d,ServiceAccount/e",
	}}

	class, reason := assessK8sRBACMustFix(context.Background(), f, seed, nil)

	require.Equal(t, MustFixElevated, class)
	require.Contains(t, reason, "blast radius")
}

// A binding asset with no subjects field at all is a collection gap, not
// evidence — it must fail open rather than demote.
func TestAssessK8sRBACMustFix_BindingWithoutSubjectsFieldFailsOpen(t *testing.T) {
	f := rbacFinding("k8s_role_binding", "rb")

	class, reason := assessK8sRBACMustFix(context.Background(), f, asset.Asset{}, nil)

	require.Empty(t, class)
	require.Empty(t, reason)
}

// ── roles: subjects come from the inbound binds edges ──

func TestAssessK8sRBACMustFix_RoleResolvesSubjectsViaBindings(t *testing.T) {
	f := rbacFinding("k8s_cluster_role", "example-connector-cluster/clusterrole/admin")
	binds := &fakeRBACBindings{
		edges:  []asset.Edge{{SrcID: "example-connector-cluster/clusterrolebinding/x", EdgeType: "binds"}},
		assets: []asset.Asset{{Metadata: map[string]string{"subjects": "Group/sre@example.com"}}},
	}

	class, reason := assessK8sRBACMustFix(context.Background(), f, asset.Asset{}, binds)

	require.Equal(t, MustFixElevated, class)
	require.Contains(t, reason, "outside the cluster")
	require.Equal(t, 1, binds.calls)
}

// The demotion this path exists to make: a dangerous permission set that
// nothing binds is latent hygiene, not urgent.
// The provider's own control-plane Users, which the collector records only on
// a cluster known to be that provider's (platform_subjects), are in-cluster;
// the same User on a binding without that record stays external.
func TestAssessK8sRBACMustFix_PlatformUsersAreInternal(t *testing.T) {
	f := rbacFinding("k8s_cluster_role_binding", "c/clusterrolebinding/eks:addon-cluster-admin")
	onEKS := asset.Asset{Metadata: map[string]string{"subjects": "User/eks:addon-manager", "platform_subjects": "User/eks:addon-manager"}}
	class, _ := assessK8sRBACMustFix(context.Background(), f, onEKS, nil)
	require.Equal(t, MustFixContained, class)

	unknown := asset.Asset{Metadata: map[string]string{"subjects": "User/eks:addon-manager", "platform_subjects": ""}}
	class, _ = assessK8sRBACMustFix(context.Background(), f, unknown, nil)
	require.Equal(t, MustFixElevated, class)

	role := rbacFinding("k8s_cluster_role", "c/clusterrole/eks:addon-manager")
	binds := &fakeRBACBindings{
		edges:  []asset.Edge{{SrcID: "b1"}, {SrcID: "b2"}},
		assets: []asset.Asset{onEKS, {Metadata: map[string]string{"subjects": "User/alice"}}},
	}
	class, reason := assessK8sRBACMustFix(context.Background(), role, asset.Asset{}, binds)
	require.Equal(t, MustFixElevated, class)
	require.Contains(t, reason, "User/alice")
	require.NotContains(t, reason, "eks:addon-manager")
}

func TestAssessK8sRBACMustFix_UnboundRoleIsContained(t *testing.T) {
	f := rbacFinding("k8s_role", "example-connector-cluster/namespace/x/role/dangerous")
	binds := &fakeRBACBindings{} // no edges, no error — positively unbound

	class, reason := assessK8sRBACMustFix(context.Background(), f, asset.Asset{}, binds)

	require.Equal(t, MustFixContained, class)
	require.Contains(t, reason, "unused permission set")
}

func TestAssessK8sRBACMustFix_NilResolverForRoleFailsOpen(t *testing.T) {
	f := rbacFinding("k8s_role", "r")

	class, _ := assessK8sRBACMustFix(context.Background(), f, asset.Asset{}, nil)

	require.Empty(t, class, "no resolver means no subject evidence — must not classify")
}

func TestAssessK8sRBACMustFix_LookupErrorsFailOpen(t *testing.T) {
	f := rbacFinding("k8s_role", "r")

	edgeErr := &fakeRBACBindings{edgesErr: errors.New("ch down")}
	class, _ := assessK8sRBACMustFix(context.Background(), f, asset.Asset{}, edgeErr)
	require.Empty(t, class, "edge lookup error must not classify")

	fetchErr := &fakeRBACBindings{
		edges:    []asset.Edge{{SrcID: "b1"}},
		byIDsErr: errors.New("ch down"),
	}
	class, _ = assessK8sRBACMustFix(context.Background(), f, asset.Asset{}, fetchErr)
	require.Empty(t, class, "binding fetch error must not classify")
}

// Bindings exist but carry no subjects: a collection gap. Demoting here would
// call a held role unheld.
func TestAssessK8sRBACMustFix_BoundButSubjectlessFailsOpen(t *testing.T) {
	f := rbacFinding("k8s_role", "r")
	binds := &fakeRBACBindings{
		edges:  []asset.Edge{{SrcID: "b1"}},
		assets: []asset.Asset{{Metadata: map[string]string{}}},
	}

	class, _ := assessK8sRBACMustFix(context.Background(), f, asset.Asset{}, binds)

	require.Empty(t, class)
}

// ── subject classification ──

func TestIsExternalRBACSubject(t *testing.T) {
	tests := []struct {
		subject string
		want    bool
	}{
		{"ServiceAccount/tiller", false},
		{"User/alice@example.com", true},
		{"Group/sre@example.com", true},
		{"User/deployer@example-project-c.iam.gserviceaccount.com", true},
		{"Unknown/deployer@example-project-c.iam.gserviceaccount.com", true},
		{"Unknown/arn:aws:iam::1:role/eks", true},
		{"Unknown/plain-name", false},
		{"no-kind-prefix", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			require.Equal(t, tt.want, isExternalRBACSubject(tt.subject))
		})
	}
}

func TestSplitRBACSubjects_DropsEmpties(t *testing.T) {
	require.Equal(t,
		[]string{"ServiceAccount/a", "Group/b"},
		splitRBACSubjects("ServiceAccount/a, ,Group/b,"))
	require.Empty(t, splitRBACSubjects(""))
}

// ── routing: assessMustFix must send RBAC findings down this path ──

func TestAssessMustFix_RoutesRBACAroundReachPath(t *testing.T) {
	f := rbacFinding("k8s_cluster_role_binding", "example-connector-cluster/clusterrolebinding/ca-cr")
	seed := asset.Asset{Metadata: map[string]string{"subjects": "Group/sre@example.com"}}

	// A reach provider that would answer "unreachable" for anything: before this
	// fix the RBAC finding fell through to classifyMustFix and landed blank.
	class, reason := assessMustFix(context.Background(), f, seed,
		fakeReach{hops: -1, ok: true}, fakeCounter{count: 0}, nil, nil, nil, time.Now())

	require.Equal(t, MustFixElevated, class)
	require.Contains(t, reason, "outside the cluster")
}
