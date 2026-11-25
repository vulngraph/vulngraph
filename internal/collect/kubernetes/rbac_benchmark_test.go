package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// ── fixtures ───────────────────────────────────────────────────────────────

var bootstrapLabel = map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}

func user(n string) rbacv1.Subject  { return rbacv1.Subject{Kind: "User", Name: n} }
func group(n string) rbacv1.Subject { return rbacv1.Subject{Kind: "Group", Name: n} }
func sa(ns, n string) rbacv1.Subject {
	return rbacv1.Subject{Kind: "ServiceAccount", Namespace: ns, Name: n}
}

func clusterRole(name string, labels map[string]string, rules ...rbacv1.PolicyRule) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}, Rules: rules}
}

func role(ns, name string, rules ...rbacv1.PolicyRule) rbacv1.Role {
	return rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Rules: rules}
}

func crb(name, roleName string, labels map[string]string, subjects ...rbacv1.Subject) rbacv1.ClusterRoleBinding {
	return rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName}, Subjects: subjects}
}

func roleBinding(ns, name, roleKind, roleName string, subjects ...rbacv1.Subject) rbacv1.RoleBinding {
	return rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		RoleRef: rbacv1.RoleRef{Kind: roleKind, Name: roleName}, Subjects: subjects}
}

var (
	starRule  = rule([]string{"*"}, []string{"*"}, []string{"*"})
	core      = []string{""}
	nodeToken = "system:bootstrappers:kubeadm:default-node-token"
)

// loadRBACFixtures decodes every RBAC object in the YAML files under dir —
// both `kind: List` documents (the upstream bootstrap testdata) and multi-doc
// streams (the kube-up addons) — into f.
func loadRBACFixtures(t *testing.T, f *fakeK8s, dir string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	var add func(raw json.RawMessage)
	add = func(raw json.RawMessage) {
		var head struct {
			Kind  string            `json:"kind"`
			Items []json.RawMessage `json:"items"`
		}
		require.NoError(t, json.Unmarshal(raw, &head))
		switch head.Kind {
		case "List":
			for _, it := range head.Items {
				add(it)
			}
		case "ClusterRole":
			var o rbacv1.ClusterRole
			require.NoError(t, json.Unmarshal(raw, &o))
			f.crs = append(f.crs, o)
		case "Role":
			var o rbacv1.Role
			require.NoError(t, json.Unmarshal(raw, &o))
			f.roles = append(f.roles, o)
		case "ClusterRoleBinding":
			var o rbacv1.ClusterRoleBinding
			require.NoError(t, json.Unmarshal(raw, &o))
			f.crbs = append(f.crbs, o)
		case "RoleBinding":
			var o rbacv1.RoleBinding
			require.NoError(t, json.Unmarshal(raw, &o))
			f.rbs = append(f.rbs, o)
		}
	}
	for _, p := range paths {
		fh, err := os.Open(p)
		require.NoError(t, err)
		dec := utilyaml.NewYAMLOrJSONDecoder(fh, 4096)
		for {
			var raw json.RawMessage
			err := dec.Decode(&raw)
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err, p)
			if len(raw) > 0 && string(raw) != "null" {
				add(raw)
			}
		}
		require.NoError(t, fh.Close())
	}
}

// aggregate fills every aggregated ClusterRole's rules from the roles its
// selectors match, to a fixed point, as the clusterrole-aggregation controller
// does on a live cluster: the vendored admin/edit/view ship rules: null, and
// a test over them would never see what the built-ins really grant. Selectors
// go through LabelSelectorAsSelector like the controller's, so an empty one
// matches every role and matchExpressions are honoured; like the controller,
// a role never aggregates itself.
func aggregate(t *testing.T, crs []rbacv1.ClusterRole) {
	t.Helper()
	for range len(crs) {
		for i := range crs {
			if crs[i].AggregationRule == nil {
				continue
			}
			var rules []rbacv1.PolicyRule
			for _, ls := range crs[i].AggregationRule.ClusterRoleSelectors {
				sel, err := metav1.LabelSelectorAsSelector(&ls)
				require.NoError(t, err)
				for j := range crs {
					if j != i && sel.Matches(labels.Set(crs[j].Labels)) {
						rules = append(rules, crs[j].Rules...)
					}
				}
			}
			crs[i].Rules = rules
		}
	}
}

func TestAggregateSelectors(t *testing.T) {
	crs := []rbacv1.ClusterRole{
		{ObjectMeta: metav1.ObjectMeta{Name: "all"}, AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "expr"}, AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"a"}}},
		}}}},
		clusterRole("a", map[string]string{"tier": "a"}, rule(core, []string{"pods"}, []string{"get"})),
		clusterRole("b", map[string]string{"tier": "b"}, rule(core, []string{"nodes"}, []string{"get"})),
	}
	aggregate(t, crs)
	require.Len(t, crs[1].Rules, 1, "matchExpressions select tier=a only")
	require.Len(t, crs[0].Rules, 3, "an empty selector matches every other role, aggregated ones included")
}

// upstreamCluster is the real upstream bootstrap policy (testdata/bootstrappolicy,
// vendored from kubernetes/kubernetes) with its aggregation applied, on a
// cluster whose distribution is unknown.
func upstreamCluster(t *testing.T) *fakeK8s {
	t.Helper()
	f := &fakeK8s{}
	loadRBACFixtures(t, f, "testdata/bootstrappolicy")
	aggregate(t, f.crs)
	return f
}

// stockCluster is a kubeadm cluster: the upstream policy plus kubeadm's own
// objects and the kubeadm-config ConfigMap that identifies it.
func stockCluster(t *testing.T) *fakeK8s {
	t.Helper()
	return withDistro(t, upstreamCluster(t), distroKubeadm)
}

// rbacFinding is what findings records per (resource name, check ID).
type rbacFinding = map[string]map[string]finding.Severity

// findings runs the collector over f and the full check registry over what it
// collected, keyed by resource name then check ID. Only RBAC resources: the
// fixture namespace's own posture findings are not under test here.
func findings(t *testing.T, f *fakeK8s) rbacFinding {
	t.Helper()
	f.namespaces = appNamespace()
	res, err := withFakeK8s(f).Collect(context.Background(), nil)
	require.NoError(t, err)
	out := rbacFinding{}
	for _, fd := range checks.Default().Run(res.Assets, time.Now()) {
		if !graphschema.IsK8sRBACType(fd.ResourceType) {
			continue
		}
		if out[fd.ResourceName] == nil {
			out[fd.ResourceName] = map[string]finding.Severity{}
		}
		out[fd.ResourceName][fd.CheckID] = fd.Severity
	}
	return out
}

// fired reports whether check fired on resource.
func fired(got rbacFinding, resource, check string) bool {
	_, ok := got[resource][check]
	return ok
}

// requireSilentAboveInfo fails on any finding above Info.
func requireSilentAboveInfo(t *testing.T, got rbacFinding) {
	t.Helper()
	for name, ids := range got {
		for id, sev := range ids {
			require.Equal(t, finding.SeverityInfo, sev, "stock RBAC object %s must not produce %s above Info", name, id)
		}
	}
}

func withAttack(t *testing.T, crs []rbacv1.ClusterRole, crbs ...rbacv1.ClusterRoleBinding) *fakeK8s {
	f := stockCluster(t)
	f.crs = append(f.crs, crs...)
	f.crbs = append(f.crbs, crbs...)
	return f
}

// ── attacks: each must surface ────────────────────────────────────────────

func TestRBACAttacksSurface(t *testing.T) {
	injectedView := func(t *testing.T) *fakeK8s {
		f := stockCluster(t)
		for i := range f.crs {
			if f.crs[i].Name == "view" {
				f.crs[i].Rules = append(f.crs[i].Rules, rule(core, []string{"secrets"}, []string{"get"}))
			}
		}
		return f
	}
	tests := []struct {
		name     string
		f        func(t *testing.T) *fakeK8s
		resource string
		check    string
	}{
		// Round 2.
		{"A system:serviceaccount user", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:metrics", "cluster-admin", nil, user("system:serviceaccount:app:evil")))
		}, "system:metrics", "k8s-cluster-admin-binding"},
		{"B forged bootstrap grant to everyone", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("system:ext", bootstrapLabel, starRule)},
				crb("system:ext", "system:ext", bootstrapLabel, group("system:authenticated")))
		}, "system:ext", "k8s-privileged-binding-to-everyone"},
		{"B the forged role itself", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("system:ext", bootstrapLabel, starRule)},
				crb("system:ext", "system:ext", bootstrapLabel, group("system:authenticated")))
		}, "system:ext", "k8s-cluster-role-wildcard-verbs"},
		{"F system:-named binding to system:masters", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:masters-ops", "view", nil, group("system:masters")))
		}, "system:masters-ops", "k8s-binding-system-masters"},
		{"F the real binding name with an extra subject", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("cluster-admin", "cluster-admin", bootstrapLabel, group("system:masters"), user("alice")))
		}, "cluster-admin", "k8s-cluster-admin-binding"},
		{"H system:nodes cluster-admin", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:node-x", "cluster-admin", nil, group("system:nodes")))
		}, "system:node-x", "k8s-cluster-admin-binding"},
		{"L */exec", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("debugger", nil, rule(core, []string{"*/exec"}, []string{"create"}))},
				crb("debug", "debugger", nil, user("alice")))
		}, "debugger", "k8s-rbac-pod-exec"},
		{"backdoor system:-named wildcard role bound to a human", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("system:backdoor", nil, starRule)},
				crb("metrics", "system:backdoor", nil, user("alice")))
		}, "system:backdoor", "k8s-rbac-escalate"},
		{"aggregated view bound to everyone", func(t *testing.T) *fakeK8s {
			f := injectedView(t)
			f.crbs = append(f.crbs, crb("all-view", "view", nil, group("system:authenticated")))
			return f
		}, "all-view", "k8s-privileged-binding-to-everyone"},
		// Round 3: B1 — attacker-mintable names are not platform identities.
		{"B1 node user", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:node:evil", "cluster-admin", nil, user("system:node:evil")))
		}, "system:node:evil", "k8s-cluster-admin-binding"},
		{"B1 eks user", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("eks:evil", "cluster-admin", nil, user("eks:evil")))
		}, "eks:evil", "k8s-cluster-admin-binding"},
		{"B1 system: group", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:evil", "cluster-admin", nil, group("system:evil")))
		}, "system:evil", "k8s-cluster-admin-binding"},
		{"B1 bootstrappers group", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:bootstrap-admin", "cluster-admin", bootstrapLabel, group("system:bootstrappers")))
		}, "system:bootstrap-admin", "k8s-cluster-admin-binding"},
		{"B1 edit to a node user", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:node-edit", "edit", nil, user("system:node:evil")))
		}, "system:node-edit", "k8s-clusterrolebinding-admin-edit"},
		{"B1 kubelet-api-admin to an eks user", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("eks:kubelet", "system:kubelet-api-admin", nil, user("eks:evil")))
		}, "system:kubelet-api-admin", "k8s-rbac-node-proxy"},
		// B2: a forged self-named role and binding to system:nodes.
		{"B2 system:god to system:nodes", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("system:god", bootstrapLabel, starRule)},
				crb("system:god", "system:god", bootstrapLabel, group("system:nodes")))
		}, "system:god", "k8s-cluster-role-wildcard-verbs"},
		// B3: a controller-shaped binding for a controller that does not exist.
		{"B3 system:controller:evil", func(t *testing.T) *fakeK8s {
			return withAttack(t, nil, crb("system:controller:evil", "cluster-admin", bootstrapLabel, sa("kube-system", "evil")))
		}, "system:controller:evil", "k8s-cluster-admin-binding"},
		{"B3 secrets to a kube-system SA through a system: binding", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("secret-reader", nil, rule(core, []string{"secrets"}, []string{"get", "list"}))},
				crb("system:secret-reader", "secret-reader", bootstrapLabel, sa("kube-system", "evil")))
		}, "secret-reader", "k8s-rbac-secrets-access"},
		{"B3 escalate to a kube-system SA through a system: binding", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("binder", nil, rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles"}, []string{"bind", "escalate"}))},
				crb("system:binder", "binder", bootstrapLabel, sa("kube-system", "evil")))
		}, "binder", "k8s-rbac-escalate"},
		{"B3 token-mint to a kube-system SA through a system: binding", func(t *testing.T) *fakeK8s {
			return withAttack(t, []rbacv1.ClusterRole{clusterRole("minter", nil, rule(core, []string{"serviceaccounts/token"}, []string{"create"}))},
				crb("system:minter", "minter", bootstrapLabel, sa("kube-system", "evil")))
		}, "minter", "k8s-rbac-token-create"},
		// Aggregation injection is reported on the role itself, bound or not —
		// not only through a grant to everyone.
		{"injected view, role level", injectedView, "view", "k8s-rbac-secrets-access"},
		{"injected edit, role level", func(t *testing.T) *fakeK8s {
			f := stockCluster(t)
			for i := range f.crs {
				if f.crs[i].Name == "edit" {
					f.crs[i].Rules = append(f.crs[i].Rules, rule(core, []string{"nodes/proxy"}, []string{"get"}))
				}
			}
			return f
		}, "edit", "k8s-rbac-node-proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findings(t, tt.f(t))
			require.True(t, fired(got, tt.resource, tt.check), "want %s on %s, got %v", tt.check, tt.resource, got[tt.resource])
			require.NotEqual(t, finding.SeverityInfo, got[tt.resource][tt.check], "an attack must not read as the platform's standing grant")
		})
	}
}

func TestRBACNonAttacksStaySilent(t *testing.T) {
	// L2: pods/* is not an RBAC wildcard form.
	got := findings(t, withAttack(t, []rbacv1.ClusterRole{clusterRole("pods-star", nil, rule(core, []string{"pods/*"}, []string{"create"}))},
		crb("ps", "pods-star", nil, user("alice"))))
	require.Empty(t, got["pods-star"])

	// List-only exec and nodes/proxy reach nothing; a read-only wildcard reads
	// Secrets but neither execs nor proxies.
	got = findings(t, withAttack(t, []rbacv1.ClusterRole{
		clusterRole("lister", nil, rule(core, []string{"pods/exec", "nodes/proxy"}, []string{"list"})),
		clusterRole("watcher", nil, rule([]string{"*"}, []string{"*"}, []string{"list", "watch"})),
	}, crb("l", "lister", nil, user("alice")), crb("w", "watcher", nil, user("alice"))))
	require.Empty(t, got["lister"])
	require.False(t, fired(got, "watcher", "k8s-rbac-node-proxy"))
	require.False(t, fired(got, "watcher", "k8s-rbac-pod-exec"))

	// A stock-named role nothing extra binds stays the platform's.
	got = findings(t, stockCluster(t))
	require.Empty(t, got["system:kubelet-api-admin"])
}

// An injected edit reports only what aggregation added, not edit's by-design
// grants.
func TestInjectedBuiltinReportsOnlyTheInjection(t *testing.T) {
	f := stockCluster(t)
	for i := range f.crs {
		if f.crs[i].Name == "edit" {
			f.crs[i].Rules = append(f.crs[i].Rules,
				rule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"}, []string{"update"}))
		}
	}
	got := findings(t, f)
	require.True(t, fired(got, "edit", "k8s-rbac-csr-approve"))
	require.False(t, fired(got, "edit", "k8s-rbac-secrets-access"), "Secrets access is edit's baseline")
}

// A binding to a role that was not collected is unknown, not clean.
func TestBindingToMissingRoleIsUnknown(t *testing.T) {
	b, _ := clusterRoleBindingAsset(crb("ghost", "not-collected", nil, sa("default", "default")), "prod", time.Now(), roleGrades{}, saInventory{}, nil)
	require.Equal(t, "false", b.Metadata["role_ref_resolved"])
	_, has := b.Metadata["dangerous_perms"]
	require.False(t, has, "an unresolved role must not read as not dangerous")
	c, ok := checks.Default().ByID("k8s-default-service-account-bound")
	require.True(t, ok)
	require.False(t, c.Evaluable(b), "the check cannot conclude clean without the role")

	// The same through the collector: no stock name vouches for a binding whose
	// role is gone.
	f := stockCluster(t)
	f.namespaces = appNamespace()
	f.crbs = append(f.crbs, crb("system:ghost", "system:ghost", bootstrapLabel, sa("default", "default")))
	res, err := withFakeK8s(f).Collect(context.Background(), nil)
	require.NoError(t, err)
	var ghost *asset.Asset
	for i := range res.Assets {
		if res.Assets[i].Name == "system:ghost" {
			ghost = &res.Assets[i]
		}
	}
	require.NotNil(t, ghost)
	require.Equal(t, "false", ghost.Metadata["role_ref_resolved"])
	require.Equal(t, "false", ghost.Metadata["platform_managed"])
	require.False(t, c.Evaluable(*ghost))
}

func TestPlatformManagedBinding(t *testing.T) {
	f := func(name, roleName string, subjects ...rbacv1.Subject) bindingFacts {
		return clusterRoleBindingFacts("c", crb(name, roleName, bootstrapLabel, subjects...))
	}
	require.True(t, platformManagedBinding(f("cluster-admin", "cluster-admin", group("system:masters")), nil))
	require.True(t, platformManagedBinding(f("system:controller:job-controller", "system:controller:job-controller", sa("kube-system", "job-controller")), nil))
	require.True(t, platformManagedBinding(f("system:node", "system:node"), nil))
	require.True(t, platformManagedBinding(f("system:node", "system:node", group("system:nodes")), nil))
	require.False(t, platformManagedBinding(f("cluster-admin", "cluster-admin", group("system:masters"), user("alice")), nil), "extra subject")
	require.False(t, platformManagedBinding(f("cluster-admin", "view", group("system:masters")), nil), "wrong roleRef")
	require.False(t, platformManagedBinding(f("system:controller:job-controller", "cluster-admin", sa("kube-system", "job-controller")), nil), "wrong roleRef")
	require.False(t, platformManagedBinding(f("system:controller:job-controller", "system:controller:job-controller", sa("app", "job-controller")), nil), "wrong SA namespace")
	require.False(t, platformManagedBinding(roleBindingFacts("c", roleBinding("kube-system", "cluster-admin", "ClusterRole", "cluster-admin", group("system:masters"))), nil),
		"a RoleBinding is not the ClusterRoleBinding of the same name")
}

// resources: ["*"] or apiGroups: ["*"] is a wildcard for least privilege but
// NOT wildcard verbs, which a binding inherits as a privilege signal: only
// verbs: ["*"] sets that, and both read-only forms grade the same.
func TestRoleAssets_WildcardVerbsMeansVerbsOnly(t *testing.T) {
	for _, rules := range [][]rbacv1.PolicyRule{
		{rule([]string{"apps"}, []string{"*"}, []string{"get", "list", "watch"})},
		{rule([]string{"*"}, []string{"deployments"}, []string{"get", "list", "watch"})},
	} {
		cr := clusterRoleAsset(clusterRole("reader", nil, rules...), "prod", time.Now())
		require.Equal(t, "false", cr.Metadata["wildcard_verbs"])
		require.Equal(t, "true", cr.Metadata["wildcard_resources"])
		b, _ := clusterRoleBindingAsset(crb("readers", "reader", nil), "prod", time.Now(), roleGrades{cr.ID: cr}, saInventory{}, nil)
		require.Equal(t, "false", b.Metadata["wildcard_verbs"])
	}
	narrow := clusterRoleAsset(clusterRole("pod-reader", nil, rule(core, []string{"pods"}, []string{"get"})), "prod", time.Now())
	require.Equal(t, "false", narrow.Metadata["wildcard_resources"])
	writer := clusterRoleAsset(clusterRole("writer", nil, rule([]string{"*"}, []string{"deployments"}, []string{"patch"})), "prod", time.Now())
	require.Equal(t, "false", writer.Metadata["wildcard_verbs"], "a write verb is not a wildcard verb")
	require.Contains(t, writer.Metadata["dangerous_perms_detail"], dangerCategoryWorkloadWrite, "what the write reaches is its own category")
	star := clusterRoleAsset(clusterRole("star", nil, rule(core, []string{"configmaps"}, []string{"*"})), "prod", time.Now())
	require.Equal(t, "true", star.Metadata["wildcard_verbs"])
}

// A Role in a system namespace is the organisation's when it is not stock.
func TestSystemNamespaceRoleIsNotTrustedByNamespace(t *testing.T) {
	f := stockCluster(t)
	f.roles = append(f.roles, role("kube-system", "debug", starRule))
	f.rbs = append(f.rbs, roleBinding("kube-system", "debug", "Role", "debug", user("alice")))
	got := findings(t, f)
	require.True(t, fired(got, "debug", "k8s-rbac-secrets-access"))
}
