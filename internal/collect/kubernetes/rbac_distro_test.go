package kubernetes

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

const (
	eksIssuer     = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
	gkeTestIssuer = "https://container.googleapis.com/v1/projects/p/locations/us-central1/clusters/c"
)

// distroObjects are the RBAC objects kubeadm, EKS and GKE add on top of
// upstream, spelled out from the public sources cited on each table in
// rbac_stock.go. For those tables these in-code fixtures are the ONLY pin —
// no vendored manifest exists — so an entry here and its table row can only
// be checked against each other, not against the distribution itself.
func distroObjects(d distro) *fakeK8s {
	f := &fakeK8s{}
	readCM := func(name string) rbacv1.PolicyRule { return rule(core, []string{"configmaps"}, []string{"get"}, name) }
	apps, csr := []string{"apps"}, []string{"certificates.k8s.io"}
	switch d {
	case distroKubeadm:
		f.crs = []rbacv1.ClusterRole{
			clusterRole("kubeadm:get-nodes", nil, rule(core, []string{"nodes"}, []string{"get"})),
			clusterRole("system:coredns", nil,
				rule(core, []string{"endpoints", "services", "pods", "namespaces"}, []string{"list", "watch"}),
				rule(core, []string{"nodes"}, []string{"get"}),
				rule([]string{"discovery.k8s.io"}, []string{"endpointslices"}, []string{"list", "watch"})),
		}
		f.roles = []rbacv1.Role{
			role("kube-system", "kubeadm:kubelet-config", readCM("kubelet-config")),
			role("kube-system", "kubeadm:nodes-kubeadm-config", readCM("kubeadm-config")),
			role("kube-system", "kube-proxy", readCM("kube-proxy")),
			role("kube-system", "kubeadm:kubeadm-certs", rule(core, []string{"secrets"}, []string{"get"}, "kubeadm-certs")),
			role("kube-public", "kubeadm:bootstrap-signer-clusterinfo", readCM("cluster-info")),
		}
		f.crbs = []rbacv1.ClusterRoleBinding{
			crb("kubeadm:cluster-admins", "cluster-admin", nil, group("kubeadm:cluster-admins")),
			crb("kubeadm:kubelet-bootstrap", "system:node-bootstrapper", nil, group(nodeToken)),
			crb("kubeadm:node-autoapprove-bootstrap", "system:certificates.k8s.io:certificatesigningrequests:nodeclient", nil, group(nodeToken)),
			crb("kubeadm:node-autoapprove-certificate-rotation", "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient", nil, group("system:nodes")),
			crb("kubeadm:get-nodes", "kubeadm:get-nodes", nil, group(nodeToken)),
			crb("kubeadm:node-proxier", "system:node-proxier", nil, sa("kube-system", "kube-proxy")),
			crb("kubeadm:apiserver-kubelet-client", "system:kubelet-api-admin", nil, user("kube-apiserver-kubelet-client")),
			crb("system:coredns", "system:coredns", nil, sa("kube-system", "coredns")),
		}
		f.rbs = []rbacv1.RoleBinding{
			roleBinding("kube-system", "kubeadm:kubelet-config", "Role", "kubeadm:kubelet-config", group("system:nodes"), group(nodeToken)),
			roleBinding("kube-system", "kubeadm:nodes-kubeadm-config", "Role", "kubeadm:nodes-kubeadm-config", group(nodeToken), group("system:nodes")),
			roleBinding("kube-system", "kube-proxy", "Role", "kube-proxy", group(nodeToken)),
			roleBinding("kube-system", "kubeadm:kubeadm-certs", "Role", "kubeadm:kubeadm-certs", group(nodeToken)),
			roleBinding("kube-public", "kubeadm:bootstrap-signer-clusterinfo", "Role", "kubeadm:bootstrap-signer-clusterinfo", user("system:anonymous")),
		}
	case distroEKS:
		f.crs = []rbacv1.ClusterRole{
			// default-roles-users.html, verbatim.
			clusterRole("eks:k8s-metrics", nil,
				rbacv1.PolicyRule{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}},
				rule(core, []string{"endpoints", "nodes", "pods"}, []string{"list"}),
				rule(apps, []string{"deployments"}, []string{"list"})),
			// aws-vpc-cni chart, ANNOTATE_POD_IP on.
			clusterRole("aws-node", nil,
				rule([]string{"crd.k8s.amazonaws.com"}, []string{"eniconfigs"}, []string{"list", "watch", "get"}),
				rule(core, []string{"namespaces", "nodes"}, []string{"list", "watch", "get"}),
				rule(core, []string{"pods"}, []string{"list", "watch", "get", "patch"}),
				rule([]string{"", "events.k8s.io"}, []string{"events"}, []string{"create", "patch", "list"}),
				rule([]string{"vpcresources.k8s.aws"}, []string{"cninodes"}, []string{"get", "list", "watch", "patch"})),
			// aws-ebs-csi-driver chart, clusterrole-provisioner.yaml.
			clusterRole("ebs-external-provisioner-role", nil,
				rule(core, []string{"persistentvolumes"}, []string{"get", "list", "watch", "create", "patch", "delete"}),
				rule(core, []string{"persistentvolumeclaims"}, []string{"get", "list", "watch", "update"}),
				rule([]string{"storage.k8s.io"}, []string{"storageclasses", "csinodes", "volumeattachments"}, []string{"get", "list", "watch"}),
				rule(core, []string{"events"}, []string{"list", "watch", "create", "update", "patch"}),
				rule(core, []string{"nodes"}, []string{"get", "list", "watch"})),
			// AWS knowledge center: create on certificatesigningrequests/selfnodeserver.
			clusterRole("eks:node-bootstrapper", nil, rule(csr, []string{"certificatesigningrequests/selfnodeserver"}, []string{"create"})),
			// Unconfirmed rule sets (rbac_stock.go).
			clusterRole("vpc-resource-controller-role", nil,
				rule(core, []string{"pods"}, []string{"get", "list", "watch", "patch"}),
				rule(core, []string{"nodes"}, []string{"get", "list", "watch"}),
				rule(core, []string{"events"}, []string{"create", "patch"})),
			clusterRole("eks:certificate-controller-approver", nil,
				rule(csr, []string{"certificatesigningrequests/approval"}, []string{"update"})),
			clusterRole("eks:addon-manager", nil,
				rule(apps, []string{"daemonsets", "deployments"}, []string{"get", "list", "create", "update", "patch"}),
				rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles", "clusterrolebindings"}, []string{"get", "create", "update", "patch"})),
			clusterRole("eks:cloud-controller-manager", nil,
				rule(core, []string{"nodes"}, []string{"get", "list", "watch", "update", "patch"}),
				rule(core, []string{"services/status"}, []string{"patch"}),
				rule(core, []string{"events"}, []string{"create", "patch"})),
			clusterRole("eks:node-manager", nil,
				rule(core, []string{"nodes"}, []string{"get", "list", "watch", "patch"}),
				rule(core, []string{"pods"}, []string{"get", "list", "delete"}),
				rule(core, []string{"pods/eviction"}, []string{"create"})),
		}
		f.roles = []rbacv1.Role{
			role("kube-system", "eks:k8s-metrics",
				rule(apps, []string{"daemonsets"}, []string{"get"}, "aws-node"),
				rule(apps, []string{"deployments"}, []string{"get"}, "vpc-resource-controller")),
		}
		f.crbs = []rbacv1.ClusterRoleBinding{
			crb("eks:k8s-metrics", "eks:k8s-metrics", nil, user("eks:k8s-metrics")),
			crb("aws-node", "aws-node", nil, sa("kube-system", "aws-node")),
			crb("vpc-resource-controller-rolebinding", "vpc-resource-controller-role", nil, user("eks:vpc-resource-controller")),
			crb("eks:addon-cluster-admin", "cluster-admin", nil, user("eks:addon-manager")),
			crb("eks:node-bootstrapper", "eks:node-bootstrapper", nil, group("system:bootstrappers"), group("system:nodes")),
			crb("ebs-csi-provisioner-binding", "ebs-external-provisioner-role", nil, sa("kube-system", "ebs-csi-controller-sa")),
			crb("eks:certificate-controller", "system:controller:certificate-controller", nil, user("eks:certificate-controller")),
			crb("eks:certificate-controller-approver", "eks:certificate-controller-approver", nil, user("eks:certificate-controller-approver")),
			crb("eks:addon-manager", "eks:addon-manager", nil, user("eks:addon-manager")),
			crb("eks:cloud-controller-manager", "eks:cloud-controller-manager", nil, user("eks:cloud-controller-manager")),
			crb("eks:node-manager", "eks:node-manager", nil, user("eks:node-manager")),
			crb("eks:kube-proxy", "system:node-proxier", nil, sa("kube-system", "kube-proxy")),
			crb("eks:kube-proxy-fargate", "system:node-proxier", nil, group("system:node-proxier")),
			crb("eks:kube-proxy-windows", "system:node-proxier", nil, group("eks:kube-proxy-windows")),
		}
		f.rbs = []rbacv1.RoleBinding{
			roleBinding("kube-system", "eks:k8s-metrics", "Role", "eks:k8s-metrics", user("eks:k8s-metrics")),
		}
	case distroGKE:
		// Unconfirmed rule sets (rbac_stock.go).
		f.crs = []rbacv1.ClusterRole{
			clusterRole("system:gcp-controller-manager", nil,
				rule(csr, []string{"certificatesigningrequests/approval"}, []string{"update"}),
				rule(core, []string{"nodes"}, []string{"get", "list", "watch"})),
			clusterRole("gke-metadata-server", nil,
				rule(core, []string{"serviceaccounts/token"}, []string{"create"}),
				rule(core, []string{"pods", "nodes", "serviceaccounts"}, []string{"get", "list", "watch"})),
		}
		f.crbs = []rbacv1.ClusterRoleBinding{
			crb("system:gcp-controller-manager", "system:gcp-controller-manager", nil, user("system:gcp-controller-manager")),
			crb("gke-metadata-server", "gke-metadata-server", nil, sa("kube-system", "gke-metadata-server")),
			crb("kubelet-bootstrap", "system:node-bootstrapper", nil, user("kubelet")),
		}
	}
	return f
}

// withDistro adds d's objects to f and the evidence detectDistros reads for
// it. GKE also gets the vendored kube-up addons.
func withDistro(t *testing.T, f *fakeK8s, d distro) *fakeK8s {
	t.Helper()
	switch d {
	case distroKubeadm:
		f.cms = append(f.cms, corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kubeadm-config"}})
	case distroEKS:
		f.issuer = eksIssuer
	case distroGKE:
		f.issuer = gkeTestIssuer
		loadRBACFixtures(t, f, "testdata/kubeup")
	}
	o := distroObjects(d)
	f.crs = append(f.crs, o.crs...)
	f.roles = append(f.roles, o.roles...)
	f.crbs = append(f.crbs, o.crbs...)
	f.rbs = append(f.rbs, o.rbs...)
	return f
}

// distroCluster is a stock cluster of distribution d; upstream means unknown.
func distroCluster(t *testing.T, d distro) *fakeK8s {
	t.Helper()
	if d == distroUpstream {
		return upstreamCluster(t)
	}
	return withDistro(t, upstreamCluster(t), d)
}

// requireTablesMatch holds a table pair to the objects it was drawn from, both
// ways: every object is in the table with the same tuple or baseline, and
// every table entry is among the objects.
func requireTablesMatch(t *testing.T, objs *fakeK8s, bindings []stockBinding, roles []stockRole) {
	t.Helper()
	table := map[string]stockBinding{}
	for _, b := range bindings {
		table[bindingKey(b.kind, b.namespace, b.name)] = b
	}
	seen := map[string]bool{}
	check := func(f bindingFacts) {
		k := bindingKey(f.kind, f.namespace, f.name)
		seen[k] = true
		b, ok := table[k]
		require.True(t, ok, "binding %s is not in the table", k)
		require.Equal(t, b.roleKind+"/"+b.roleRef, f.roleKind+"/"+f.roleRef, k)
		var got []string
		for _, s := range f.subjects {
			got = append(got, subjectKey(s.Kind, s.Namespace, s.Name))
		}
		slices.Sort(got)
		require.True(t, slices.ContainsFunc(b.subjectSets, func(set []string) bool { return slices.Equal(set, slices.Compact(got)) }),
			"binding %s subjects %v not among %v", k, got, b.subjectSets)
	}
	for _, b := range objs.crbs {
		check(clusterRoleBindingFacts("c", b))
	}
	for _, b := range objs.rbs {
		check(roleBindingFacts("c", b))
	}
	for k := range table {
		require.True(t, seen[k], "table binding %s has no source object", k)
	}

	roleTable := map[string]stockRole{}
	for _, r := range roles {
		roleTable[stockRoleKey(r.namespace, r.name)] = r
	}
	got := map[string]stockRole{}
	add := func(namespace string, meta map[string]string, name string) {
		got[stockRoleKey(namespace, name)] = stockRole{namespace: namespace, name: name,
			wildVerbs: meta["wildcard_verbs"] == "true", wildResources: meta["wildcard_resources"] == "true",
			detail: sortedDetail(meta["dangerous_perms_detail"])}
	}
	for _, r := range objs.crs {
		add("", clusterRoleAsset(r, "c", time.Now()).Metadata, r.Name)
	}
	for _, r := range objs.roles {
		add(r.Namespace, roleAsset(r, "c", time.Now()).Metadata, r.Name)
	}
	for k := range roleTable {
		r := roleTable[k]
		r.detail = sortedDetail(r.detail)
		roleTable[k] = r
	}
	require.Equal(t, roleTable, got, "role baselines must be exactly what the source rules grant")
}

func sortedDetail(d string) string {
	parts := strings.Split(d, ",")
	slices.Sort(parts)
	return strings.Trim(strings.Join(parts, ","), ",")
}

// Upstream and kube-up tables against the vendored manifests, both ways.
func TestStockTablesMatchVendoredSources(t *testing.T) {
	requireTablesMatch(t, upstreamCluster(t), upstreamBindings, upstreamRoles)
	kubeup := &fakeK8s{}
	loadRBACFixtures(t, kubeup, "testdata/kubeup")
	requireTablesMatch(t, kubeup, kubeupBindings, kubeupRoles)
}

// kubeadm, EKS and GKE tables are pinned ONLY to the in-code fixtures in
// distroObjects (no vendored source exists); see rbac_stock.go for which of
// their entries a public source confirms.
func TestStockTablesMatchInCodeFixtures(t *testing.T) {
	requireTablesMatch(t, distroObjects(distroKubeadm), kubeadmBindings, kubeadmRoles)
	requireTablesMatch(t, distroObjects(distroEKS), eksBindings, eksRoles)
	requireTablesMatch(t, distroObjects(distroGKE), gkeBindings, gkeRoles)
}

func TestStockClusterRBACIsSilent(t *testing.T) {
	for _, d := range []distro{distroUpstream, distroKubeadm, distroEKS, distroGKE} {
		t.Run(string(d), func(t *testing.T) {
			f := distroCluster(t, d)
			require.Greater(t, len(f.crbs), 50, "the upstream bootstrap testdata must actually load")
			for _, cr := range f.crs {
				if cr.Name == "admin" || cr.Name == "edit" || cr.Name == "view" {
					require.NotEmpty(t, cr.Rules, "%s must carry its aggregated rules", cr.Name)
				}
			}
			requireSilentAboveInfo(t, findings(t, f))
		})
	}
}

// Reconciliation never removes a rule added to a stock role, so every stock
// role with {*,*,*} added must report the injection — table-driven over every
// entry so a new one cannot skip it.
func TestStockRoleInjectionReports(t *testing.T) {
	for _, src := range stockSources {
		for _, r := range src.roles {
			t.Run(string(src.distro)+"/"+stockRoleKey(r.namespace, r.name), func(t *testing.T) {
				if r.namespace == "" && r.name == "cluster-admin" {
					t.Skip("cluster-admin's stock rule is already {*,*,*}: nothing can exceed it")
				}
				f := distroCluster(t, src.distro)
				injected := false
				if r.namespace == "" {
					for i := range f.crs {
						if f.crs[i].Name == r.name {
							f.crs[i].Rules, injected = append(f.crs[i].Rules, starRule), true
						}
					}
				} else {
					for i := range f.roles {
						if f.roles[i].Namespace == r.namespace && f.roles[i].Name == r.name {
							f.roles[i].Rules, injected = append(f.roles[i].Rules, starRule), true
						}
					}
				}
				require.True(t, injected, "the %s fixture must carry the role", src.distro)
				got := findings(t, f)
				wildcard := "k8s-cluster-role-wildcard-verbs"
				if r.namespace != "" {
					wildcard = "k8s-role-wildcard-verbs"
				}
				if r.wildVerbs {
					// system:kubelet-api-admin and kubelet-api-admin: verbs "*" on
					// nodes/proxy by design. The added rule's Secrets access is what
					// reports; the kubelet access stays the baseline's.
					require.Equal(t, "node-proxy", r.detail, "a new wildcard-verb stock role needs its own assertion here")
					require.True(t, fired(got, r.name, "k8s-rbac-secrets-access"), "got %v", got[r.name])
					require.False(t, fired(got, r.name, "k8s-rbac-node-proxy"), "node-proxy is the stock baseline")
					return
				}
				require.True(t, fired(got, r.name, wildcard), "got %v", got[r.name])
			})
		}
	}
}

// A distribution's objects created fresh on a cluster that is not that
// distribution are anyone's, and report.
func TestFreshDistroObjectsOnWrongDistroReport(t *testing.T) {
	star := func(name string) []rbacv1.ClusterRole { return []rbacv1.ClusterRole{clusterRole(name, nil, starRule)} }
	tests := []struct {
		name     string
		on       distro
		crs      []rbacv1.ClusterRole
		crb      rbacv1.ClusterRoleBinding
		resource string
		check    string
	}{
		{"aws-node on an unknown distro", distroUpstream, star("aws-node"),
			crb("aws-node", "aws-node", nil, sa("kube-system", "aws-node")), "aws-node", "k8s-cluster-role-wildcard-verbs"},
		{"cloud-node-controller on EKS", distroEKS, star("system:controller:cloud-node-controller"),
			crb("system:controller:cloud-node-controller", "system:controller:cloud-node-controller", nil, sa("kube-system", "cloud-node-controller")),
			"system:controller:cloud-node-controller", "k8s-cluster-role-wildcard-verbs"},
		{"eks:addon-cluster-admin on GKE", distroGKE, nil,
			crb("eks:addon-cluster-admin", "cluster-admin", nil, user("eks:addon-manager")), "eks:addon-cluster-admin", "k8s-cluster-admin-binding"},
		{"kubeadm:cluster-admins on an unknown distro", distroUpstream, nil,
			crb("kubeadm:cluster-admins", "cluster-admin", nil, group("kubeadm:cluster-admins")), "kubeadm:cluster-admins", "k8s-cluster-admin-binding"},
		{"kubeadm:cluster-admins on EKS", distroEKS, nil,
			crb("kubeadm:cluster-admins", "cluster-admin", nil, group("kubeadm:cluster-admins")), "kubeadm:cluster-admins", "k8s-cluster-admin-binding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := distroCluster(t, tt.on)
			f.crs = append(f.crs, tt.crs...)
			f.crbs = append(f.crbs, tt.crb)
			got := findings(t, f)
			require.True(t, fired(got, tt.resource, tt.check), "got %v", got[tt.resource])
			require.NotEqual(t, finding.SeverityInfo, got[tt.resource][tt.check], "off its distribution it is not the platform's")
		})
	}
}

// Stock bindings that hand out cluster-admin beyond system:masters are the
// platform's, but a standing admin grant: reported at Info, never silent.
func TestPlatformClusterAdminReportsAtInfo(t *testing.T) {
	got := findings(t, distroCluster(t, distroKubeadm))
	require.Equal(t, finding.SeverityInfo, got["kubeadm:cluster-admins"]["k8s-cluster-admin-binding"])
	require.False(t, fired(got, "cluster-admin", "k8s-cluster-admin-binding"), "the bootstrap system:masters binding stays silent")
	got = findings(t, distroCluster(t, distroEKS))
	require.Equal(t, finding.SeverityInfo, got["eks:addon-cluster-admin"]["k8s-cluster-admin-binding"])
}

// The provider's control-plane Users are recorded as such only on that
// provider's clusters.
func TestPlatformSubjectsOnlyOnMatchingDistro(t *testing.T) {
	b := crb("addon-admin", "view", nil, user("eks:addon-manager"), user("alice"))
	a, _ := clusterRoleBindingAsset(b, "c", time.Now(), roleGrades{}, saInventory{}, platformEnv{distroEKS: true})
	require.Equal(t, "User/eks:addon-manager", a.Metadata["platform_subjects"])
	a, _ = clusterRoleBindingAsset(b, "c", time.Now(), roleGrades{}, saInventory{}, nil)
	require.Empty(t, a.Metadata["platform_subjects"])
	anon := crb("anon", "view", nil, user("system:anonymous"))
	a, _ = clusterRoleBindingAsset(anon, "c", time.Now(), roleGrades{}, saInventory{}, platformEnv{distroKubeadm: true})
	require.Empty(t, a.Metadata["platform_subjects"], "system:anonymous is everyone, never internal")
}

// The distribution is read from the issuer and the kubeadm ConfigMap; nothing
// else, and a failed read is unknown.
func TestDetectDistros(t *testing.T) {
	ctx := t.Context()
	require.Equal(t, platformEnv{distroEKS: true}, detectDistros(ctx, &fakeK8s{}, clusterIdentity{Issuer: eksIssuer}))
	require.Equal(t, platformEnv{distroGKE: true}, detectDistros(ctx, &fakeK8s{}, clusterIdentity{Issuer: gkeTestIssuer}))
	kubeadm := &fakeK8s{cms: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kubeadm-config"}}}}
	require.Equal(t, platformEnv{distroKubeadm: true}, detectDistros(ctx, kubeadm, clusterIdentity{}))
	elsewhere := &fakeK8s{cms: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "kubeadm-config"}}}}
	require.Empty(t, detectDistros(ctx, elsewhere, clusterIdentity{}))
	kubeadm.cmErr = errors.New("forbidden")
	require.Empty(t, detectDistros(ctx, kubeadm, clusterIdentity{}))
}

// A scoped baseline explains only the scoped grant: kubeadm:kubeadm-certs may
// read the one kubeadm-certs Secret, and widened to every Secret it reports.
// The reverse holds: an unscoped baseline explains a scoped grant.
func TestScopedBaselineDoesNotExplainUnscopedGrant(t *testing.T) {
	require.Equal(t, []string{"secrets-read"}, beyondBaseline("secrets-read", "secrets-read(scoped)"))
	require.Empty(t, beyondBaseline("secrets-read(scoped)", "secrets-read"))
	require.Empty(t, beyondBaseline("secrets-read(scoped)", "secrets-read(scoped)"))

	f := distroCluster(t, distroKubeadm)
	for i := range f.roles {
		if f.roles[i].Name == "kubeadm:kubeadm-certs" {
			f.roles[i].Rules = []rbacv1.PolicyRule{rule(core, []string{"secrets"}, []string{"get"})}
		}
	}
	got := findings(t, f)
	require.True(t, fired(got, "kubeadm:kubeadm-certs", "k8s-rbac-secrets-access"), "got %v", got["kubeadm:kubeadm-certs"])
}
