package kubernetes

import (
	"context"
	"fmt"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// rbac_platform.go — which RBAC objects Kubernetes or the managed control plane
// owns, so findings on them (unactionable: the platform recreates them) are
// suppressed without letting anyone borrow that suppression.
//
// Every heuristic marker — a system:/eks:/gke- name, the
// kubernetes.io/bootstrapping=rbac-defaults label, a system namespace, a
// system:-looking subject — is writable or mintable by anyone with RBAC write
// (a CSR approved on the kube-apiserver-client signer mints any CN or O). So
// nothing here trusts a marker:
//   - a binding is the platform's only when its (kind, namespace, name,
//     roleRef, exact subject set) tuple is one a distribution this cluster is
//     KNOWN to run ships (rbac_stock.go, detectDistros);
//   - a role is the platform's only when it is stock for such a distribution,
//     no organisation binding grants it, and its rules grant nothing beyond
//     the stock baseline. API-server auto-reconciliation only ADDS missing
//     rules to a bootstrap role and never removes extra ones, so a stock role
//     with a rule added stays that way: the baseline is what catches it.

// platformEnv is the set of non-upstream distributions this cluster is known
// to run. Upstream entries always apply; the zero value is upstream only,
// which is what an unknown distribution must mean — it fails closed.
type platformEnv map[distro]bool

func (e platformEnv) has(d distro) bool { return d == distroUpstream || e[d] }

// detectDistros reads which distribution the cluster runs from evidence an
// RBAC writer cannot forge:
//   - EKS and GKE from the API server's service-account issuer (identity.go),
//     which the managed control plane sets and the same string the AWS and GCP
//     collectors join the cluster on;
//   - kubeadm from the kube-system/kubeadm-config ConfigMap kubeadm init
//     uploads. This is the only kube-system ConfigMap read: the namespace loop
//     skips system namespaces.
//
// Residual risk, accepted: a forged kube-system/kubeadm-config on a cluster
// that is not kubeadm makes kubeadm's tuples count as stock. Forging it takes
// ConfigMap write in kube-system, and exploiting it takes an identity the
// silenced tuples name (minting a node-bootstrap token or a CSR-signed user).
// kubeadm's tuples grant no more than node bootstrap, and
// kubeadm:cluster-admins still reports at Info.
//
// A failed read leaves the distribution unknown, never assumed.
func detectDistros(ctx context.Context, client k8sAPI, ident clusterIdentity) platformEnv {
	env := platformEnv{}
	switch ident.cloudProvider() {
	case "aws":
		env[distroEKS] = true
	case "gcp":
		env[distroGKE] = true
	}
	cms, err := client.ListConfigMaps(ctx, "kube-system")
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("k8s kubeadm detection skipped; kubeadm RBAC is not treated as stock")
		return env
	}
	if slices.ContainsFunc(cms, func(cm corev1.ConfigMap) bool { return cm.Namespace == "kube-system" && cm.Name == "kubeadm-config" }) {
		env[distroKubeadm] = true
	}
	return env
}

// bindingFacts is the identity of a RoleBinding or ClusterRoleBinding.
type bindingFacts struct {
	kind      string // "ClusterRoleBinding" or "RoleBinding"
	namespace string
	name      string
	roleKind  string
	roleRef   string
	roleID    string
	subjects  []rbacv1.Subject
}

func clusterRoleBindingFacts(cluster string, crb rbacv1.ClusterRoleBinding) bindingFacts {
	return bindingFacts{kind: "ClusterRoleBinding", name: crb.Name, roleKind: "ClusterRole", roleRef: crb.RoleRef.Name,
		roleID: fmt.Sprintf("%s/clusterrole/%s", cluster, crb.RoleRef.Name), subjects: crb.Subjects}
}

func roleBindingFacts(cluster string, rb rbacv1.RoleBinding) bindingFacts {
	roleID := fmt.Sprintf("%s/namespace/%s/role/%s", cluster, rb.Namespace, rb.RoleRef.Name)
	if rb.RoleRef.Kind == "ClusterRole" {
		roleID = fmt.Sprintf("%s/clusterrole/%s", cluster, rb.RoleRef.Name)
	}
	return bindingFacts{kind: "RoleBinding", namespace: rb.Namespace, name: rb.Name, roleKind: rb.RoleRef.Kind,
		roleRef: rb.RoleRef.Name, roleID: roleID, subjects: rb.Subjects}
}

// subjectKey renders a subject the way the stock tables spell it. A
// ServiceAccount's namespace is part of its identity; a User's or Group's is not.
func subjectKey(kind, namespace, name string) string {
	if kind == rbacv1.ServiceAccountKind {
		return kind + ":" + namespace + ":" + name
	}
	return kind + ":" + name
}

func subjUser(name string) string  { return subjectKey(rbacv1.UserKind, "", name) }
func subjGroup(name string) string { return subjectKey(rbacv1.GroupKind, "", name) }
func subjSA(ns, n string) string   { return subjectKey(rbacv1.ServiceAccountKind, ns, n) }

type taggedBinding struct {
	distro distro
	stockBinding
}

type taggedRole struct {
	distro distro
	stockRole
}

func bindingKey(kind, namespace, name string) string { return kind + "/" + namespace + "/" + name }
func stockRoleKey(namespace, name string) string     { return namespace + "/" + name }

// stockBindingIndex and stockRoleIndex index rbac_stock.go's tables; a name
// may be stock for more than one distribution.
var stockBindingIndex, stockRoleIndex = func() (map[string][]taggedBinding, map[string][]taggedRole) {
	bindings, roles := map[string][]taggedBinding{}, map[string][]taggedRole{}
	for _, src := range stockSources {
		for _, b := range src.bindings {
			for _, set := range b.subjectSets {
				slices.Sort(set)
			}
			k := bindingKey(b.kind, b.namespace, b.name)
			bindings[k] = append(bindings[k], taggedBinding{src.distro, b})
		}
		for _, r := range src.roles {
			k := stockRoleKey(r.namespace, r.name)
			roles[k] = append(roles[k], taggedRole{src.distro, r})
		}
	}
	return bindings, roles
}()

// platformManagedBinding reports whether a binding is exactly one a known
// distribution ships: same kind, namespace, name and roleRef, and the same
// subject set.
func platformManagedBinding(b bindingFacts, env platformEnv) bool {
	got := make([]string, 0, len(b.subjects))
	for _, s := range b.subjects {
		got = append(got, subjectKey(s.Kind, s.Namespace, s.Name))
	}
	slices.Sort(got)
	got = slices.Compact(got)
	for _, stock := range stockBindingIndex[bindingKey(b.kind, b.namespace, b.name)] {
		if !env.has(stock.distro) || stock.roleKind != b.roleKind || stock.roleRef != b.roleRef {
			continue
		}
		if slices.ContainsFunc(stock.subjectSets, func(set []string) bool { return slices.Equal(set, got) }) {
			return true
		}
	}
	return false
}

// platformClusterAdmin reports whether a platform-managed binding grants
// cluster-admin to anyone but system:masters (kubeadm:cluster-admins,
// eks:addon-cluster-admin). Shipped by the platform, but a standing admin
// grant a human should know exists: k8s-cluster-admin-binding reports it at
// Info rather than suppressing it.
func platformClusterAdmin(b bindingFacts) bool {
	if b.roleKind != "ClusterRole" || b.roleRef != "cluster-admin" {
		return false
	}
	mastersOnly := len(b.subjects) == 1 && b.subjects[0].Kind == rbacv1.GroupKind && b.subjects[0].Name == "system:masters"
	return !mastersOnly
}

// stockRoleFor returns the stock baseline for a role on a known distribution.
// When the name is stock for several known distributions the baselines are
// unioned: either shipping it explains the grant.
func stockRoleFor(env platformEnv, namespace, name string) (stockRole, bool) {
	var out stockRole
	found := false
	for _, r := range stockRoleIndex[stockRoleKey(namespace, name)] {
		if !env.has(r.distro) {
			continue
		}
		if found {
			out.wildVerbs = out.wildVerbs || r.wildVerbs
			out.wildResources = out.wildResources || r.wildResources
			out.detail += "," + r.detail
			continue
		}
		out, found = r.stockRole, true
	}
	return out, found
}

// platformUsers are the User subjects the matched non-upstream distributions'
// own bindings name: control-plane components of that provider, which the
// must-fix classifier must not read as identities from outside the cluster.
// Upstream's are left out on purpose (on an unknown distribution a User stays
// external), and so is system:anonymous, which is everyone.
func platformUsers(env platformEnv) map[string]bool {
	out := map[string]bool{}
	for _, src := range stockSources {
		if src.distro == distroUpstream || !env.has(src.distro) {
			continue
		}
		for _, b := range src.bindings {
			for _, set := range b.subjectSets {
				for _, s := range set {
					if name, ok := strings.CutPrefix(s, rbacv1.UserKind+":"); ok && name != "system:anonymous" {
						out[name] = true
					}
				}
			}
		}
	}
	return out
}

// platformSubjects lists, in the binding's own "Kind/Name" spelling, the
// subjects that are the provider's control-plane Users (platformUsers).
func platformSubjects(subjects []rbacv1.Subject, users map[string]bool) string {
	var out []string
	for _, s := range subjects {
		if s.Kind == rbacv1.UserKind && users[s.Name] {
			out = append(out, s.Kind+"/"+s.Name)
		}
	}
	return strings.Join(out, ",")
}

// orgBoundRoles returns the asset IDs of the roles that at least one
// organisation-owned binding (platformManagedBinding false) references.
func orgBoundRoles(cluster string, crbs []rbacv1.ClusterRoleBinding, rbs []rbacv1.RoleBinding, env platformEnv) map[string]bool {
	out := map[string]bool{}
	for _, b := range crbs {
		if f := clusterRoleBindingFacts(cluster, b); !platformManagedBinding(f, env) {
			out[f.roleID] = true
		}
	}
	for _, b := range rbs {
		if f := roleBindingFacts(cluster, b); !platformManagedBinding(f, env) {
			out[f.roleID] = true
		}
	}
	return out
}

// builtinUserFacing are the ClusterRoles the binding checks match by name
// (privilegedRoleRef, k8s-cluster-admin-binding, k8s-*-admin-edit), so an
// organisation binding to one is reported there and does not reclaim the
// role; only what exceeds the stock baseline is reported on the role itself.
var builtinUserFacing = map[string]bool{"cluster-admin": true, "admin": true, "edit": true, "view": true}

// gradePlatformRole decides whether a collected role is the platform's. Not
// stock on a known distribution, or granted by an organisation binding: it is
// the organisation's and reports in full. Otherwise it is suppressed when it
// grants nothing beyond its stock baseline, and reclaimed reporting ONLY the
// excess when it does — an aggregated-in rule on view, or a rule added to a
// system:controller role, which reconciliation will never take away.
func gradePlatformRole(a *asset.Asset, env platformEnv, orgBound map[string]bool) {
	namespace := a.Metadata["namespace"]
	stock, ok := stockRoleFor(env, namespace, a.Name)
	if !ok {
		return
	}
	builtin := namespace == "" && builtinUserFacing[a.Name]
	if orgBound[a.ID] && !builtin {
		return
	}
	injected := beyondBaseline(a.Metadata["dangerous_perms_detail"], stock.detail)
	wildVerbs := a.Metadata["wildcard_verbs"] == "true" && !stock.wildVerbs
	wildResources := a.Metadata["wildcard_resources"] == "true" && !stock.wildResources
	if len(injected) == 0 && !wildVerbs && !wildResources {
		a.Metadata["platform_managed"] = "true"
		a.Metadata["dangerous_perms"] = "false"
		return
	}
	a.Metadata["dangerous_perms_detail"] = strings.Join(injected, ",")
	a.Metadata["dangerous_perms"] = fmt.Sprintf("%t", len(injected) > 0)
	a.Metadata["wildcard_verbs"] = fmt.Sprintf("%t", wildVerbs)
	a.Metadata["wildcard_resources"] = fmt.Sprintf("%t", wildResources)
}

// beyondBaseline returns the detail entries the baseline does not explain. A
// scoped entry is explained by the same capability unscoped; the reverse is
// an escalation.
func beyondBaseline(detail, baseline string) []string {
	base := map[string]bool{}
	for _, c := range strings.Split(baseline, ",") {
		base[strings.TrimSpace(c)] = true
	}
	var out []string
	for _, c := range strings.Split(detail, ",") {
		c = strings.TrimSpace(c)
		if c == "" || base[c] || base[strings.TrimSuffix(c, dangerSuffixScoped)] {
			continue
		}
		out = append(out, c)
	}
	return out
}
