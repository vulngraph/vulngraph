package kubernetes

import (
	"fmt"
	"slices"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// serviceAccountID is the one place a ServiceAccount asset ID is spelled. The
// binding producers below emit `binds` edges keyed on it and the collector records
// which of those IDs it actually saw, so a divergence between the two spellings
// would make every RBAC edge dangling — the failure this helper exists to prevent.
func serviceAccountID(cluster, namespace, name string) string {
	if namespace == "" {
		namespace = "default"
	}
	return fmt.Sprintf("%s/namespace/%s/serviceaccount/%s", cluster, namespace, name)
}

// saInventory is what the collector proved about ServiceAccounts this sweep, so
// the RBAC producers can refuse to emit a `binds` edge to a subject that does
// not exist — a binding's subject list is whatever was written there, including
// references left behind by things long since deleted (e.g. a Helm-managed SA
// whose namespace is gone).
//
// Both fields are POSITIVE evidence, and absence of evidence fails OPEN: a
// namespace whose ServiceAccount list errored is not in listedNamespaces, so its
// subjects are still emitted. Only a subject the collector can PROVE is gone —
// either its namespace does not exist, or its namespace was listed successfully
// and it was not in the result — is suppressed.
type saInventory struct {
	ids              map[string]bool // ServiceAccount asset IDs actually collected
	existsNamespaces map[string]bool // every namespace the cluster returned
	listedNamespaces map[string]bool // namespaces whose SA list succeeded
}

func newSAInventory(namespaces []corev1.Namespace) saInventory {
	inv := saInventory{
		ids:              map[string]bool{},
		existsNamespaces: make(map[string]bool, len(namespaces)),
		listedNamespaces: map[string]bool{},
	}
	for _, ns := range namespaces {
		inv.existsNamespaces[ns.Name] = true
	}
	return inv
}

// provablyGone reports whether this ServiceAccount subject is known not to exist.
func (inv saInventory) provablyGone(namespace, id string) bool {
	if namespace == "" || !inv.existsNamespaces[namespace] {
		return len(inv.existsNamespaces) > 0
	}
	return inv.listedNamespaces[namespace] && !inv.ids[id]
}

func serviceAccountAsset(sa corev1.ServiceAccount, cluster string, now time.Time) asset.Asset {
	ns := sa.Namespace
	if ns == "" {
		ns = "default"
	}
	return asset.Asset{
		ID:       serviceAccountID(cluster, ns, sa.Name),
		Name:     sa.Name,
		Type:     "k8s_service_account", // canonical type used by correlationTypes + gcp_wif correlator
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     sa.Labels,
		Metadata: map[string]string{
			"namespace": ns,
			// GKE Workload Identity annotation — maps this SA to a GCP service account.
			// Key MUST match what the gcp_wif correlator reads (the raw annotation key)
			// or federated_access edges silently never emit.
			"iam.gke.io/gcp-service-account": sa.Annotations["iam.gke.io/gcp-service-account"],
			// EKS IRSA annotation — maps this SA to an AWS IAM role.
			"exec_role": sa.Annotations["eks.amazonaws.com/role-arn"],
			// Whether pods on this SA get its token mounted unless their own spec
			// says otherwise (unset means yes).
			"automount_token": fmt.Sprintf("%t", effectiveAutomount(sa.AutomountServiceAccountToken)),
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

func clusterRoleAsset(cr rbacv1.ClusterRole, cluster string, now time.Time) asset.Asset {
	rules := fmt.Sprintf("%d", len(cr.Rules))
	wildcardVerbs := hasWildcard(cr.Rules)
	// Categories, not just a boolean: the specific capability is what a responder
	// needs ("secrets-read" is a credential-theft path, "pod-exec" is code
	// execution) and what the finding quotes as evidence.
	dangerous := dangerousPermissionCategories(cr.Rules)
	return asset.Asset{
		ID:       fmt.Sprintf("%s/clusterrole/%s", cluster, cr.Name),
		Name:     cr.Name,
		Type:     "k8s_cluster_role",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     cr.Labels,
		Metadata: map[string]string{
			"rule_count":     rules,
			"wildcard_verbs": fmt.Sprintf("%t", wildcardVerbs),
			// resources: ["*"] under any verb, read-only included: every resource type
			// in the rule's groups, including ones added later (CRDs). Kept apart
			// from wildcard_verbs, which bindings inherit as a privilege signal.
			"wildcard_resources": fmt.Sprintf("%t", hasWildcardResources(cr.Rules)),
			// The check reads dangerous_perms; the detail stays populated when
			// gradePlatformRole (rbac_platform.go) suppresses a stock role, so a
			// query or responder can still see what it grants.
			"dangerous_perms":        fmt.Sprintf("%t", len(dangerous) > 0),
			"dangerous_perms_detail": strings.Join(dangerous, ","),
			"platform_managed":       "false",
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// roleGrades indexes the privilege grade of every collected Role and ClusterRole
// by its asset ID, so a binding can be stamped with what the role it references
// actually grants. Built from the role ASSETS rather than recomputed from the
// rules, so a binding can never disagree with the role it points at — including
// the platform-managed suppression (without it, `admin`/`edit`/system:* wildcard
// verbs would fire on nearly every binding that references them).
type roleGrades map[string]asset.Asset

// stampRoleRef copies the referenced role's privilege grade onto a binding, since
// checks.privilegedRoleRef reads dangerous_perms/wildcard_verbs ON THE BINDING,
// not the role.
//
// role_ref_resolved records whether the referenced role was found at all. A
// binding to a role that was not collected must read as unknown rather than as a
// clean "not privileged" — absence of the role is not evidence of safety.
func stampRoleRef(a *asset.Asset, roleID string, grades roleGrades) {
	role, ok := grades[roleID]
	if !ok {
		a.Metadata["role_ref_resolved"] = "false"
		return
	}
	platform := role.Metadata["platform_managed"] == "true"
	a.Metadata["role_ref_resolved"] = "true"
	a.Metadata["dangerous_perms"] = role.Metadata["dangerous_perms"]
	// wildcard_verbs is suppressed for platform-managed roles the same way
	// dangerous_perms already is on the role itself. On the ROLE the raw boolean
	// is informational, but on a BINDING it is a check input: privilegedRoleRef
	// ORs the two, and most system:/gke- ClusterRoles carry `verbs: ["*"]` by
	// design, so inheriting it unsuppressed would fire
	// k8s-rolebinding-default-service-account-bound on much of the estate — the
	// exact fire-on-everything pattern that check is scoped to avoid. The
	// built-ins that DO matter (cluster-admin, admin, edit) are matched by name
	// in checks.privilegedRoleRef and do not depend on this key.
	a.Metadata["wildcard_verbs"] = fmt.Sprintf("%t", role.Metadata["wildcard_verbs"] == "true" && !platform)
	a.Metadata["dangerous_perms_detail"] = role.Metadata["dangerous_perms_detail"]
	a.Metadata["role_platform_managed"] = role.Metadata["platform_managed"]
	// The role's own wildcard flag, never platform-suppressed: a grant to
	// everyone is judged on what the role actually allows, since the
	// suppression's markers are writable (k8s-privileged-binding-to-everyone).
	a.Metadata["role_wildcard_verbs"] = role.Metadata["wildcard_verbs"]
}

// stampPlatformBinding records what the stock tables say about a binding:
// platform_managed (the exact tuple ships on a known distribution),
// platform_cluster_admin (such a binding nonetheless hands out cluster-admin
// beyond system:masters) and platform_subjects (its subjects that are the
// provider's own control-plane Users, for the must-fix classifier).
func stampPlatformBinding(a *asset.Asset, b bindingFacts, env platformEnv) {
	platform := platformManagedBinding(b, env)
	a.Metadata["platform_managed"] = fmt.Sprintf("%t", platform)
	a.Metadata["platform_cluster_admin"] = fmt.Sprintf("%t", platform && platformClusterAdmin(b))
	a.Metadata["platform_subjects"] = platformSubjects(b.subjects, platformUsers(env))
}

func clusterRoleBindingAsset(crb rbacv1.ClusterRoleBinding, cluster string, now time.Time, grades roleGrades, known saInventory, env platformEnv) (asset.Asset, []asset.Edge) {
	id := fmt.Sprintf("%s/clusterrolebinding/%s", cluster, crb.Name)
	var subjects []string
	for _, s := range crb.Subjects {
		subjects = append(subjects, fmt.Sprintf("%s/%s", s.Kind, s.Name))
	}
	a := asset.Asset{
		ID:       id,
		Name:     crb.Name,
		Type:     "k8s_cluster_role_binding",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     crb.Labels,
		Metadata: map[string]string{
			"role_ref": crb.RoleRef.Name,
			"subjects": strings.Join(subjects, ","),
		},
		DiscoveredAt: now, LastSeen: now,
	}
	stampPlatformBinding(&a, clusterRoleBindingFacts(cluster, crb), env)
	roleID := fmt.Sprintf("%s/clusterrole/%s", cluster, crb.RoleRef.Name)
	stampRoleRef(&a, roleID, grades)
	edges := []asset.Edge{{
		SrcID: id, SrcType: "k8s_cluster_role_binding",
		DstID: roleID, DstType: "k8s_cluster_role",
		EdgeType: "binds",
	}}
	// Emit binds edges to each ServiceAccount subject so RBAC chains are traversable.
	// Only ServiceAccount subjects produce assets in our graph; User/Group are skipped,
	// and so is any subject the collector proved does not exist (see saInventory).
	for _, subj := range crb.Subjects {
		if subj.Kind != "ServiceAccount" {
			continue
		}
		ns := subj.Namespace
		if ns == "" {
			ns = "default"
		}
		saID := serviceAccountID(cluster, ns, subj.Name)
		if known.provablyGone(ns, saID) {
			continue
		}
		edges = append(edges, asset.Edge{
			SrcID: saID, SrcType: "k8s_service_account", // canonical type (matches serviceAccountAsset + correlationTypes)
			DstID: id, DstType: "k8s_cluster_role_binding",
			EdgeType: "binds",
		})
	}
	return a, edges
}

// roleAsset maps a namespaced Role to a k8s_role asset. Metadata mirrors
// clusterRoleAsset exactly (same hasWildcard/dangerousPermissionCategories
// reuse over the shared []rbacv1.PolicyRule shape) plus namespace, since a
// Role's rules are namespace-scoped rather than cluster-wide.
func roleAsset(role rbacv1.Role, cluster string, now time.Time) asset.Asset {
	rules := fmt.Sprintf("%d", len(role.Rules))
	wildcardVerbs := hasWildcard(role.Rules)
	dangerous := dangerousPermissionCategories(role.Rules)
	return asset.Asset{
		ID:       fmt.Sprintf("%s/namespace/%s/role/%s", cluster, role.Namespace, role.Name),
		Name:     role.Name,
		Type:     "k8s_role",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     role.Labels,
		Metadata: map[string]string{
			"namespace":      role.Namespace,
			"rule_count":     rules,
			"wildcard_verbs": fmt.Sprintf("%t", wildcardVerbs),
			// resources: ["*"] under any verb, read-only included: every resource type
			// in the rule's groups, including ones added later (CRDs). Kept apart
			// from wildcard_verbs, which bindings inherit as a privilege signal.
			"wildcard_resources": fmt.Sprintf("%t", hasWildcardResources(role.Rules)),
			// See clusterRoleAsset: graded by gradePlatformRole.
			"dangerous_perms":        fmt.Sprintf("%t", len(dangerous) > 0),
			"dangerous_perms_detail": strings.Join(dangerous, ","),
			"platform_managed":       "false",
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// roleBindingAsset maps a namespaced RoleBinding to a k8s_role_binding asset
// plus its binds edges. Unlike ClusterRoleBinding, RoleRef.Kind here is either
// "Role" or "ClusterRole" — role_ref_kind records which, so a namespaced Role
// legitimately named "admin" is never confused with the built-in ClusterRole
// of the same name.
func roleBindingAsset(rb rbacv1.RoleBinding, cluster string, now time.Time, grades roleGrades, known saInventory, env platformEnv) (asset.Asset, []asset.Edge) {
	id := fmt.Sprintf("%s/namespace/%s/rolebinding/%s", cluster, rb.Namespace, rb.Name)
	var subjects []string
	for _, s := range rb.Subjects {
		subjects = append(subjects, fmt.Sprintf("%s/%s", s.Kind, s.Name))
	}
	a := asset.Asset{
		ID:       id,
		Name:     rb.Name,
		Type:     "k8s_role_binding",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     rb.Labels,
		Metadata: map[string]string{
			"namespace":     rb.Namespace,
			"role_ref":      rb.RoleRef.Name,
			"role_ref_kind": rb.RoleRef.Kind,
			"subjects":      strings.Join(subjects, ","),
		},
		DiscoveredAt: now, LastSeen: now,
	}
	stampPlatformBinding(&a, roleBindingFacts(cluster, rb), env)

	// Kind dispatch: a RoleBinding can reference either a namespaced Role (same
	// namespace as the binding) or a cluster-wide ClusterRole — the existing
	// ClusterRole asset, which is what makes an already-collected dangerous
	// ClusterRole finally show its namespaced subjects.
	var dstID, dstType string
	if rb.RoleRef.Kind == "ClusterRole" {
		dstID = fmt.Sprintf("%s/clusterrole/%s", cluster, rb.RoleRef.Name)
		dstType = "k8s_cluster_role"
	} else {
		dstID = fmt.Sprintf("%s/namespace/%s/role/%s", cluster, rb.Namespace, rb.RoleRef.Name)
		dstType = "k8s_role"
	}
	stampRoleRef(&a, dstID, grades)
	edges := []asset.Edge{{
		SrcID: id, SrcType: "k8s_role_binding",
		DstID: dstID, DstType: dstType,
		EdgeType: "binds",
	}}

	// Emit binds edges to each ServiceAccount subject. subject.Namespace is
	// commonly a DIFFERENT namespace than the binding's own, so it must always
	// be honoured when set; only fall back to the binding's own namespace when
	// empty (never "default" — that fallback is only correct for a
	// cluster-scoped binding, and rbacv1 defines no default here).
	for _, subj := range rb.Subjects {
		if subj.Kind != "ServiceAccount" {
			continue
		}
		ns := subj.Namespace
		if ns == "" {
			ns = rb.Namespace
		}
		saID := serviceAccountID(cluster, ns, subj.Name)
		if known.provablyGone(ns, saID) {
			continue
		}
		edges = append(edges, asset.Edge{
			SrcID: saID, SrcType: "k8s_service_account",
			DstID: id, DstType: "k8s_role_binding",
			EdgeType: "binds",
		})
	}
	return a, edges
}

// hasWildcardResources reports whether any rule names resources: ["*"] or
// apiGroups: ["*"], whatever its verbs. hasWildcard reads verbs only, since its
// result is a privilege signal a binding inherits; least privilege (CIS 5.1.3)
// objects to the read-only form too.
func hasWildcardResources(rules []rbacv1.PolicyRule) bool {
	return slices.ContainsFunc(rules, func(r rbacv1.PolicyRule) bool {
		return slices.Contains(r.Resources, "*") || slices.Contains(r.APIGroups, "*")
	})
}

// hasWildcard reports whether any rule grants verbs: ["*"] — wildcard VERBS
// only. A "*" in resources or apiGroups is wildcard_resources; whatever such a
// rule can write that matters is a dangerous_perms category of its own, so the
// flag a binding inherits never depends on which list carries the "*".
func hasWildcard(rules []rbacv1.PolicyRule) bool {
	return slices.ContainsFunc(rules, func(r rbacv1.PolicyRule) bool { return slices.Contains(r.Verbs, "*") })
}

// Dangerous-permission category labels, emitted in dangerous_perms_detail and
// read by the per-capability k8s-rbac-* checks (internal/checks/k8s_rbac_grants.go).
const (
	dangerCategorySecretsRead   = "secrets-read"
	dangerCategorySecretsWrite  = "secrets-write"
	dangerCategoryPodExec       = "pod-exec"
	dangerCategoryPodCreate     = "pod-create"
	dangerCategoryWorkloadWrite = "workload-create"
	dangerCategoryTokenMint     = "token-mint"
	dangerCategoryNodeProxy     = "node-proxy"
	dangerCategoryRBACEscalate  = "rbac-escalate"
	dangerCategoryCSRApprove    = "csr-approve"
	dangerCategoryWebhookHijack = "admission-webhook"
	dangerCategoryHostMount     = "host-mount"
	// dangerSuffixScoped marks a category whose rule was confined with
	// resourceNames, so it grants the capability over named objects only.
	dangerSuffixScoped = "(scoped)"
)

// dangerousPermissionCategories returns the distinct high-impact capabilities the
// rules grant, in a stable order. Empty means none.
//
// API groups are honoured — "secrets" and "pods/exec" only mean what they mean
// in the core ("") group, so a CRD coincidentally named "secrets" in another
// group does not count. resourceNames scoping is recorded rather than dropping
// the finding: a rule confined to named objects is still reported, since reading
// even one credential-bearing Secret is credential theft, but the scope is
// visible to a responder.
func dangerousPermissionCategories(rules []rbacv1.PolicyRule) []string {
	var found []string
	seen := map[string]bool{}
	add := func(category string, scoped bool) {
		if scoped {
			category += dangerSuffixScoped
		}
		if !seen[category] {
			seen[category] = true
			found = append(found, category)
		}
	}

	for _, r := range rules {
		verbs := newRBACSet(r.Verbs)
		groups := newRBACSet(r.APIGroups)
		// resourceNames confines a rule to named objects. Note Kubernetes ignores
		// it for list/watch (those verbs cannot be object-scoped), so a rule that
		// grants list/watch is never really scoped by it.
		scoped := len(r.ResourceNames) > 0 && !verbs.any("list", "watch", "*")

		readVerb := verbs.any("get", "list", "watch", "*")
		writeVerb := verbs.any("create", "update", "patch", "delete", "deletecollection", "*")
		createVerb := verbs.any("create", "*")
		// Mutating a workload controller is as powerful as creating one: patching an
		// existing Deployment's serviceAccountName or image assumes any SA in the
		// namespace just as well. Requiring literal `create` would miss the very common
		// "editor"-shaped role that grants patch/update but not create.
		mutateVerb := verbs.any("create", "update", "patch", "*")
		core := groups.any("", "*")
		rbacGroup := groups.any("rbac.authorization.k8s.io", "*")

		// escalate/bind/impersonate are privesc regardless of which resource they
		// are attached to: impersonate targets users/groups/serviceaccounts, and
		// escalate/bind defeat the RBAC privilege-escalation prevention itself.
		if verbs.any("escalate", "bind", "impersonate") {
			add(dangerCategoryRBACEscalate, false)
		}

		for _, res := range expandWildcardResources(r.Resources) {
			switch res {
			case "users", "groups", "serviceaccounts", "uids":
				// verbs: ["*"] includes impersonate, which the explicit-verb test
				// above cannot see.
				if verbs.any("impersonate", "*") && groups.any("", "authentication.k8s.io", "*") {
					add(dangerCategoryRBACEscalate, false)
				}
			case "secrets":
				if !core {
					continue
				}
				if readVerb {
					add(dangerCategorySecretsRead, scoped)
				}
				if writeVerb {
					// Writing a Secret can plant credentials or overwrite ones a
					// workload trusts.
					add(dangerCategorySecretsWrite, scoped)
				}
			case "pods/exec", "pods/attach", "pods/ephemeralcontainers",
				"pods/portforward", "pods/proxy":
				// pods/ephemeralcontainers is the modern debug-container path to the
				// same outcome as exec. portforward and proxy reach any port inside
				// any pod, which is equivalent access by a different mechanism.
				// The connection is a create (exec/attach/portforward) or a get
				// (proxy, websocket exec); list/watch reach nothing.
				if core && verbs.any("create", "get", "*") {
					add(dangerCategoryPodExec, scoped)
				}
			case "services/proxy":
				// Proxy through a Service to the pods behind it — same reach as
				// pods/proxy, one indirection away.
				if core && verbs.any("create", "get", "*") {
					add(dangerCategoryPodExec, scoped)
				}
			case "pods":
				if core && createVerb {
					// Creating a Pod means choosing its serviceAccountName — i.e.
					// assuming any ServiceAccount in the namespace.
					add(dangerCategoryPodCreate, scoped)
				}
			case "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs":
				// Indirect Pod creation: the controller creates the Pod for you, so
				// the same ServiceAccount-assumption path applies. patch/update count
				// as well as create — see mutateVerb.
				if mutateVerb && groups.any("apps", "batch", "extensions", "*") {
					add(dangerCategoryWorkloadWrite, scoped)
				}
			case "certificatesigningrequests/approval", "signers":
				// Self-approving a CSR mints a client certificate with any subject the
				// requester chooses — including O=system:masters, which the API server
				// authorises as cluster-admin outside RBAC entirely. One of the
				// best-known real takeover primitives.
				if (writeVerb || verbs.any("approve")) && groups.any("certificates.k8s.io", "*") {
					add(dangerCategoryCSRApprove, scoped)
				}
			case "mutatingwebhookconfigurations", "validatingwebhookconfigurations":
				// Registering an admission webhook intercepts every matching API
				// object cluster-wide: rewrite any Pod's serviceAccountName or image
				// in flight, or silently neuter policy enforcement. Total control.
				if writeVerb && groups.any("admissionregistration.k8s.io", "*") {
					add(dangerCategoryWebhookHijack, scoped)
				}
			case "persistentvolumes":
				// A hostPath PersistentVolume mounts the node filesystem into a pod —
				// node compromise, and from there every pod's SA token.
				if core && createVerb {
					add(dangerCategoryHostMount, scoped)
				}
			// NOT detected: coordination.k8s.io/leases write. Leader election is how
			// essentially every controller works, so write access to Leases is close
			// to universal and rarely a privilege gain on its own — flagging it would
			// swamp genuine findings with noise.
			case "serviceaccounts/token":
				if core && createVerb {
					add(dangerCategoryTokenMint, scoped)
				}
			case "nodes/proxy":
				// The kubelet API bypasses the API server's RBAC: exec into any pod
				// on the node and read its ServiceAccount token.
				// A get (or create) reaches the kubelet; list/watch do not.
				if core && verbs.any("create", "get", "*") {
					add(dangerCategoryNodeProxy, scoped)
				}
			case "clusterroles", "clusterrolebindings", "roles", "rolebindings":
				if rbacGroup && writeVerb {
					// Write access to RBAC objects is escalation even without the
					// escalate verb: bind a more privileged role to yourself.
					add(dangerCategoryRBACEscalate, scoped)
				}
			}
		}
	}
	return found
}

// dangerousResources is every resource dangerousPermissionCategories knows, in
// the order its categories are reported.
var dangerousResources = []string{
	"secrets", "pods/exec", "pods/attach", "pods/ephemeralcontainers", "pods/portforward", "pods/proxy",
	"services/proxy", "pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs",
	"certificatesigningrequests/approval", "signers", "mutatingwebhookconfigurations",
	"validatingwebhookconfigurations", "persistentvolumes", "serviceaccounts/token", "nodes/proxy",
	"clusterroles", "clusterrolebindings", "roles", "rolebindings", "users", "groups", "serviceaccounts", "uids",
}

// expandWildcardResources applies RBAC's resource wildcards: "*" names every
// resource and subresource, and "*/<subresource>" that subresource of every
// resource — the only two wildcard forms Kubernetes' ResourceMatches accepts
// ("pods/*" is not one: it matches nothing but a resource literally named so). A
// rule of verbs/resources/apiGroups "*" therefore yields every capability, not
// only the Secrets one; each category's own API-group and verb test
// still applies, so resources: ["*"] in apiGroups: ["apps"] yields only
// workload writes.
func expandWildcardResources(resources []string) []string {
	var out []string
	seen := map[string]bool{}
	push := func(r string) {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, r := range resources {
		switch {
		case r == "*":
			for _, d := range dangerousResources {
				push(d)
			}
		case strings.HasPrefix(r, "*/"):
			suffix := strings.TrimPrefix(r, "*")
			for _, d := range dangerousResources {
				if strings.HasSuffix(d, suffix) {
					push(d)
				}
			}
		default:
			push(r)
		}
	}
	return out
}

// rbacSet is a small membership helper for a PolicyRule's verb/group/resource
// lists, which are unordered and frequently wildcarded.
type rbacSet map[string]struct{}

func newRBACSet(values []string) rbacSet {
	s := make(rbacSet, len(values))
	for _, v := range values {
		s[v] = struct{}{}
	}
	return s
}

func (s rbacSet) any(values ...string) bool {
	for _, v := range values {
		if _, ok := s[v]; ok {
			return true
		}
	}
	return false
}
