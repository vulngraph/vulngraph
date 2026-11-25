package checks

// rbac_namespaced.go — checks over the namespaced RBAC asset types (k8s_role,
// k8s_role_binding) collected by internal/collect/kubernetes/rbac.go's
// roleAsset/roleBindingAsset. These are the exact siblings of the four
// ClusterRole/ClusterRoleBinding checks in rbac_cluster.go — many
// RoleBindings reference a ClusterRole, including the built-in admin/edit
// ones, so both scopes need the same checks.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var k8sRoleWildcardVerbs = Check{
	ID:          "k8s-role-wildcard-verbs",
	Title:       "Role grants a wildcard rule",
	Description: "The namespaced Role has a policy rule with a wildcard (\"*\") in its verbs, resources, or API groups — granting sweeping access within the namespace (any action, and/or any resource type, and/or any API group). This is overly permissive and violates the principle of least privilege.",
	Remediation: "Replace the wildcard with the specific verbs, resources, and API groups required (e.g. verbs: [\"get\", \"list\"]). Use audit logs to determine what is actually needed.",
	Type:        "rbac",
	// Medium is the ceiling: an RBAC grant is posture, and who holds it — which
	// the must-fix classifier reads from its bindings — is what makes it urgent.
	// A wildcard that also confers a named escalation/credential-theft capability
	// is reported by the matching k8s-rbac-* check as well, not graded up here.
	Severity:  finding.SeverityMedium,
	Provider:  asset.ProviderKubernetes,
	AssetType: "k8s_role",
	Violates: func(a asset.Asset) bool {
		// platform_managed excludes Kubernetes' own bootstrap Roles and GKE's
		// managed ones: they carry wildcards by design and are reverted by the
		// control plane if edited.
		return (a.Metadata["wildcard_verbs"] == "true" || a.Metadata["wildcard_resources"] == "true") &&
			a.Metadata["platform_managed"] != "true"
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["wildcard_verbs"] != "true" {
			// A "*" only in resources or apiGroups — see the ClusterRole sibling.
			return finding.SeverityLow
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"rule_count": a.Metadata["rule_count"]}
		if d := a.Metadata["dangerous_perms_detail"]; d != "" {
			ev["dangerous_capabilities"] = d
		}
		return ev
	},
}

// k8sRoleBindingAdminBinding fires when a RoleBinding grants the built-in
// admin/edit ClusterRole into a namespace: namespace-wide admin, the primary
// privilege-escalation path available to a tenant who can create
// RoleBindings in their own namespace. Gated on role_ref_kind == "ClusterRole"
// so a namespaced Role legitimately named "admin" (a common team convention)
// is never mistaken for the built-in ClusterRole of the same name — see
// TestRoleBindingAsset_RoleRefKindDistinguishesAdminRoleFromAdminClusterRole.
var k8sRoleBindingAdminBinding = Check{
	ID:          "k8s-rolebinding-admin-binding",
	Title:       "RoleBinding grants the built-in admin/edit ClusterRole into a namespace",
	Description: "A RoleBinding grants the built-in 'cluster-admin', 'admin', or 'edit' ClusterRole, scoped to this namespace. 'admin' and 'edit' both grant broad read/write access to almost every resource in the namespace, including Secrets. A tenant who can create RoleBindings in their own namespace can self-grant this, and a review of ClusterRoleBindings alone does not show it.",
	Remediation: "Audit the subjects of this binding. Replace with a scoped, namespaced Role granting only the permissions the workload or team actually needs.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_role_binding",
	// cluster-admin into a namespace is Medium and admin/edit Low: never above
	// k8s-cluster-admin-binding (Medium), the same grant cluster-wide. Who the
	// subjects are is what makes it urgent, and the must-fix classifier reads
	// that from the binding.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["role_ref"] == "cluster-admin" {
			return finding.SeverityMedium
		}
		return finding.SeverityLow
	},
	Violates: func(a asset.Asset) bool {
		if a.Metadata["role_ref_kind"] != "ClusterRole" {
			return false
		}
		switch a.Metadata["role_ref"] {
		case "cluster-admin", "admin", "edit":
			return true
		}
		return false
	},
}

// k8sRoleBindingDefaultServiceAccountBound is the namespaced sibling of
// k8sDefaultServiceAccountBound.
var k8sRoleBindingDefaultServiceAccountBound = Check{
	ID:          "k8s-rolebinding-default-service-account-bound",
	Title:       "RoleBinding grants elevated privileges to default service account",
	Description: "A RoleBinding binds a privileged role to a 'default' service account in this namespace. The default service account is used by pods that do not specify a service account, making this an easy privilege escalation path.",
	Remediation: "Create dedicated service accounts for workloads that need specific permissions. Never bind elevated roles to 'default' service accounts.",
	Type:        "rbac",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_role_binding",
	Violates: func(a asset.Asset) bool {
		// The bound role must actually be privileged. Without this gate the
		// check fired on any default-SA binding at all — including `view`, the
		// read-only built-in, which is not a privilege-escalation path, and
		// Helm charts bind the default SA to it routinely.
		if !privilegedRoleRef(a) {
			return false
		}
		for s := range strings.SplitSeq(a.Metadata["subjects"], ",") {
			if strings.TrimSpace(s) == "ServiceAccount/default" {
				return true
			}
		}
		return false
	},
}

// privilegedRoleRef reports whether a RoleBinding references a role that actually
// confers dangerous power: one of the built-in admin-ish ClusterRoles, or a role
// the collector already graded as carrying dangerous permissions or wildcard verbs.
// `view` and other read-only roles are deliberately excluded.
func privilegedRoleRef(a asset.Asset) bool {
	if refersToClusterRole(a) {
		switch a.Metadata["role_ref"] {
		case "cluster-admin", "admin", "edit":
			return true
		}
	}
	// The collector grades the REFERENCED role and stamps the result on the
	// binding (collect/kubernetes.stampRoleRef). That join lives there because
	// the collector lists roles and bindings together, while the check
	// framework evaluates one asset at a time and, on the normal sync path,
	// only over CHANGED assets — a binding can change in a sweep its role does
	// not, so a cross-asset lookup here would be silently incomplete.
	//
	// Both keys arrive platform-suppressed: a bootstrap or provider-managed
	// role's by-design wildcards do not make every binding to it privileged. An
	// absent key means the roleRef did not resolve (role_ref_resolved=false)
	// and is deliberately NOT read as "not privileged" here — it stays
	// unproven, and the binding is judged on the built-in names alone.
	return a.Metadata["dangerous_perms"] == "true" || a.Metadata["wildcard_verbs"] == "true"
}

// refersToClusterRole reports whether a binding's roleRef names a ClusterRole.
//
// role_ref_kind is only meaningful on a RoleBinding, which may reference
// either a namespaced Role or a ClusterRole. A ClusterRoleBinding has no such
// choice: the Kubernetes API rejects any roleRef whose kind is not
// ClusterRole, so an absent key there is the invariant, not ambiguity —
// reading it as "not a ClusterRole" would make every cluster-scoped branch of
// privilegedRoleRef return false.
func refersToClusterRole(a asset.Asset) bool {
	if a.Type == "k8s_cluster_role_binding" {
		return a.Metadata["role_ref_kind"] == "" || a.Metadata["role_ref_kind"] == "ClusterRole"
	}
	return a.Metadata["role_ref_kind"] == "ClusterRole"
}

// grantToEveryoneIsPrivileged is privilegedRoleRef without the platform
// suppression: for a grant to everyone the role is judged on what it actually
// allows — its capability detail and its own wildcard flag, both stamped
// unsuppressed by the collector. A stock role name is writable by anyone with
// RBAC write (a deleted stock role can be recreated with any rules), and the
// bootstrap roles Kubernetes really binds to everyone (system:discovery,
// system:basic-user, system:public-info-viewer) grant no capability, so
// reading past it costs nothing on a stock cluster. It also catches an
// aggregated `view` that picked up Secrets access.
func grantToEveryoneIsPrivileged(a asset.Asset) bool {
	return privilegedRoleRef(a) || a.Metadata["dangerous_perms_detail"] != "" || a.Metadata["role_wildcard_verbs"] == "true"
}

// everyoneGroups are the built-in RBAC groups that every request belongs to.
// A privileged role bound to one of these grants that privilege to the entire
// world: system:authenticated is every authenticated caller (in a cluster with
// any IdP or an over-broad IAM/RBAC mapping, that is a very large set), and
// system:unauthenticated / system:anonymous is literally anyone who can reach the
// API server.
var everyoneGroups = map[string]bool{
	"Group/system:authenticated":   true,
	"Group/system:unauthenticated": true,
	"Group/system:anonymous":       true,
	"User/system:anonymous":        true,
}

// k8sBindingToEveryone catches the worst possible RBAC misconfiguration: a
// privileged role bound to a group that contains everybody.
//
// Graph edges fan out only to ServiceAccount subjects (User/Group subjects
// produce no asset, so no edge), so a role check alone can miss e.g.
// `cluster-admin` bound to `system:authenticated`. The `subjects` metadata
// records all subject kinds, so this check reads it directly instead of
// relying on graph edges. Gating on the role being privileged keeps this
// silent for the benign built-in bindings (system:basic-user,
// system:discovery, …) and loud for the one that matters.
var k8sBindingToEveryone = Check{
	ID:          "k8s-privileged-binding-to-everyone",
	Title:       "Privileged role is bound to a group containing all users",
	Description: "A ClusterRoleBinding or RoleBinding grants a privileged role (cluster-admin, admin, edit, or a role carrying dangerous permissions) to system:authenticated, system:unauthenticated, or system:anonymous. Those groups contain every caller — authenticated ones in the first case, literally anyone who can reach the API server in the others. This is not a privilege-escalation path, it is a completed escalation for the entire world.",
	Remediation: "Remove the binding immediately and grant the role to specific ServiceAccounts, users or narrowly-scoped groups instead. If broad read access is genuinely intended, bind a purpose-built read-only role, never admin/edit/cluster-admin.",
	Type:        "rbac",
	Severity:    finding.SeverityCritical,
	Provider:    asset.ProviderKubernetes,
	// Deliberately AssetType-blank so it applies to both k8s_cluster_role_binding
	// and k8s_role_binding; the Violates predicate filters by type. A
	// cluster-scoped binding to everyone is worse, but a namespaced one still
	// hands that namespace to the world.
	Violates: func(a asset.Asset) bool {
		if a.Type != "k8s_cluster_role_binding" && a.Type != "k8s_role_binding" {
			return false
		}
		if !grantToEveryoneIsPrivileged(a) {
			return false
		}
		for s := range strings.SplitSeq(a.Metadata["subjects"], ",") {
			if everyoneGroups[strings.TrimSpace(s)] {
				return true
			}
		}
		return false
	},
}
