package checks

// k8s_rbac_bindings.go — binding checks the benchmarks audit by subject or by
// role name: admin/edit bound cluster-wide, bindings naming system:masters, and
// any binding to the unauthenticated or all-authenticated groups. Graded as
// posture (Low/Medium) like the other RBAC grants; the must-fix classifier
// elevates a binding whose subjects come from outside the cluster, which every
// Group subject here does.
//
// Each skips platform-managed bindings (collector platform_managed: the
// binding's kind, name, roleRef and exact subject set match one the platform
// ships, so a backdoor merely named like a system binding is still reported)
// — Kubernetes ships system:discovery and system:basic-user bound to
// system:authenticated, and the cluster-admin binding to system:masters, and
// restores them if removed.

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// bindingNamesSubject reports whether a binding's subject list contains one of
// subjects (exact "Kind/Name" matches).
func bindingNamesSubject(a asset.Asset, subjects ...string) bool {
	for s := range strings.SplitSeq(a.Metadata["subjects"], ",") {
		for _, want := range subjects {
			if strings.TrimSpace(s) == want {
				return true
			}
		}
	}
	return false
}

// isOrgBinding reports whether a is a RoleBinding or ClusterRoleBinding the
// organisation owns. platform_managed absent (a binding collected before the
// key existed) is unknown and must not read as org-owned.
func isOrgBinding(a asset.Asset) bool {
	return (a.Type == "k8s_cluster_role_binding" || a.Type == "k8s_role_binding") &&
		a.Metadata["platform_managed"] == "false"
}

// k8sClusterRoleBindingAdminEdit is the cluster-wide sibling of
// k8s-rolebinding-admin-binding: the built-in admin or edit ClusterRole bound
// by a ClusterRoleBinding applies in every namespace. It is kept separate from
// k8s-cluster-admin-binding so that check fires only on the cluster-admin
// control it is mapped to.
var k8sClusterRoleBindingAdminEdit = Check{
	ID:          "k8s-clusterrolebinding-admin-edit",
	Title:       "ClusterRoleBinding grants the built-in admin or edit role in every namespace",
	Description: "A ClusterRoleBinding grants the built-in 'admin' or 'edit' ClusterRole. Bound cluster-wide, either gives read/write access to almost every namespaced resource in every namespace — including Secrets and the ability to create pods as any ServiceAccount — which is cluster-admin in all but name for workloads.",
	Remediation: "Replace the ClusterRoleBinding with RoleBindings in the namespaces the subject actually works in, or with a purpose-built ClusterRole granting only what is needed.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster_role_binding",
	Violates: func(a asset.Asset) bool {
		ref := a.Metadata["role_ref"]
		return (ref == "admin" || ref == "edit") && a.Metadata["platform_managed"] == "false"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"role": a.Metadata["role_ref"], "subjects": a.Metadata["subjects"]}
	},
}

var k8sBindingSystemMasters = Check{
	ID:          "k8s-binding-system-masters",
	Title:       "RBAC binding names the system:masters group",
	Description: "A RoleBinding or ClusterRoleBinding names Group/system:masters. Members of system:masters are cluster-admin before RBAC is consulted, and membership comes only from client certificates (O=system:masters) that cannot be revoked short of rotating the cluster CA — a binding naming the group is a sign such credentials are being issued or planned. Certificates minted outside the cluster are not visible to graph.",
	Remediation: "Remove the binding. Grant administrators cluster-admin through a named group from the identity provider bound by an ordinary ClusterRoleBinding, so access can be revoked; never issue client certificates in system:masters.",
	Type:        "rbac",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return isOrgBinding(a) && bindingNamesSubject(a, "Group/system:masters")
	},
}

// k8sBindingToUnauthenticated and k8sBindingToAuthenticated cover a binding to
// the world that k8s-privileged-binding-to-everyone (Critical) does not: one
// whose role is not privileged. They step aside when that check fires, so a
// binding carries one finding.
var k8sBindingToUnauthenticated = Check{
	ID:          "k8s-binding-to-unauthenticated",
	Title:       "RBAC binding grants a role to unauthenticated users",
	Description: "A RoleBinding or ClusterRoleBinding grants a role to system:unauthenticated or system:anonymous: anyone who can reach the API server holds it, with no credential at all. The bound role is not one graph rates privileged (that case is k8s-privileged-binding-to-everyone), but every read it allows is a read for the internet.",
	Remediation: "Remove the binding. If some data must be public, serve it outside the API server; Kubernetes' own anonymous access (system:public-info-viewer) is already granted by default.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return isOrgBinding(a) && !grantToEveryoneIsPrivileged(a) &&
			bindingNamesSubject(a, "Group/system:unauthenticated", "Group/system:anonymous", "User/system:anonymous")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"role": a.Metadata["role_ref"]}
	},
}

var k8sBindingToAuthenticated = Check{
	ID:          "k8s-binding-to-authenticated",
	Title:       "RBAC binding grants a role to all authenticated users",
	Description: "A RoleBinding or ClusterRoleBinding grants a role to system:authenticated: every identity the API server accepts. On GKE that is any Google account, not only the organisation's; on any cluster it includes every ServiceAccount token. The bound role is not one graph rates privileged (that case is k8s-privileged-binding-to-everyone).",
	Remediation: "Bind the role to the specific groups, users or ServiceAccounts that need it instead of system:authenticated.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return isOrgBinding(a) && !grantToEveryoneIsPrivileged(a) && bindingNamesSubject(a, "Group/system:authenticated")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"role": a.Metadata["role_ref"]}
	},
}
