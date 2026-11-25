package checks

// rbac_cluster.go — checks over the cluster-scoped RBAC asset types
// (k8s_cluster_role, k8s_cluster_role_binding). The exact siblings of the
// namespaced checks in rbac_namespaced.go, and they share its helpers
// (privilegedRoleRef, refersToClusterRole).

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var k8sClusterRoleWildcardVerbs = Check{
	ID:          "k8s-cluster-role-wildcard-verbs",
	Title:       "ClusterRole grants a wildcard rule",
	Description: "The ClusterRole has a policy rule with a wildcard (\"*\") in its verbs, resources, or API groups — granting sweeping access (any action, and/or any resource type including ones added later by CRDs, and/or any API group). This is overly permissive and violates the principle of least privilege.",
	Remediation: "Replace the wildcard with the specific verbs, resources, and API groups required (e.g. verbs: [\"get\", \"list\"]). Use audit logs to determine what is actually needed.",
	Type:        "rbac",
	// Medium at most: posture, like every RBAC grant; urgency comes from who
	// holds the role (the must-fix classifier reads its bindings).
	Severity:  finding.SeverityMedium,
	Provider:  asset.ProviderKubernetes,
	AssetType: "k8s_cluster_role",
	Violates: func(a asset.Asset) bool {
		// Kubernetes' own bootstrap ClusterRoles and GKE's managed ones carry
		// wildcard rules BY DESIGN and are reverted by the API server's
		// reconciler if edited — unactionable by construction. The sibling
		// k8s-rbac-* capability checks get this exclusion for free because the
		// collector folds platform_managed into dangerous_perms itself; the raw
		// wildcard signal needs it applied here.
		return (a.Metadata["wildcard_verbs"] == "true" || a.Metadata["wildcard_resources"] == "true") &&
			a.Metadata["platform_managed"] != "true"
	},
	// A "*" only in resources or apiGroups (wildcard_verbs is verbs: ["*"] only)
	// is Low: whatever it reaches that matters — Secrets, pod creation, workload
	// writes — is reported by the matching k8s-rbac-* capability check itself.
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["wildcard_verbs"] != "true" {
			return finding.SeverityLow
		}
		return finding.SeverityMedium
	},
	// The capabilities the wildcard implies, so one finding tells the responder
	// what "*" actually hands out; each also has its own k8s-rbac-* finding.
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"rule_count": a.Metadata["rule_count"]}
		if d := a.Metadata["dangerous_perms_detail"]; d != "" {
			ev["dangerous_capabilities"] = d
		}
		return ev
	},
}

// k8sClusterAdminBinding is Medium posture rather than Critical: nearly every
// cluster carries cluster-admin bindings for system components and installers,
// and the binding that matters — one naming an identity from outside the
// cluster — is elevated by the must-fix classifier from the binding's own
// subjects (and a grant to everyone is Critical under
// k8s-privileged-binding-to-everyone).
//
// cluster-admin only: the built-in admin and edit ClusterRoles bound
// cluster-wide are k8s-clusterrolebinding-admin-edit, so this check is exactly
// the benchmark's "cluster-admin only where required" control. The bootstrap
// cluster-admin binding to system:masters is the platform's and not the
// organisation's to justify. The other bindings a distribution ships granting
// cluster-admin (kubeadm:cluster-admins, eks:addon-cluster-admin — collector
// platform_cluster_admin) are the platform's too, but still a standing admin
// grant someone should know exists: reported at Info, never silent.
var k8sClusterAdminBinding = Check{
	ID:          "k8s-cluster-admin-binding",
	Title:       "ClusterRoleBinding grants cluster-admin",
	Description: "A ClusterRoleBinding grants the built-in 'cluster-admin' ClusterRole: unrestricted access to every resource in every namespace, including RBAC itself. It should be held only where nothing narrower works, never by an application workload.",
	Remediation: "Audit the subjects of this binding. Replace it with a ClusterRole granting only what each subject needs, or namespaced RoleBindings where the access is per namespace. Keep break-glass cluster-admin access out of standing bindings.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster_role_binding",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["role_ref"] == "cluster-admin" &&
			(a.Metadata["platform_managed"] == "false" || a.Metadata["platform_cluster_admin"] == "true")
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if a.Metadata["platform_managed"] == "true" {
			return finding.SeverityInfo
		}
		return finding.SeverityMedium
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"subjects": a.Metadata["subjects"]}
	},
}

var k8sDefaultServiceAccountBound = Check{
	ID:          "k8s-default-service-account-bound",
	Title:       "ClusterRoleBinding grants elevated privileges to default service account",
	Description: "A ClusterRoleBinding binds a privileged role to a 'default' service account. The default service account is used by pods that do not specify a service account, making this an easy privilege escalation path.",
	Remediation: "Create dedicated service accounts for workloads that need specific permissions. Never bind elevated roles to 'default' service accounts.",
	Type:        "rbac",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_cluster_role_binding",
	Violates: func(a asset.Asset) bool {
		// The bound role must actually be privileged — the same gate the
		// namespaced sibling k8s-rolebinding-default-service-account-bound
		// carries. Without it this would fire on any ClusterRoleBinding naming
		// the default SA, including read-only roles, which is not a
		// privilege-escalation path.
		if !privilegedRoleRef(a) {
			return false
		}
		// Subjects are "Kind/Name" comma-joined; exact-match each so a SA named
		// e.g. "default-backend" doesn't substring-match "default".
		for s := range strings.SplitSeq(a.Metadata["subjects"], ",") {
			if strings.TrimSpace(s) == "ServiceAccount/default" {
				return true
			}
		}
		return false
	},
}
