package checks

// k8s_rbac_grants.go — one check per RBAC capability the CIS Kubernetes, EKS
// and GKE benchmarks audit (secrets access, pod creation, PersistentVolume
// creation, nodes/proxy, CSR approval, admission webhook configuration,
// ServiceAccount token creation, escalate/bind/impersonate), plus pods/exec,
// which no benchmark names but is the same class of grant. There is
// deliberately no umbrella check folding every category into one finding: then
// no single control could pass or fail on its own.
//
// Each check covers ClusterRoles and namespaced Roles alike (the grant is the
// same capability; the evidence says which scope), over the categories the
// collector computes into dangerous_perms_detail (collect/kubernetes
// dangerousPermissionCategories). dangerous_perms is the platform-managed gate:
// the collector writes it false for Kubernetes' own and the provider's roles
// only up to their stock grants (collect/kubernetes rbac_stock.go); anything
// injected beyond that baseline is still reported, since reconciliation never
// removes added rules.
//
// A full-wildcard role ("*" verbs on "*" resources in "*" groups) grants every
// capability, and the collector expands the wildcard so each category appears
// in its detail. It gets every k8s-rbac-* finding, not none: each one is the
// evidence for a distinct CIS 5.1.x control, and silencing them would report
// those controls as passing for the most permissive role in the cluster. The
// wildcard checks additionally list the implied capabilities in their evidence.
// The flood is bounded — one finding per capability per role, at Low/Medium.
//
// Graded as posture: Low, Medium for the
// categories that are cluster-admin by another route. A role is a permission
// set; what makes one urgent is who holds it, which the must-fix classifier
// reads from its bindings (enrich/mustfix_k8s_rbac.go).

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// grantedRBACCategories returns the dangerous_perms_detail entries of a role
// that belong to one of categories, with their "(scoped)" marker kept so the
// evidence shows a resourceNames-confined grant as such. Nil for anything that
// is not a ClusterRole or Role, or whose grants are platform-suppressed.
func grantedRBACCategories(a asset.Asset, categories ...string) []string {
	if a.Type != "k8s_cluster_role" && a.Type != "k8s_role" {
		return nil
	}
	if a.Metadata["dangerous_perms"] != "true" {
		return nil
	}
	var out []string
	for _, entry := range strings.Split(a.Metadata["dangerous_perms_detail"], ",") {
		entry = strings.TrimSpace(entry)
		base := strings.TrimSuffix(entry, "(scoped)")
		for _, c := range categories {
			if base == c {
				out = append(out, entry)
			}
		}
	}
	return out
}

// rbacGrantEvidence names the matching capabilities and the scope they apply in.
func rbacGrantEvidence(a asset.Asset, categories ...string) map[string]string {
	scope := "cluster"
	if a.Type == "k8s_role" {
		scope = "namespace:" + a.Metadata["namespace"]
	}
	return map[string]string{
		"capabilities": strings.Join(grantedRBACCategories(a, categories...), ","),
		"scope":        scope,
	}
}

var k8sRBACSecretsAccess = Check{
	ID:          "k8s-rbac-secrets-access",
	Title:       "RBAC role can read or write Secrets",
	Description: "This Role or ClusterRole grants get/list/watch (or write) on Secrets. Reading Secrets yields every ServiceAccount token and application credential in scope — cluster-wide for a ClusterRole bound by a ClusterRoleBinding; writing them plants credentials a workload trusts. The scope and whether the grant is confined to named Secrets (\"(scoped)\") are in the finding evidence.",
	Remediation: "Remove Secrets access the holder does not need. Where it is needed, prefer a namespaced Role over a ClusterRole and confine the rule with resourceNames to the specific Secrets; list/watch cannot be confined that way, so grant only get.",
	Type:        "rbac",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "secrets-read", "secrets-write")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "secrets-read", "secrets-write")
	},
}

var k8sRBACPodCreate = Check{
	ID:          "k8s-rbac-pod-create",
	Title:       "RBAC role can create pods or modify workload controllers",
	Description: "This Role or ClusterRole can create Pods, or create/update/patch Deployments, DaemonSets, StatefulSets, ReplicaSets, Jobs or CronJobs. Whoever chooses a Pod's spec chooses its serviceAccountName, hostPath mounts and privileges, so the grant is every ServiceAccount's permissions in scope and, without Pod Security Admission, the node.",
	Remediation: "Grant workload creation only to deployment tooling, scoped to the namespaces it deploys to. Enforce the 'baseline' or 'restricted' Pod Security Standard so a pod creator cannot also choose host access.",
	Type:        "rbac",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "pod-create", "workload-create")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "pod-create", "workload-create")
	},
}

var k8sRBACPodExec = Check{
	ID:          "k8s-rbac-pod-exec",
	Title:       "RBAC role can exec, attach or proxy into pods",
	Description: "This Role or ClusterRole grants pods/exec, pods/attach, pods/ephemeralcontainers, pods/portforward, pods/proxy or services/proxy: code execution inside, or network reach into, every workload in scope — and with it each workload's mounted ServiceAccount token.",
	Remediation: "Reserve exec/attach/proxy for break-glass operator roles bound to named humans, scoped to the namespaces they operate.",
	Type:        "rbac",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "pod-exec")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "pod-exec")
	},
}

var k8sRBACPVCreate = Check{
	ID:          "k8s-rbac-pv-create",
	Title:       "RBAC role can create PersistentVolumes",
	Description: "This Role or ClusterRole can create PersistentVolumes. A hostPath PersistentVolume mounts the node's filesystem into any pod that claims it — a node compromise that Pod Security Admission does not see, since the pod itself names only a claim.",
	Remediation: "Let a StorageClass provisioner create PersistentVolumes; grant users and workloads only persistentvolumeclaims.",
	Type:        "rbac",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "host-mount")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "host-mount")
	},
}

var k8sRBACNodeProxy = Check{
	ID:          "k8s-rbac-node-proxy",
	Title:       "RBAC role can reach the kubelet API through nodes/proxy",
	Description: "This Role or ClusterRole grants nodes/proxy, which reaches the kubelet API directly. The kubelet authorises exec, logs and pod listing on its own, so the holder can run commands in any pod on any node, bypassing API-server RBAC and audit for those actions.",
	Remediation: "Remove nodes/proxy. Monitoring agents that scrape kubelet metrics need nodes/metrics (or nodes/stats), not nodes/proxy.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "node-proxy")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "node-proxy")
	},
}

var k8sRBACCSRApprove = Check{
	ID:          "k8s-rbac-csr-approve",
	Title:       "RBAC role can approve certificate signing requests",
	Description: "This Role or ClusterRole can update certificatesigningrequests/approval or a signer. Approving a CSR mints a client certificate with any subject the requester chose — including O=system:masters, which the API server treats as cluster-admin outside RBAC entirely and which cannot be revoked short of rotating the cluster CA.",
	Remediation: "Leave CSR approval to the control plane's own approvers. Remove the approval subresource and signer grants from every other role.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "csr-approve")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "csr-approve")
	},
}

var k8sRBACWebhookConfig = Check{
	ID:          "k8s-rbac-webhook-config",
	Title:       "RBAC role can modify admission webhook configurations",
	Description: "This Role or ClusterRole can write mutating or validating webhook configurations. An admission webhook sees, and can rewrite, every matching object the API server admits — swap any Pod's image or serviceAccountName in flight, or switch off policy enforcement cluster-wide.",
	Remediation: "Grant webhook-configuration write only to the installer of the admission controller that owns it, and remove it once installed.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "admission-webhook")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "admission-webhook")
	},
}

var k8sRBACTokenCreate = Check{
	ID:          "k8s-rbac-token-create",
	Title:       "RBAC role can create ServiceAccount tokens",
	Description: "This Role or ClusterRole can create serviceaccounts/token, minting a fresh token for any ServiceAccount in scope — the permissions of every one of them, including the most privileged.",
	Remediation: "Remove serviceaccounts/token create. A workload gets its own token through a projected volume; only the control plane needs to mint tokens for others.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "token-mint")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "token-mint")
	},
}

var k8sRBACEscalate = Check{
	ID:          "k8s-rbac-escalate",
	Title:       "RBAC role can escalate, bind or impersonate",
	Description: "This Role or ClusterRole grants the escalate, bind or impersonate verbs, or write access to Roles, ClusterRoles or their bindings. Each defeats RBAC's own privilege-escalation prevention: grant yourself a role you do not hold, bind one to yourself, or act as another user, group or ServiceAccount.",
	Remediation: "Remove escalate, bind and impersonate, and RBAC-object write access, from every role that is not a cluster administrator's.",
	Type:        "rbac",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderKubernetes,
	Violates: func(a asset.Asset) bool {
		return len(grantedRBACCategories(a, "rbac-escalate")) > 0
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return rbacGrantEvidence(a, "rbac-escalate")
	},
}
