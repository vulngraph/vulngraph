package checks

// k8s_namespace_policy.go — per-namespace admission and isolation controls:
// Pod Security Admission enforcement, a default-deny ingress NetworkPolicy, and
// the default ServiceAccount's token automounting. One finding per namespace;
// system namespaces (k8sSystemNamespaces) are exempt, as for the pod checks.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var k8sNamespaceNoPodSecurityEnforcement = Check{
	ID:          "k8s-namespace-no-pod-security-enforcement",
	Title:       "Namespace does not enforce a baseline or restricted Pod Security Standard",
	Description: "The namespace has no pod-security.kubernetes.io/enforce label of 'baseline' or 'restricted', so Pod Security Admission admits privileged, host-namespace and hostPath pods into it. The enforced level (empty when unlabelled) is in the finding evidence. An unlabelled namespace is not reported when a policy engine is shown to enforce pod security in it: a Kyverno podSecurity rule in Enforce or a Gatekeeper pod-security-library constraint in deny that matches Pods there. An installed engine without that evidence (zero, Audit-only or unrecognised policies, or policies graph could not read) lowers the finding to Info. An explicit 'privileged' label is always reported." + k8sSystemNamespaceNote,
	Remediation: "Label the namespace pod-security.kubernetes.io/enforce=baseline (or restricted) with `kubectl label namespace NAME pod-security.kubernetes.io/enforce=baseline`, after checking its workloads with the audit/warn modes, or enforce an equivalent Kyverno podSecurity or Gatekeeper pod-security constraint. Reserve 'privileged' for namespaces that run node agents.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_namespace",
	// pod_security_engine is the engine the collector PROVED enforces pod
	// security here (collect/kubernetes/admission_coverage.go); an installed
	// engine alone (cluster_policy_engines) only lowers the grade. Either key
	// absent is unread and leaves the label to decide. A namespace explicitly
	// labelled privileged always fires: it is the one place the pod checks
	// stand down (isK8sSystemPod), so this finding is how its policy is seen.
	Violates: func(a asset.Asset) bool {
		level, ok := a.Metadata["psa_enforce"]
		if !ok || a.Metadata["phase"] != "Active" || k8sSystemNamespaces[a.Name] {
			return false
		}
		if level == "" && a.Metadata["pod_security_engine"] != "" {
			return false
		}
		return level != "baseline" && level != "restricted"
	},
	SeverityFor: func(a asset.Asset) finding.Severity {
		if engineUnverified(a) {
			return finding.SeverityInfo
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if engineUnverified(a) {
			return "Namespace has no Pod Security label; a policy engine is installed but its pod-security coverage is unverified"
		}
		return "Namespace does not enforce a baseline or restricted Pod Security Standard"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		ev := map[string]string{"psa_enforce": a.Metadata["psa_enforce"]}
		for _, k := range []string{"cluster_policy_engines", "pod_security_engine"} {
			if v, ok := a.Metadata[k]; ok {
				ev[k] = v
			}
		}
		return ev
	},
}

// engineUnverified reports an unlabelled namespace in a cluster with a policy
// engine installed that was not shown to enforce pod security there.
func engineUnverified(a asset.Asset) bool {
	return a.Metadata["psa_enforce"] == "" && a.Metadata["cluster_policy_engines"] != ""
}

// k8sNamespaceNoDefaultDeny steps aside for a namespace with no NetworkPolicy
// at all: k8s-namespace-no-network-policy reports that, and a finding here
// would restate it.
var k8sNamespaceNoDefaultDeny = Check{
	ID:          "k8s-namespace-no-default-deny",
	Title:       "Namespace has NetworkPolicies but no default-deny ingress policy",
	Description: "The namespace has NetworkPolicies, but none selects every pod and denies all ingress. Pods no policy selects stay reachable from every pod in the cluster, so each new workload starts open until someone writes a policy for it." + k8sSystemNamespaceNote,
	Remediation: "Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress] and no ingress rules, then allow required traffic with narrower policies.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_namespace",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["phase"] == "Active" && !k8sSystemNamespaces[a.Name] &&
			a.Metadata["has_network_policy"] == "true" && a.Metadata["has_default_deny_ingress"] == "false"
	},
}

// k8sDefaultSAAutomount is where a pod on the default ServiceAccount that
// inherits its token mount is reported: k8s-automount-sa-token steps aside for
// it, since one change here fixes every such pod in the namespace.
var k8sDefaultSAAutomount = Check{
	ID:          "k8s-default-sa-automount",
	Title:       "Namespace default ServiceAccount automounts its token",
	Description: "The namespace's default ServiceAccount does not set automountServiceAccountToken: false, so every pod that names no ServiceAccount gets an API token mounted. Any RoleBinding to the default ServiceAccount then reaches every such pod, and a compromised pod can call the API server." + k8sSystemNamespaceNote,
	Remediation: "Set automountServiceAccountToken: false on the default ServiceAccount, and give workloads that need API access a dedicated ServiceAccount.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderKubernetes,
	AssetType:   "k8s_service_account",
	Violates: func(a asset.Asset) bool {
		return a.Name == "default" && a.Metadata["automount_token"] == "true" &&
			!k8sSystemNamespaces[a.Metadata["namespace"]]
	},
}
