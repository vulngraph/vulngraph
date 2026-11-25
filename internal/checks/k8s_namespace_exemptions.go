package checks

import (
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/k8sns"
)

// Fixed namespace exemptions of the Kubernetes checks. Each list is fixed in
// code (not configurable), and nothing is reported for a resource it exempts.
// The cost is real: a privileged pod an attacker plants in kube-system, or an
// application team's own "monitoring" namespace, is not graded by the checks
// that skip it. So the exemption is never silent: every check that applies a
// list ends its Description with that list's note (shown on each finding),
// and docs/cspm-coverage.md lists them with their checks
// (K8sNamespaceExemptions). TestK8sNamespaceExemptionsAreDescribed ties each
// predicate that reads a list to its note.

// k8sSystemNamespaces are excluded from the pod-security checks (with
// isK8sSystemPod) and from the namespace-level admission and isolation checks
// because system DaemonSets (CNI, CSI, GKE metadata server, node exporter,
// security and monitoring agents) legitimately require privileged access and
// hostNetwork. Flagging them produces thousands of critical findings with zero
// actionability, dominating the decision pipeline with noise. This static
// list is the fallback; the primary, name-independent signal is the
// namespace's Pod Security Standard enforce label (see isK8sSystemPod).
var k8sSystemNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"gke-system":      true,
	"gmp-system":      true,
	"gmp-public":      true,
	"calico-system":   true,
	"cert-manager":    true,
	"monitoring":      true,
	"istio-system":    true,
	"falco":           true,
	"datadog":         true,
}

// k8sNetworkPolicyExemptNamespaces are skipped by
// k8s-namespace-no-network-policy: their traffic policy is the platform's.
var k8sNetworkPolicyExemptNamespaces = map[string]bool{
	"kube-system": true, "kube-public": true, "kube-node-lease": true,
	"gke-system": true, "gmp-system": true, "gmp-public": true,
	"monitoring": true, "calico-system": true, "cert-manager": true,
}

// k8sResourceLimitsExemptNamespaces are skipped by k8s-pod-no-resource-limits:
// their resource profiles are the platform's.
var k8sResourceLimitsExemptNamespaces = map[string]bool{
	"kube-system": true, "gke-system": true, "gmp-system": true,
	"calico-system": true, "cert-manager": true, "monitoring": true,
}

// k8sConfigMapSkippedNamespaces are namespaces whose ConfigMaps the
// Kubernetes collector never maps to k8s_configmap assets, so
// k8s-configmap-plaintext-secret has nothing to grade there. The collector
// applies the same list (internal/k8sns).
var k8sConfigMapSkippedNamespaces = k8sns.ConfigMapSkippedNamespaces()

// The Description suffixes naming each exemption exactly.
var (
	k8sSystemPodNote            = exemptionNote(k8sSystemNamespaces, true)
	k8sSystemNamespaceNote      = exemptionNote(k8sSystemNamespaces, false)
	k8sNetworkPolicyNote        = exemptionNote(k8sNetworkPolicyExemptNamespaces, false)
	k8sResourceLimitsExemptNote = exemptionNote(k8sResourceLimitsExemptNamespaces, false)
	k8sConfigMapSkippedNote     = exemptionNote(k8sConfigMapSkippedNamespaces, false)
)

const privilegedLabel = "pod-security.kubernetes.io/enforce=privileged"

func exemptionNote(ns map[string]bool, label bool) string {
	names := sortedNames(ns)
	note := " Not evaluated in the namespaces " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	if label {
		note += ", or in a namespace labelled " + privilegedLabel
	}
	return note + "."
}

func sortedNames(ns map[string]bool) []string {
	out := make([]string, 0, len(ns))
	for n := range ns {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// K8sNamespaceExemption is one fixed set of namespaces that some Kubernetes
// checks never evaluate.
type K8sNamespaceExemption struct {
	Scope      string
	Namespaces []string
	// PrivilegedLabel: namespaces labelled
	// pod-security.kubernetes.io/enforce=privileged are skipped too.
	PrivilegedLabel bool
	Reason          string
	CheckIDs        []string
}

// K8sNamespaceExemptions lists every fixed namespace exemption with the
// registered checks that apply it, for docs/cspm-coverage.md.
func K8sNamespaceExemptions() []K8sNamespaceExemption {
	rows := []struct {
		scope  string
		ns     map[string]bool
		label  bool
		note   string
		reason string
	}{
		{"Pod checks", k8sSystemNamespaces, true, k8sSystemPodNote,
			"Node agents (CNI, CSI, metadata servers, monitoring and security agents) need privileged access and host namespaces there, and an operator who labels a namespace privileged has declared the same. Names match exactly, so an application namespace that happens to be called monitoring is skipped too. A privileged pod placed in one of these namespaces is not reported, so review them by other means (admission policy, runtime detection); k8s-namespace-no-pod-security-enforcement still reports a privileged label outside this list."},
		{"Namespace admission and isolation", k8sSystemNamespaces, false, k8sSystemNamespaceNote,
			"The same platform namespaces as the pod checks."},
		{"NetworkPolicy presence", k8sNetworkPolicyExemptNamespaces, false, k8sNetworkPolicyNote,
			"Their traffic policy is managed by the platform."},
		{"Resource limits", k8sResourceLimitsExemptNamespaces, false, k8sResourceLimitsExemptNote,
			"Their resource profiles are managed by the platform."},
		{"ConfigMap plaintext secrets", k8sConfigMapSkippedNamespaces, false, k8sConfigMapSkippedNote,
			"The collector does not record ConfigMaps there, so a plaintext secret in one is not reported: their ConfigMaps are the platform's."},
	}
	all := Default().All()
	out := make([]K8sNamespaceExemption, 0, len(rows))
	for _, r := range rows {
		e := K8sNamespaceExemption{Scope: r.scope, Namespaces: sortedNames(r.ns), PrivilegedLabel: r.label, Reason: r.reason}
		for _, c := range all {
			if strings.HasSuffix(c.Description, r.note) {
				e.CheckIDs = append(e.CheckIDs, c.ID)
			}
		}
		sort.Strings(e.CheckIDs)
		out = append(out, e)
	}
	return out
}
