package enrich

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Some finding families live on resource types with no graph edges — a leaked
// secret or a SAST hit belongs to a github_repo; a nuclei web vulnerability
// belongs to a scanned endpoint URL. Enrichment's graph-signal scoring (exposure,
// blast, reachability) has nothing to attach to, so these findings never earn
// points beyond BaseSeverity — and BaseSeverity tops out at 40 (critical) while
// ThresholdPipeline is 50, so severity ALONE can never leave the monitor band.
// The result: a live leaked credential sits at score 0, invisible. This source
// floors those context-blind families out of monitor by their real urgency (same
// mechanism as ThreatFloor for behavioral detections). Floors only ever raise.

const sourceSignalFloor = "signal_floor"

// isSecretFinding reports whether a finding is an exposed-credential detection
// (a GitHub secret-scanning alert).
func isSecretFinding(f finding.Finding) bool {
	return f.Source == "ghas_secrets"
}

// isWebVulnFinding reports whether a finding is an active web-scan vulnerability
// (nuclei), confirmed by probing a live target — so it is real and often
// directly exploitable, unlike a static misconfiguration.
func isWebVulnFinding(f finding.Finding) bool {
	return f.Source == "nuclei"
}

// isCodeFinding reports whether a finding is a pre-deployment code/IaC issue
// (SAST or infrastructure-as-code). Real, but not live-exploitable yet, so it is
// floored into the reasoning pipeline rather than the actionable band.
func isCodeFinding(f finding.Finding) bool {
	return f.Source == "iac" || f.Source == "ghas_code_scanning"
}

// k8sRBACResourceTypes are the Kubernetes RBAC objects whose findings describe a
// privilege grant rather than a running workload.
var k8sRBACResourceTypes = map[string]bool{
	"k8s_cluster_role":         true,
	"k8s_cluster_role_binding": true,
	// Namespaced RBAC, added in the same change as its collector — the condition
	// this map's earlier comment set for including them. A namespaced Role is as
	// context-blind as a ClusterRole (reachability scoring skips RBAC objects and
	// every identity source is gated to iam_role/iam_user), so without the floor
	// these would land in monitor at BaseSeverity exactly as their cluster-scoped
	// siblings did.
	"k8s_role":         true,
	"k8s_role_binding": true,
}

// isK8sRBACFinding reports whether a finding describes a Kubernetes RBAC
// privilege grant. These are context-blind in exactly the way this source exists
// to fix, and for a subtler reason than the other families: reachability scoring
// skips them (IsNetworkReachableResource covers pods and services, not RBAC
// objects), and every identity-scoring source — PrincipalClass, IdentityHygiene,
// entryCap — is hard-gated to iam_role/iam_user, so none of the IAM machinery
// touches them either. A ClusterRole that grants cluster-wide Secrets read or
// self-CSR-approval therefore earned BaseSeverity and almost nothing else,
// landing under ThresholdPipeline and sitting in the monitor band permanently:
// alerted once, then never adjudicated, never in a must-fix worklist, and
// sorted to the bottom of every score-ranked view.
func isK8sRBACFinding(f finding.Finding) bool {
	return f.Type == "rbac" && k8sRBACResourceTypes[f.ResourceType]
}

// signalFloor returns the band floor for a context-blind finding, or 0 for none.
// Medium/low/info findings are deliberately left at their graph-scored band so
// the pipeline is not flooded with low-fidelity noise.
func signalFloor(f finding.Finding) int {
	switch {
	case isSecretFinding(f):
		// A leaked credential that may still work is act-now. High/critical →
		// actionable. One known not to work — a provider's test-mode key, or one
		// GitHub's validity check reports inactive — is floored into reasoning
		// only, matching the contained class the must-fix classifier gives it
		// (credentialNotLive): an actionable floor here would leave it
		// "contained" and High at once. Unknown validity keeps the actionable
		// floor.
		if f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh {
			if credentialNotLive(f) {
				return ThresholdPipeline
			}
			return ThresholdHigh
		}
	case isWebVulnFinding(f):
		// Probe-confirmed web vuln: critical → actionable, high → into reasoning.
		if f.Severity == finding.SeverityCritical {
			return ThresholdHigh
		}
		if f.Severity == finding.SeverityHigh {
			return ThresholdPipeline
		}
	case isCodeFinding(f):
		// Pre-deployment: high/critical → into reasoning, not straight to actionable.
		if f.Severity == finding.SeverityCritical || f.Severity == finding.SeverityHigh {
			return ThresholdPipeline
		}
	case isK8sRBACFinding(f):
		// A standing privilege grant, not a live exploit: floor into reasoning so it
		// is adjudicated and ranked rather than buried. Critical here means the grant
		// is cluster-admin-equivalent (self-CSR-approval, admission-webhook control,
		// escalate/bind/impersonate, token minting, kubelet proxy), which warrants
		// the actionable band directly.
		if f.Severity == finding.SeverityCritical {
			return ThresholdHigh
		}
		if f.Severity == finding.SeverityHigh {
			return ThresholdPipeline
		}
	}
	return 0
}

// SignalFloor floors context-blind finding families (secrets, web vulns, code/IaC)
// out of the monitor band so severity-only findings on edge-less resource types
// are not silently buried.
type SignalFloor struct{}

// Name identifies the source in the score breakdown.
func (SignalFloor) Name() string { return sourceSignalFloor }

// Evaluate floors a context-blind finding by its family and severity; everything
// else (graph-scorable findings, low-fidelity noise) passes through untouched.
func (SignalFloor) Evaluate(_ context.Context, f finding.Finding) (Factor, bool, error) {
	floor := signalFloor(f)
	if floor == 0 {
		return Factor{}, false, nil
	}
	band := "pipeline"
	if floor >= ThresholdHigh {
		band = "actionable"
	}
	return Factor{
		Source: sourceSignalFloor,
		Floor:  floor,
		Detail: "context-blind finding (" + f.Source + ") floored to the " + band + " band — no graph edges for scoring to attach to",
	}, true, nil
}
