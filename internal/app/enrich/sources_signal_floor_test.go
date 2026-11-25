package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestSignalFloor(t *testing.T) {
	tests := []struct {
		name      string
		f         finding.Finding
		wantFloor int // 0 = not applied
	}{
		// Exposed secrets — a live leaked credential is act-now.
		{"ghas secret high → actionable", finding.Finding{Source: "ghas_secrets", Type: "exposure", Severity: finding.SeverityHigh}, ThresholdHigh},
		{"ghas secret critical → actionable", finding.Finding{Source: "ghas_secrets", Severity: finding.SeverityCritical}, ThresholdHigh},
		// A medium secret is left at its graph-scored band (avoid flooding).
		{"ghas secret medium → no floor", finding.Finding{Source: "ghas_secrets", Severity: finding.SeverityMedium}, 0},

		// Nuclei web vulns — confirmed against a live target.
		{"nuclei critical → actionable", finding.Finding{Source: "nuclei", Type: "vulnerability", Severity: finding.SeverityCritical}, ThresholdHigh},
		{"nuclei high → pipeline", finding.Finding{Source: "nuclei", Type: "vulnerability", Severity: finding.SeverityHigh}, ThresholdPipeline},
		{"nuclei medium → no floor", finding.Finding{Source: "nuclei", Severity: finding.SeverityMedium}, 0},

		// Code / IaC — pre-deployment, into reasoning not straight to actionable.
		{"iac critical → pipeline", finding.Finding{Source: "iac", Severity: finding.SeverityCritical}, ThresholdPipeline},
		{"ghas code high → pipeline", finding.Finding{Source: "ghas_code_scanning", Type: "code_vulnerability", Severity: finding.SeverityHigh}, ThresholdPipeline},

		// A VM package CVE (not a secret) is graph-scorable via runs_package — untouched here.
		{"vm package cve → no floor", finding.Finding{Source: "vm_vuln", Type: "vulnerability", Severity: finding.SeverityHigh}, 0},
		// A CSPM exposure check (shares Type "exposure") must NOT be floored by this source.
		{"cspm exposure → no floor", finding.Finding{Source: "cspm", Type: "exposure", CheckID: "aws-s3-public", Severity: finding.SeverityHigh}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, applied, err := SignalFloor{}.Evaluate(context.Background(), tt.f)
			require.NoError(t, err)
			if tt.wantFloor == 0 {
				require.False(t, applied)
				return
			}
			require.True(t, applied)
			require.Equal(t, tt.wantFloor, f.Floor)
			require.Equal(t, sourceSignalFloor, f.Source)
		})
	}
}

// K8s RBAC findings are context-blind in exactly the way this source exists to
// fix, and for a subtler reason than secrets/nuclei/IaC: reachability scoring
// skips RBAC objects (IsNetworkReachableResource covers pods and services), and
// every identity-scoring source is hard-gated to iam_role/iam_user, so nothing
// touches them. A ClusterRole granting cluster-wide Secrets read earned
// BaseSeverity and almost nothing else — under ThresholdPipeline, so it sat in
// the monitor band permanently: alerted once, never adjudicated, never in a
// must-fix worklist, bottom of every score-ranked view.
func TestSignalFloor_K8sRBACIsFloored(t *testing.T) {
	high := finding.Finding{
		Type: "rbac", ResourceType: "k8s_cluster_role",
		CheckID: "k8s-cluster-role-dangerous-permissions", Severity: finding.SeverityHigh,
	}
	require.Equal(t, ThresholdPipeline, signalFloor(high),
		"a dangerous ClusterRole must reach the reasoning pipeline")

	// Critical means the grant is cluster-admin-equivalent (self-CSR-approval,
	// admission-webhook control, escalate/bind/impersonate, token minting,
	// kubelet proxy) — straight to actionable.
	critical := high
	critical.Severity = finding.SeverityCritical
	require.Equal(t, ThresholdHigh, signalFloor(critical))

	// Bindings count too.
	binding := finding.Finding{
		Type: "rbac", ResourceType: "k8s_cluster_role_binding", Severity: finding.SeverityCritical,
	}
	require.Equal(t, ThresholdHigh, signalFloor(binding))
}

// Low-fidelity RBAC noise stays at its graph-scored band, and non-RBAC k8s
// findings are unaffected — the floor must not become a blanket promotion.
func TestSignalFloor_K8sRBACDoesNotFloorEverything(t *testing.T) {
	medium := finding.Finding{
		Type: "rbac", ResourceType: "k8s_cluster_role", Severity: finding.SeverityMedium,
	}
	require.Equal(t, 0, signalFloor(medium))

	// A pod-security finding is graph-scorable (pods have reachability), so it
	// must not be floored here.
	pod := finding.Finding{
		Type: "rbac", ResourceType: "k8s_pod", Severity: finding.SeverityCritical,
	}
	require.Equal(t, 0, signalFloor(pod))
}

// Namespaced RBAC must be floored exactly like its cluster-scoped siblings. This
// pins the map against the collector: internal/collect/kubernetes now emits
// k8s_role and k8s_role_binding assets, and a finding on one of them is just as
// context-blind as on a ClusterRole — no reachability signal, no identity signal —
// so without the floor it sits in monitor at BaseSeverity.
func TestSignalFloor_NamespacedK8sRBACIsFloored(t *testing.T) {
	for _, rt := range []string{"k8s_role", "k8s_role_binding"} {
		high := finding.Finding{Type: "rbac", ResourceType: rt, Severity: finding.SeverityHigh}
		require.Equal(t, ThresholdPipeline, signalFloor(high), rt)

		critical := high
		critical.Severity = finding.SeverityCritical
		require.Equal(t, ThresholdHigh, signalFloor(critical), rt)
	}
}
