package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// CIS 5.2.1 accepts an external policy system only where it is shown to
// enforce pod security. An installed engine without that proof (no policies,
// Audit-only ones, an unread policy list) is graded Info, never clean; an
// explicit privileged label always fires at Low.
func TestNamespacePSA_PolicyEngineEvidence(t *testing.T) {
	ns := func(md map[string]string) asset.Asset {
		md["phase"] = "Active"
		return asset.Asset{Name: "payments", Type: "k8s_namespace", Provider: asset.ProviderKubernetes, Metadata: md}
	}
	c := k8sNamespaceNoPodSecurityEnforcement
	sev := func(a asset.Asset) finding.Severity { return c.SeverityFor(a) }

	proven := ns(map[string]string{"psa_enforce": "", "cluster_policy_engines": "kyverno", "pod_security_engine": "kyverno"})
	require.False(t, c.Violates(proven))

	installedOnly := ns(map[string]string{"psa_enforce": "", "cluster_policy_engines": "kyverno", "pod_security_engine": ""})
	require.True(t, c.Violates(installedOnly))
	require.Equal(t, finding.SeverityInfo, sev(installedOnly))

	unread := ns(map[string]string{"psa_enforce": "", "cluster_policy_engines": "gatekeeper"})
	require.True(t, c.Violates(unread), "a forbidden constraint read is never clean")
	require.Equal(t, finding.SeverityInfo, sev(unread))

	none := ns(map[string]string{"psa_enforce": "", "cluster_policy_engines": "", "pod_security_engine": ""})
	require.True(t, c.Violates(none))
	require.Equal(t, finding.SeverityLow, sev(none))

	privileged := ns(map[string]string{"psa_enforce": "privileged", "cluster_policy_engines": "gatekeeper", "pod_security_engine": "gatekeeper"})
	require.True(t, c.Violates(privileged))
	require.Equal(t, finding.SeverityLow, sev(privileged))
}
