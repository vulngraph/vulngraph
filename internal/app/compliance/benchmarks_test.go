package compliance

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
)

// cisMatrices maps a CIS compliance control's ID prefix to the benchmark
// matrices that must back it. Kubernetes controls may be backed by the managed
// variants too: their RBAC and pod sections are the same recommendations.
// An EKS node control does not back a general EC2 claim, which is why this is
// keyed on the control rather than on the check's provider.
var cisMatrices = map[string][]string{
	"CIS-AWS-": {"cis-aws-foundations"},
	"CIS-GCP-": {"cis-gcp-foundation"},
	"CIS-AZ-":  {"cis-azure-foundations"},
	"CIS-K8S-": {"cis-kubernetes", "cis-eks", "cis-gke", "cis-aks"},
}

// cisWithoutMatrix are CIS prefixes with no benchmark matrix yet. The CIS
// GitHub (software supply chain) benchmark is not measured; every cloud and
// Kubernetes prefix is, and must stay off this list.
var cisWithoutMatrix = []string{"CIS-GH-"}

// TestCISControlsAgreeWithBenchmarkMatrix keeps the compliance view honest
// about CIS: every check a CIS-framework control maps must be listed as
// covered or partial by a CIS matrix for that control's platform. The matrix
// is the control-by-control reading of the benchmark; a compliance control
// claiming CIS for a check the matrix says implements no CIS recommendation
// would show auditors CIS posture graph does not measure.
func TestCISControlsAgreeWithBenchmarkMatrix(t *testing.T) {
	bs, err := benchmarks.Load()
	require.NoError(t, err)
	backed := map[string]map[string]bool{} // benchmark ID → check IDs evidencing some control
	for _, b := range bs {
		backed[b.ID] = map[string]bool{}
		for _, c := range b.Controls {
			if c.Status == benchmarks.StatusCovered || c.Status == benchmarks.StatusPartial {
				for _, id := range c.CheckIDs {
					backed[b.ID][id] = true
				}
			}
		}
	}
	for _, ids := range cisMatrices {
		for _, id := range ids {
			require.Contains(t, backed, id, "no benchmark matrix %q", id)
		}
	}

	for _, c := range controls {
		if !slices.Contains(frameworksFor(c.ID), FrameworkCIS) {
			continue
		}
		if slices.ContainsFunc(cisWithoutMatrix, func(p string) bool { return strings.HasPrefix(c.ID, p) }) {
			continue
		}
		var matrices []string
		for prefix, ids := range cisMatrices {
			if strings.HasPrefix(c.ID, prefix) {
				matrices = ids
			}
		}
		require.NotEmpty(t, matrices, "%s rolls up under CIS but names no CIS benchmark platform", c.ID)
		for _, id := range c.CheckIDs {
			ok := slices.ContainsFunc(matrices, func(m string) bool { return backed[m][id] })
			require.True(t, ok,
				"%s rolls up under CIS but %v list %q under no covered/partial control — fix the matrix if the "+
					"check does implement a CIS recommendation, else drop CIS from %s's frameworks",
				c.ID, matrices, id, c.ID)
		}
	}
}
