package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
)

// TestBenchmarkMatricesAreWellFormed parses every benchmark matrix and holds
// each control to its status contract: a status, a reason wherever the status
// needs one, and — the part a YAML schema cannot see — every check ID it names
// registered, on the provider the benchmark is for. A renamed or deleted check
// would otherwise leave a control claiming coverage nothing provides.
func TestBenchmarkMatricesAreWellFormed(t *testing.T) {
	bs, err := benchmarks.Load()
	require.NoError(t, err)
	require.NotEmpty(t, bs)

	reg := Default()
	ids := map[string]bool{}
	for _, b := range bs {
		require.False(t, ids[b.ID], "duplicate benchmark id %s", b.ID)
		ids[b.ID] = true
		require.NoError(t, benchmarks.Validate(b))
		for _, c := range b.Controls {
			for _, id := range c.CheckIDs {
				chk, ok := reg.ByID(id)
				require.True(t, ok, "%s %s names check %q, which is not registered", b.ID, c.ID, id)
				require.Contains(t, b.Providers, string(chk.Provider),
					"%s %s names check %q from another provider", b.ID, c.ID, id)
			}
		}
	}
}
