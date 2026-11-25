package finding_test

// External package on purpose: internal/app/coverage transitively imports
// internal/app/finding via internal/app/enrich, so this guard would create an
// import cycle if it lived in `package finding` alongside source_activity.go.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/coverage"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// The guard against the exact drift internal/app/coverage's own doc comment
// warns about: every source this tree can actually produce must be a
// conscious decision here, either paged on (finding.ExpectedActivitySources)
// or explicitly excluded with a reason (finding.ExcludedActivitySources) —
// never silently unaccounted for, which is how a brand-new automated producer
// would stay invisible to GraphFindingSourceDark forever.
func TestExpectedActivitySourcesAccountsForEveryDeclaredSource(t *testing.T) {
	declared, err := coverage.DeclaredSources("../../..")
	require.NoError(t, err)

	expected := map[string]bool{}
	for _, s := range finding.ExpectedActivitySources {
		expected[s] = true
	}

	var unaccounted []string
	for _, source := range declared {
		if expected[source] || finding.ExcludedActivitySources[source] != "" {
			continue
		}
		unaccounted = append(unaccounted, source)
	}
	assert.Emptyf(t, unaccounted,
		"source(s) %v declared in the tree but not in ExpectedActivitySources or ExcludedActivitySources — "+
			"decide whether GraphFindingSourceDark should alert on them and record why either way", unaccounted)
}

// Every excluded source must still be one the tree actually declares — an
// exclusion for a source that no longer exists is dead weight that could be
// hiding a typo'd name that was meant to match a real one.
func TestExcludedActivitySourcesAreAllStillDeclared(t *testing.T) {
	declared, err := coverage.DeclaredSources("../../..")
	require.NoError(t, err)
	declaredSet := map[string]bool{}
	for _, s := range declared {
		declaredSet[s] = true
	}
	for source := range finding.ExcludedActivitySources {
		assert.Truef(t, declaredSet[source], "ExcludedActivitySources names %q, which the tree no longer declares", source)
	}
}
