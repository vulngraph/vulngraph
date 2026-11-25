package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/intel"
)

func TestDemoCandidates_CoverTheThreeOutcomes(t *testing.T) {
	got := demoCandidates(time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC))
	require.Len(t, got, 3)

	status := map[intel.CandidateStatus]int{}
	ids := map[string]bool{}
	for _, c := range got {
		status[c.Status]++
		require.False(t, ids[c.ID], "duplicate candidate id")
		ids[c.ID] = true
		require.Equal(t, intel.CandidateID(c.Domain, demoDomain), c.ID)
		require.NotEmpty(t, c.AIReasoning)
		require.True(t, c.NotAfter.After(c.NotBefore))
	}
	require.Equal(t, 2, status[intel.StatusPending])
	require.Equal(t, 1, status[intel.StatusAutoDismissed])
	for _, c := range got {
		if c.Status == intel.StatusAutoDismissed {
			require.False(t, c.AIIsPhishing, "a cleared candidate must carry a benign verdict")
			require.Equal(t, intel.ClearedByTriage, c.ClearedBy())
		}
	}
}

func TestDemoCmd_RejectsUnknownArgs(t *testing.T) {
	require.Error(t, demoCmd(t.Context(), []string{"wipe"}, func(string) string { return "" }, nil))
}
