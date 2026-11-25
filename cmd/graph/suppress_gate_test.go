package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeFindingsByID struct {
	rows  map[string]finding.Finding
	err   error
	calls int
}

func (f *fakeFindingsByID) ByIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []finding.Finding
	for _, id := range ids {
		if r, ok := f.rows[id]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestSuppressAgentGate(t *testing.T) {
	scored := time.Unix(1, 0)
	store := &fakeFindingsByID{rows: map[string]finding.Finding{
		"low":  {ID: "low", Severity: finding.SeverityLow, ScoreBand: "monitor", MustFixClass: "routine", EnrichedAt: scored},
		"crit": {ID: "crit", Severity: finding.SeverityCritical, ScoreBand: "monitor", MustFixClass: "routine", EnrichedAt: scored},
	}}
	got, err := suppressAgentGate{findings: store}.AgentRefusals(context.Background(), []string{"low", "crit", "ghost"})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"low": "", "crit": "critical severity"}, got, "a missing id is absent, not allowed")

	ids := make([]string, agentGateBatch+1)
	for i := range ids {
		ids[i] = fmt.Sprint(i)
	}
	store.calls = 0
	_, err = suppressAgentGate{findings: store}.AgentRefusals(context.Background(), ids)
	require.NoError(t, err)
	require.Equal(t, 2, store.calls, "reads are batched")

	_, err = suppressAgentGate{findings: &fakeFindingsByID{err: errors.New("down")}}.AgentRefusals(context.Background(), []string{"low"})
	require.Error(t, err)
}
