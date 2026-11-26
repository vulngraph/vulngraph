package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeDriftFindings struct {
	found []finding.Finding
	err   error
}

func (f fakeDriftFindings) ByResourceIDs(context.Context, []string) ([]finding.Finding, error) {
	return f.found, f.err
}

type fakeDriftExposure struct {
	exposed map[string]bool
	failOn  string
}

func (f fakeDriftExposure) IsExposedEdge(_ context.Context, id string) (bool, error) {
	if id == f.failOn {
		return false, errors.New("clickhouse down")
	}
	return f.exposed[id], nil
}

func TestDriftFacts_FindingsCountOpenAndMaxScore(t *testing.T) {
	d := driftFacts{findings: fakeDriftFindings{found: []finding.Finding{
		{ResourceID: "a", Score: 40},
		{ResourceID: "a", Score: 80},
		{ResourceID: "a", Score: 99, ResolvedAt: time.Now()},
		{ResourceID: "b", Score: 10},
	}}}

	got, err := d.Findings(t.Context(), []string{"a", "b", "c"})

	require.NoError(t, err)
	assert.Equal(t, 2, got["a"].OpenFindings)
	assert.Equal(t, 80, got["a"].MaxScore, "a resolved finding does not count")
	assert.Equal(t, 1, got["b"].OpenFindings)
	assert.NotContains(t, got, "c", "an asset without findings is absent, not zero-scored")
}

func TestDriftFacts_FindingsFailureIsAnError(t *testing.T) {
	boom := errors.New("too large")
	got, err := driftFacts{findings: fakeDriftFindings{err: boom}}.Findings(t.Context(), []string{"a"})
	require.ErrorIs(t, err, boom)
	assert.Nil(t, got, "no partial map that could read as clean")
}

func TestDriftFacts_Exposure(t *testing.T) {
	d := driftFacts{assets: fakeDriftExposure{exposed: map[string]bool{"a": true}}}
	got, err := d.Exposure(t.Context(), []string{"a", "b"})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"a": true, "b": false}, got)
}

func TestDriftFacts_ExposureAnyFailureFailsTheWholeLookup(t *testing.T) {
	d := driftFacts{assets: fakeDriftExposure{exposed: map[string]bool{"a": true}, failOn: "b"}}
	got, err := d.Exposure(t.Context(), []string{"a", "b"})
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestDriftAnalysisSwitch(t *testing.T) {
	for _, v := range []string{"", "0", "false"} {
		svc, err := driftAnalysisService(t.Context(), func(k string) string {
			return map[string]string{"DRIFT_ANALYSIS_ENABLED": v}[k]
		}, nil, nil, nil, nil)
		require.NoError(t, err)
		assert.Nil(t, svc, "DRIFT_ANALYSIS_ENABLED=%q must leave drift analysis off", v)
	}
	on, err := driftAnalysisService(t.Context(), func(k string) string {
		return map[string]string{"DRIFT_ANALYSIS_ENABLED": "true"}[k]
	}, nil, nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, on)
	assert.True(t, on.Enabled())

	_, err = driftAnalysisService(t.Context(), func(k string) string {
		return map[string]string{"DRIFT_ANALYSIS_ENABLED": "ture"}[k]
	}, nil, nil, nil, nil)
	require.ErrorContains(t, err, "DRIFT_ANALYSIS_ENABLED")
}
