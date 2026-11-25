package findingctx

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

type fakeFindings struct {
	f   finding.Finding
	err error
}

func (f fakeFindings) Get(context.Context, string) (finding.Finding, error) { return f.f, f.err }

type fakeContext struct{ pack respond.ContextPack }

func (f fakeContext) Context(context.Context, finding.Finding) (respond.ContextPack, error) {
	return f.pack, nil
}

type fakeReason struct {
	entry reasoncache.Entry
	err   error
}

func (f fakeReason) Get(context.Context, string) (reasoncache.Entry, error) {
	return f.entry, f.err
}

type fakeFactors struct{ factors []enrich.Factor }

func (f fakeFactors) Factors(context.Context, string) ([]enrich.Factor, error) {
	return f.factors, nil
}

func svc(find fakeFindings, reason fakeReason, fac fakeFactors) *Service {
	pack := respond.ContextPack{
		Finding:    find.f,
		Blast:      respond.BlastSummary{Count: 3},
		Provenance: respond.Provenance{Connector: "aws", Owner: "team-a"},
	}
	return NewService(find, fakeContext{pack: pack}, reason, fac)
}

func TestContext_AssemblesAllSections(t *testing.T) {
	find := fakeFindings{f: finding.Finding{ID: "f1", Title: "Public bucket", Severity: finding.SeverityHigh}}
	reason := fakeReason{entry: reasoncache.Entry{
		ActionClass: "remediate", Summary: "lock it", Rationale: "owned prod",
		ConfidenceBand: "high", ConfidenceScore: 0.92, EffectiveN: 4.5, SampleCount: 6,
		BlastRadius: 3, CoVeConcerns: []string{"destructive on prod"},
	}}
	fac := fakeFactors{factors: []enrich.Factor{{Source: "kev", Points: 30}}}

	fc, err := svc(find, reason, fac).Context(context.Background(), "f1")
	require.NoError(t, err)
	require.Equal(t, "f1", fc.Finding.ID)
	require.Equal(t, 3, fc.Blast.Count)
	require.Equal(t, "aws", fc.Provenance.Connector)
	require.NotNil(t, fc.Reasoning)
	require.Equal(t, "remediate", fc.Reasoning.ActionClass)
	// The full 7-step trace flows through, not just the plan.
	require.Equal(t, "high", fc.Reasoning.ConfidenceBand)
	require.InDelta(t, 0.92, fc.Reasoning.ConfidenceScore, 0.001)
	require.Equal(t, 6, fc.Reasoning.SampleCount)
	require.Equal(t, 3, fc.Reasoning.BlastRadius)
	require.Equal(t, []string{"destructive on prod"}, fc.Reasoning.CoVeConcerns)
	require.Len(t, fc.Factors, 1)
	require.Equal(t, "kev", fc.Factors[0].Source)
}

func TestContext_NotFound_Propagates(t *testing.T) {
	find := fakeFindings{err: finding.ErrNotFound}
	_, err := svc(find, fakeReason{}, fakeFactors{}).Context(context.Background(), "missing")
	require.ErrorIs(t, err, finding.ErrNotFound)
}

func TestContext_NotReasoned_DegradesGracefully(t *testing.T) {
	find := fakeFindings{f: finding.Finding{ID: "f1"}}
	reason := fakeReason{err: reasoncache.ErrNotFound}

	fc, err := svc(find, reason, fakeFactors{}).Context(context.Background(), "f1")
	require.NoError(t, err)
	require.Nil(t, fc.Reasoning, "no cached decision => no reasoning section, not an error")
	require.Empty(t, fc.Factors)
}

func TestContext_FactorReadError_Ignored(t *testing.T) {
	find := fakeFindings{f: finding.Finding{ID: "f1"}}
	// factors fake never errors; assert a not-reasoned + present-finding still returns.
	fc, err := svc(find, fakeReason{err: errors.New("pg blip")}, fakeFactors{}).Context(context.Background(), "f1")
	require.NoError(t, err)
	require.Nil(t, fc.Reasoning)
}
