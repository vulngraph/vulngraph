package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type projectedBlast struct {
	counts asset.BlastAccountCounts
	err    error
	calls  int
}

func (*projectedBlast) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	return asset.BlastRadius{}, errors.New("unexpected full asset read")
}

func (p *projectedBlast) BlastRadiusAccounts(context.Context, string, int) (asset.BlastAccountCounts, error) {
	p.calls++
	return p.counts, p.err
}

func TestBlastAccountProjectionPreservesDiscountAndFailureRules(t *testing.T) {
	for _, counter := range []BlastRadiusCounter{nil, fakeCounter{count: 500}} {
		for _, truncated := range []bool{false, true} {
			provider := &projectedBlast{counts: asset.BlastAccountCounts{Total: 499, ByAccount: map[string]int{"same-account": 499}, Truncated: truncated}}
			source := BlastRadius{Provider: provider, Counter: counter}
			factor, applied, err := source.Evaluate(t.Context(), finding.Finding{ResourceID: "seed"})
			require.NoError(t, err)
			require.True(t, applied)
			require.Equal(t, 1, provider.calls)
			want := 4
			if truncated {
				want = 20
			}
			require.Equal(t, want, factor.Points)
		}
		provider := &projectedBlast{err: errors.New("account query failed")}
		factor, applied, err := (BlastRadius{Provider: provider, Counter: counter}).Evaluate(t.Context(), finding.Finding{ResourceID: "seed"})
		require.Equal(t, 1, provider.calls)
		if counter == nil {
			require.ErrorIs(t, err, provider.err)
			require.False(t, applied)
		} else {
			require.NoError(t, err)
			require.True(t, applied)
			require.Equal(t, 20, factor.Points, "failed account confirmation cannot discount the measured count")
		}
	}
}
