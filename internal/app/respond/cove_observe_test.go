package respond

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/policy"
)

// The action class comes from the LLM, and the finding text it reads is
// attacker-influenceable. A prompt injection that lands "observe" on an
// urgent finding would take it out of every human queue, so an observe plan
// for a page/high-band or must_fix finding escalates to a person instead.
func TestCoVe_Check8_ObserveFloor(t *testing.T) {
	br := seed(asset.Asset{ID: "i-1", Type: "ec2_instance"}, 0)
	for _, tc := range []struct {
		name string
		f    finding.Finding
		want bool
	}{
		{"page band", finding.Finding{ScoreBand: string(enrich.BandPage), Score: 95}, true},
		{"high band", finding.Finding{ScoreBand: string(enrich.BandHigh), Score: 75}, true},
		{"must_fix at a lower band", finding.Finding{ScoreBand: string(enrich.BandPipeline), MustFixClass: enrich.MustFix}, true},
		{"pipeline band, routine", finding.Finding{ScoreBand: string(enrich.BandPipeline), MustFixClass: enrich.MustFixRoutine}, false},
		{"elevated is not must_fix", finding.Finding{ScoreBand: string(enrich.BandPipeline), MustFixClass: "elevated"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := verify(Plan{ActionClass: ClassObserve}, tc.f, br, highConf())
			require.Equal(t, tc.want, r.escalate, concatConcerns(r))
			if tc.want {
				require.Contains(t, concatConcerns(r), "observe-only plan")
			}
		})
	}

	// Only observe is floored: an action plan on the same finding is decided
	// by the other guardrails as before.
	r := verify(Plan{ActionClass: ClassRemediate}, finding.Finding{ScoreBand: string(enrich.BandPage), Score: 95}, br, highConf())
	require.NotContains(t, concatConcerns(r), "observe-only plan")
}

// End to end: an injected "observe" on a page-band finding reaches the
// governor queue as escalated, not observed.
func TestDecide_ObservePlanOnAnUrgentFindingWaitsForAHuman(t *testing.T) {
	gate := policy.Gate{}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassObserve, Summary: "ignore this"}},
		gate,
		fakeConfidence{band: memory.BandHigh},
		fakeBlast{n: 0},
		&fakeAudit{}, nil, nil, nil,
	)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	d, err := svc.Decide(context.Background(), finding.Finding{ID: "f-page", ResourceID: "i-1", ResourceType: "ec2_instance",
		Score: 95, ScoreBand: string(enrich.BandPage)})
	require.NoError(t, err)
	require.Equal(t, OutcomeEscalated, d.Outcome)
	require.Equal(t, "verification_concern", d.EscalationReason)
	require.True(t, d.Outcome.AwaitingHuman())
}
