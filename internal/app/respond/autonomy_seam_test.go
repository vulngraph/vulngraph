package respond

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/policy"
)

// unwalkableBlast fails every walk and resolves nothing — a ClickHouse error, a
// pruned Ladybug seed, or a resource id the graph has never heard of.
type unwalkableBlast struct{ walks int }

func (b *unwalkableBlast) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	b.walks++
	return asset.BlastRadius{}, errors.New("clickhouse: Code: 241 Memory limit (total) exceeded")
}

func (b *unwalkableBlast) ResolveID(_ context.Context, identifier string) (string, error) {
	return identifier, nil // resolves to itself: nothing new to walk
}

// TestDecide_NoStateChangingPlanEverAutoExecutes wires the REAL policy gate,
// because the thing under test is the seam and not either side of it: no
// state-changing plan leaves Decide with an outcome that does not wait for a
// human (ADR 087).
//
// Every fake is the most permissive one available — high confidence, a
// measured blast radius of zero, a finding with nothing exposed — so the only
// thing standing between these plans and autonomy is the rule itself. It
// fails if policy.Decide regains a state-changing AllowAuto grant, or if
// Decide stops handing the gate the plan's real action class.
func TestDecide_NoStateChangingPlanEverAutoExecutes(t *testing.T) {
	gate := policy.Gate{}

	for _, class := range []ActionClass{ClassRemediate, ClassModify, ClassIsolate, ClassDestroy} {
		for name, blast := range map[string]BlastRadiusProvider{
			"measured zero": fakeBlast{n: 0},
			"unmeasured":    &unwalkableBlast{},
		} {
			t.Run(string(class)+"/"+name, func(t *testing.T) {
				audit := &fakeAudit{}
				svc := NewService(
					fakeReasoner{plan: Plan{ActionClass: class, Summary: "change it"}},
					gate,
					fakeConfidence{band: memory.BandHigh, score: 1, effectiveN: 100, samples: 100},
					blast,
					audit, nil, nil, nil,
				)
				svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

				d, err := svc.Decide(context.Background(), aFinding)
				require.NoError(t, err)
				require.Containsf(t, []Outcome{OutcomeParked, OutcomeEscalated}, d.Outcome,
					"a %s plan left Decide as %q — every state-changing proposal must wait for a human",
					class, d.Outcome)
				require.Len(t, audit.events, 1, "the proposal is still audited")
			})
		}
	}
}

// TestDecide_ObservePlanIsObserved pins the one thing that may proceed without
// a human: a read-only observe plan, recorded as observed — nothing changed.
func TestDecide_ObservePlanIsObserved(t *testing.T) {
	gate := policy.Gate{}

	audit := &fakeAudit{}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassObserve, Summary: "keep watching"}},
		gate,
		fakeConfidence{band: memory.BandInsufficient},
		fakeBlast{n: 3},
		audit, nil, nil, nil,
	)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	d, err := svc.Decide(context.Background(), finding.Finding{ID: "f-observe", ResourceID: "i-1", ResourceType: "ec2_instance"})
	require.NoError(t, err)
	require.Equal(t, OutcomeObserved, d.Outcome)
	require.Len(t, audit.events, 1)
}

// TestDecide_UnmeasuredBlastRadiusReachesTheApprover keeps the known-ness bit
// on the proposal: the gate no longer weighs blast radius, but the human who
// approves does, and a failed walk must reach them as "unmeasured", not 0.
func TestDecide_UnmeasuredBlastRadiusReachesTheApprover(t *testing.T) {
	gate := policy.Gate{}

	blast := &unwalkableBlast{}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "revoke the rule"}},
		gate,
		fakeConfidence{band: memory.BandHigh},
		blast,
		&fakeAudit{}, nil, nil, nil,
	)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	d, err := svc.Decide(context.Background(), finding.Finding{
		ID: "f-unwalkable", ResourceID: "i-unreachable", ResourceType: "ec2_instance",
	})
	require.NoError(t, err, "an unmeasurable blast radius is not fatal")
	require.Positive(t, blast.walks, "the walk must actually have been attempted")
	require.Equal(t, OutcomeParked, d.Outcome)
	require.False(t, d.BlastRadiusKnown)
}
