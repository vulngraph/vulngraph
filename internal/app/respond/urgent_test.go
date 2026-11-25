package respond

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/policy"
)

// The pattern key holds the LLM-chosen class, so an injection can steer an
// urgent finding onto a pattern a human once denied. That must escalate it
// (with the denial on record), never suppress it for 90 days.
func TestDecide_PatternDenied_UrgentFindingEscalates(t *testing.T) {
	notifier := &fakeNotifier{}
	pv := &fakePatternVerdicts{verdict: patternVerdictDenied, found: true}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "fix it"}},
		&countingGate{decision: policy.Decision{NeedsApproval: true}}, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1},
		&fakeAudit{}, nil, nil, nil,
	).WithDecisionWebhook(notifier).WithPatternVerdicts(pv)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	for _, f := range []finding.Finding{
		{ID: "f-page", CheckID: "c", ResourceID: "i-1", ResourceType: "s3_bucket", Score: 95, ScoreBand: string(enrich.BandPage)},
		{ID: "f-must", CheckID: "c", ResourceID: "i-2", ResourceType: "s3_bucket", MustFixClass: enrich.MustFix},
	} {
		d, err := svc.Decide(context.Background(), f)
		require.NoError(t, err)
		require.Equal(t, OutcomeEscalated, d.Outcome, f.ID)
		require.Contains(t, concatConcerns(coveResult{concerns: d.CoVeConcerns}), "pattern previously denied")
	}
	require.Equal(t, 2, notifier.calls, "an escalated urgent finding reaches the notifiers")
}

// An escalated observe plan (CoVe check 8) is sent to the decision notifiers;
// a plain observed one is not.
func TestDecisionNotifiable(t *testing.T) {
	require.False(t, Decision{Plan: Plan{ActionClass: ClassObserve}, Outcome: OutcomeObserved}.Notifiable())
	require.True(t, Decision{Plan: Plan{ActionClass: ClassObserve}, Outcome: OutcomeEscalated}.Notifiable())
	require.True(t, Decision{Plan: Plan{ActionClass: ClassRemediate}, Outcome: OutcomeParked}.Notifiable())

	n, ct := testNotifier("whsec")
	d := Decision{FindingID: "f1", Outcome: OutcomeEscalated, Plan: Plan{ActionClass: ClassObserve, Summary: "ignore"}}
	require.NoError(t, n.Notify(context.Background(), finding.Finding{ID: "f1", ScoreBand: string(enrich.BandPage)}, d, ContextPack{}))
	require.NotNil(t, ct.req, "the escalated observe plan reaches the webhook")
}

// The action class is the reasoner's choice, which injected scan text can
// steer. A denial recorded for that one class must not suppress a non-urgent
// finding: it is annotated and goes through the normal gate to a person.
func TestDecide_PatternDeniedForChosenClassOnly_DoesNotSuppress(t *testing.T) {
	notifier := &fakeNotifier{}
	gate := &countingGate{decision: policy.Decision{NeedsApproval: true}}
	pv := &fakePatternVerdicts{byClass: map[string]string{string(ClassDestroy): patternVerdictDenied}}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassDestroy, Summary: "delete it"}},
		gate, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1},
		&fakeAudit{}, nil, nil, nil,
	).WithDecisionWebhook(notifier).WithPatternVerdicts(pv)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	d, err := svc.Decide(context.Background(), finding.Finding{ID: "f1", CheckID: "c", ResourceID: "i-1", ResourceType: "s3_bucket"})
	require.NoError(t, err)
	require.NotEqual(t, OutcomeSuppressedByVerdict, d.Outcome)
	require.Equal(t, OutcomeParked, d.Outcome, "it reaches the normal gate")
	require.Equal(t, 1, gate.calls)
	require.Equal(t, 1, notifier.calls, "a human hears about it")
	require.Contains(t, d.PlanNotes[0], "previously denied")
	require.Equal(t, string(ClassDestroy), pv.gotActionClass, "the chosen class is looked up first")
}

// Suppression is decided by (check_id, resource_type) alone: when every
// class is denied, the outcome is the same whichever class the model picked.
func TestDecide_PatternDeniedForEveryClass_SuppressesWhateverTheClass(t *testing.T) {
	all := map[string]string{}
	for _, c := range patternClasses {
		all[string(c)] = patternVerdictDenied
	}
	for _, class := range patternClasses {
		svc := NewService(
			fakeReasoner{plan: Plan{ActionClass: class, Summary: "x"}},
			&countingGate{decision: policy.Decision{NeedsApproval: true}}, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1},
			&fakeAudit{}, nil, nil, nil,
		).WithPatternVerdicts(&fakePatternVerdicts{byClass: all})
		svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

		d, err := svc.Decide(context.Background(), finding.Finding{ID: "f1", CheckID: "c", ResourceID: "i-1", ResourceType: "s3_bucket"})
		require.NoError(t, err)
		require.Equal(t, OutcomeSuppressedByVerdict, d.Outcome, class)
	}
}

// One expired denial among the classes means not every class is live-denied,
// so nothing is suppressed.
func TestDecide_PatternDenied_ExpiredSiblingBlocksSuppression(t *testing.T) {
	expiring := &expiringPatternVerdicts{fresh: string(ClassRemediate)}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "fix it"}},
		&countingGate{decision: policy.Decision{NeedsApproval: true}}, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1},
		&fakeAudit{}, nil, nil, nil,
	).WithPatternVerdicts(expiring)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC().Add(PatternVerdictMaxAge * 2) }

	d, err := svc.Decide(context.Background(), finding.Finding{ID: "f1", CheckID: "c", ResourceID: "i-1", ResourceType: "s3_bucket"})
	require.NoError(t, err)
	require.Equal(t, OutcomeParked, d.Outcome)
}

// expiringPatternVerdicts denies every class, but only the fresh one was
// decided recently; the rest are past PatternVerdictMaxAge.
type expiringPatternVerdicts struct{ fresh string }

func (e *expiringPatternVerdicts) PatternVerdict(_ context.Context, _, actionClass, _ string) (string, time.Time, bool, error) {
	decidedAt := time.Unix(0, 0).UTC()
	if actionClass == e.fresh {
		decidedAt = decidedAt.Add(PatternVerdictMaxAge * 2)
	}
	return patternVerdictDenied, decidedAt, true, nil
}
