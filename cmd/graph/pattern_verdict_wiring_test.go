package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/policy"
)

// respond's PatternVerdicts consumer receives "approved"/"denied" as plain
// strings (they cross the govern/respond package boundary as strings — see
// the import-cycle note in cmd/graph/worker.go), with nothing at compile time
// tying them back to govern.VerdictApproved/VerdictDenied. This test pins the
// two together by feeding a real govern.Verdict through the exact closure
// shape worker.go wires and asserting respond actually suppresses on it, so a
// future rename of either constant breaks the test instead of silently going
// dark in production.
func TestPatternVerdictStrings_GovernAndRespondAgree(t *testing.T) {
	closure := func(v govern.Verdict) respond.PatternVerdictsFunc {
		return func(context.Context, string, string, string) (string, time.Time, bool, error) {
			return string(v), time.Now(), true, nil
		}
	}

	svc := respond.NewService(
		wiringFakeReasoner{}, wiringFakeGate{decision: policy.Decision{NeedsApproval: true}},
		wiringFakeConfidence{}, wiringFakeBlast{}, &wiringFakeAudit{},
		nil, nil, nil,
	).WithPatternVerdicts(closure(govern.VerdictDenied))

	d, err := svc.Decide(context.Background(), wiringFinding)
	require.NoError(t, err)
	require.Equal(t, respond.OutcomeSuppressedByVerdict, d.Outcome,
		"govern.VerdictDenied, passed through the real closure shape, must suppress in respond")

	svcApproved := respond.NewService(
		wiringFakeReasoner{}, wiringFakeGate{decision: policy.Decision{NeedsApproval: true}},
		wiringFakeConfidence{}, wiringFakeBlast{}, &wiringFakeAudit{},
		nil, nil, nil,
	).WithPatternVerdicts(closure(govern.VerdictApproved))

	d2, err := svcApproved.Decide(context.Background(), wiringFinding)
	require.NoError(t, err)
	require.Equal(t, respond.OutcomeParked, d2.Outcome,
		"govern.VerdictApproved must never suppress — it only annotates")
	require.NotEmpty(t, d2.PlanNotes)
}

var wiringFinding = finding.Finding{ID: "wire-f1", ResourceID: "i-wire-1", ResourceType: "ec2_instance"}

type wiringFakeReasoner struct{}

func (wiringFakeReasoner) Reason(context.Context, respond.ContextPack) (respond.Plan, error) {
	return respond.Plan{ActionClass: respond.ClassRemediate, Summary: "fix it"}, nil
}

type wiringFakeGate struct{ decision policy.Decision }

func (g wiringFakeGate) Evaluate(context.Context, policy.Input) (policy.Decision, error) {
	return g.decision, nil
}

type wiringFakeConfidence struct{}

func (wiringFakeConfidence) Confidence(context.Context, string, string) (memory.Confidence, error) {
	return memory.Confidence{Band: memory.BandHigh}, nil
}

type wiringFakeBlast struct{}

func (wiringFakeBlast) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	return asset.BlastRadius{}, nil
}

func (wiringFakeBlast) ResolveID(_ context.Context, identifier string) (string, error) {
	return identifier, nil
}

type wiringFakeAudit struct{}

func (*wiringFakeAudit) Record(context.Context, respond.AuditEvent) error { return nil }
