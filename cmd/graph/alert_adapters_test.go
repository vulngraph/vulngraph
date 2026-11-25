package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

type capturedDispatch struct{ sent []notify.Notification }

func (c *capturedDispatch) Dispatch(_ context.Context, n notify.Notification) {
	c.sent = append(c.sent, n)
}

// Slack follows Decision.Notifiable: a plain observe is noise, an observe
// plan escalated for an urgent finding is not.
func TestSlackDecisionNotifier_FollowsNotifiable(t *testing.T) {
	d := &capturedDispatch{}
	n := &slackDecisionNotifier{notify: d}
	f := finding.Finding{ID: "f1", Title: "KEV on prod"}

	require.NoError(t, n.Notify(context.Background(), f,
		respond.Decision{Plan: respond.Plan{ActionClass: respond.ClassObserve}, Outcome: respond.OutcomeObserved}, respond.ContextPack{}))
	require.Empty(t, d.sent)

	require.NoError(t, n.Notify(context.Background(), f,
		respond.Decision{Plan: respond.Plan{ActionClass: respond.ClassObserve}, Outcome: respond.OutcomeEscalated}, respond.ContextPack{}))
	require.Len(t, d.sent, 1, "the escalated observe plan reaches Slack")
	require.Contains(t, d.sent[0].Title, "escalated")
}

// An unmeasured blast radius reads "unmeasured" in Slack, never "0 assets".
func TestSlackDecisionNotifier_UnmeasuredBlastRadius(t *testing.T) {
	d := &capturedDispatch{}
	n := &slackDecisionNotifier{notify: d}
	f := finding.Finding{ID: "f1", Title: "Public bucket"}
	plan := respond.Plan{ActionClass: respond.ClassRemediate}

	require.NoError(t, n.Notify(context.Background(), f,
		respond.Decision{Plan: plan, Outcome: respond.OutcomeParked}, respond.ContextPack{}))
	require.NoError(t, n.Notify(context.Background(), f,
		respond.Decision{Plan: plan, Outcome: respond.OutcomeParked, BlastRadius: 2, BlastRadiusKnown: true}, respond.ContextPack{}))
	require.Len(t, d.sent, 2)
	blast := func(n notify.Notification) string {
		for _, fl := range n.Fields {
			if fl.Label == "Blast radius" {
				return fl.Value
			}
		}
		return ""
	}
	require.Equal(t, "unmeasured", blast(d.sent[0]))
	require.Equal(t, "2 assets", blast(d.sent[1]))
}

// An unsigned decision webhook used to be sent with only a warning; the
// receiver cannot tell it from a forgery. It is now refused unless the
// operator opts in to unsigned delivery.
func TestDecisionWebhookNotifier(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"no url", map[string]string{"DECISION_WEBHOOK_SECRET": "s"}, false},
		{"url without secret is refused", map[string]string{"DECISION_WEBHOOK_URL": "https://hook.example"}, false},
		{"opt-in must be exactly true", map[string]string{"DECISION_WEBHOOK_URL": "https://hook.example", "DECISION_WEBHOOK_ALLOW_UNSIGNED": "1"}, false},
		{"explicit unsigned opt-in", map[string]string{"DECISION_WEBHOOK_URL": "https://hook.example", "DECISION_WEBHOOK_ALLOW_UNSIGNED": "true"}, true},
		{"signed", map[string]string{"DECISION_WEBHOOK_URL": "https://hook.example", "DECISION_WEBHOOK_SECRET": "s"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := decisionWebhookNotifier(context.Background(), func(k string) string { return tc.env[k] })
			require.Equal(t, tc.want, n != nil)
		})
	}
}

type stubDecisionNotifier struct {
	err   error
	calls int
}

func (s *stubDecisionNotifier) Notify(context.Context, finding.Finding, respond.Decision, respond.ContextPack) error {
	s.calls++
	return s.err
}

type stubApprovalNotifier struct {
	err   error
	calls int
}

func (s *stubApprovalNotifier) NotifyApproval(context.Context, govern.ApprovalPayload) error {
	s.calls++
	return s.err
}

// Every notifier runs even when an earlier one fails, and the failure is
// returned instead of being swallowed as success.
func TestMultiNotifiers_RunAllAndReturnErrors(t *testing.T) {
	boom := errors.New("webhook down")
	failing, ok := &stubDecisionNotifier{err: boom}, &stubDecisionNotifier{}
	err := multiDecisionNotifier{failing, ok}.Notify(context.Background(), finding.Finding{}, respond.Decision{}, respond.ContextPack{})
	require.ErrorIs(t, err, boom)
	require.Equal(t, 1, ok.calls, "a failure does not block the others")
	require.NoError(t, multiDecisionNotifier{ok}.Notify(context.Background(), finding.Finding{}, respond.Decision{}, respond.ContextPack{}))

	af, aok := &stubApprovalNotifier{err: boom}, &stubApprovalNotifier{}
	require.ErrorIs(t, multiApprovalNotifier{af, aok}.NotifyApproval(context.Background(), govern.ApprovalPayload{}), boom)
	require.Equal(t, 1, aok.calls)
	require.NoError(t, multiApprovalNotifier{aok}.NotifyApproval(context.Background(), govern.ApprovalPayload{}))
}
