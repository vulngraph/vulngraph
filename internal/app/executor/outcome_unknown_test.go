package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

var s3Req = ExecutionRequest{ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs"}}

// The cloud call runs under ExecutionTimeout, detached from the caller: the
// caller's cancellation never reaches it, and it always has a deadline.
func TestExecute_CloudCallHasItsOwnTimeout(t *testing.T) {
	require.Less(t, ExecutionTimeout, 45*time.Second, "the call must finish inside the HTTP request deadline")
	svc := NewService(&fakeConnectors{c: execConnector()})
	var deadline time.Time
	var hasDeadline bool
	var callerCancelled error
	ctx, cancel := context.WithCancel(adminCtx("ops@example.com"))
	svc.call = func(ctx context.Context, _ connector.Connector, _ Action, _ map[string]string) (ExecutionResult, error) {
		deadline, hasDeadline = ctx.Deadline()
		cancel() // the client disconnects mid-call
		callerCancelled = ctx.Err()
		return ExecutionResult{Detail: "done"}, nil
	}
	start := time.Now()
	_, err := svc.Execute(ctx, s3Req)
	require.NoError(t, err)
	require.True(t, hasDeadline, "the cloud call must not inherit an unbounded context")
	require.WithinDuration(t, start.Add(ExecutionTimeout), deadline, 5*time.Second)
	require.NoError(t, callerCancelled, "a disconnect must not cut the mutation off")
}

// timedOut simulates a cloud call still in flight when ExecutionTimeout hits.
func timedOut(ctx context.Context, _ connector.Connector, _ Action, _ map[string]string) (ExecutionResult, error) {
	<-ctx.Done()
	return ExecutionResult{}, errors.New("operation error S3: PutPublicAccessBlock, context deadline exceeded")
}

func shortTimeout(s *Service) { s.execTimeout = 20 * time.Millisecond }

func TestExecute_CallCutOffAfterIntentIsOutcomeUnknown(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(&fakeConnectors{c: execConnector()}).WithAudit(audit)
	shortTimeout(svc)
	svc.call = timedOut
	_, err := svc.Execute(adminCtx("ops@example.com"), s3Req)
	require.ErrorIs(t, err, ErrOutcomeUnknown)
	require.Equal(t, AuditActionExecuteIntent, audit.events[0].Action, "the intent row was written before the call")
	require.Equal(t, AuditActionExecuteOutcomeUnknown, audit.events[len(audit.events)-1].Action,
		"audited as unknown, not as failed")

	// A call that fails on its own is a plain failure.
	svc.call = func(context.Context, connector.Connector, Action, map[string]string) (ExecutionResult, error) {
		return ExecutionResult{}, ErrExecutionFailed
	}
	_, err = svc.Execute(adminCtx("ops@example.com"), s3Req)
	require.ErrorIs(t, err, ErrExecutionFailed)
	require.NotErrorIs(t, err, ErrOutcomeUnknown)
	require.Equal(t, AuditActionExecuteFailed, audit.events[len(audit.events)-1].Action)
}

// A decision run whose call timed out is held as outcome_unknown: a click
// cannot retry it, and the release needs the admin's attestation — but not a
// 15-minute wait, since nothing is in flight.
func TestRunDecision_CutOffCallNeedsVerificationBeforeRetry(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	shortTimeout(f.svc)
	f.svc.call = timedOut
	run, _, err := f.svc.RunDecision(adminCtx("a@example.com"), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrOutcomeUnknown)
	require.Equal(t, RunOutcomeUnknown, run.Status)
	require.Equal(t, RunOutcomeUnknown, f.runs.rows["d-s3"].Status)
	require.Contains(t, f.runs.rows["d-s3"].Error, "verify in the cloud console")
	require.Equal(t, evidenceIntentWithoutResult, f.svc.stalledRunEvidence(context.Background(), f.runs.rows["d-s3"]),
		"an outcome-unknown result row leaves the intent unanswered")

	_, _, err = f.svc.RunDecision(adminCtx("a@example.com"), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrRunConflict, "a plain retry cannot take it")

	_, err = f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", false, "")
	require.ErrorIs(t, err, ErrCloudStateUnverified)
	released, err := f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", true, "bucket was not changed")
	require.NoError(t, err)
	require.Equal(t, RunFailed, released.Status)

	f.svc.call = func(context.Context, connector.Connector, Action, map[string]string) (ExecutionResult, error) {
		return ExecutionResult{Detail: "blocked"}, nil
	}
	run, _, err = f.svc.RunDecision(adminCtx("a@example.com"), "d-s3", nil, "", decisionRequest)
	require.NoError(t, err, "once released, the retry runs")
	require.Equal(t, RunSucceeded, run.Status)
}

// The HTTP request deadline expiring while the call runs must not leave the
// run marked running: the call completes detached, and its state is written
// on a context of its own.
func TestRunDecision_StateIsWrittenAfterTheRequestDeadline(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	f.svc.call = func(context.Context, connector.Connector, Action, map[string]string) (ExecutionResult, error) {
		time.Sleep(100 * time.Millisecond)
		return ExecutionResult{Detail: "blocked"}, nil
	}
	ctx, cancel := context.WithTimeout(adminCtx("a@example.com"), 50*time.Millisecond)
	defer cancel()
	run, _, err := f.svc.RunDecision(ctx, "d-s3", nil, "", decisionRequest)
	require.NoError(t, err, "the detached call completed")
	require.Equal(t, RunSucceeded, run.Status)
	require.Equal(t, RunSucceeded, f.runs.rows["d-s3"].Status, "the state write outlived the request deadline")
	require.Len(t, f.outcomes.recorded, 1)
}

// An outcome-unknown run blocks a new second-admin request, like a running one.
func TestRequestDecisionApproval_RefusesWhileOutcomeUnknown(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	f.runs.rows["d-stop"] = DecisionRun{DecisionID: "d-stop", Status: RunOutcomeUnknown, UpdatedAt: time.Now()}
	_, err := f.svc.RequestDecisionApproval(adminCtx("a@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrRunConflict)
	for _, e := range f.audit.events {
		require.NotEqual(t, AuditActionApprove, e.Action, "no grant is minted for a run that cannot be retried")
	}
}

// Whatever the trail says, an outcome-unknown run is released only with the
// admin's attestation — even when its trail would read as "no intent".
func TestMarkStalledRunFailed_OutcomeUnknownAlwaysNeedsVerification(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	f.runs.rows["d-s3"] = DecisionRun{DecisionID: "d-s3", ConnectorID: "conn-1", Action: ActionS3BlockPublic,
		Status: RunOutcomeUnknown, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	_, err := f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", false, "")
	require.ErrorIs(t, err, ErrCloudStateUnverified)
}
