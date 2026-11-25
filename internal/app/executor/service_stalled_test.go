package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// stalledRun puts a run that has been running for age into the fixture, and
// the audit rows its cloud call left.
func stalledRun(f decisionFixture, age time.Duration, actions ...string) {
	started := time.Now().Add(-age)
	f.runs.rows["d-s3"] = DecisionRun{DecisionID: "d-s3", ConnectorID: "conn-1", Action: ActionS3BlockPublic,
		Plan: "block all public access on S3 bucket logs (eu-west-1)", Status: RunRunning,
		ExecutedBy: "a@example.com", ExecutedByID: "uid:a@example.com", CreatedAt: started, UpdatedAt: started}
	for i, a := range actions {
		f.audit.events = append(f.audit.events, AuditEvent{TS: started.Add(time.Duration(i+1) * time.Second),
			Action: a, TargetID: "conn-1", Details: `{"decision_id":"d-s3"}`})
	}
}

// A pod that dies mid-call leaves the run in running. However old it is, a
// click never takes it over: the cloud change may already have happened.
func TestRunDecision_StalledRunIsNeverReclaimedAutomatically(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	stalledRun(f, 3*time.Hour, AuditActionExecuteIntent)
	_, _, err := f.svc.RunDecision(adminCtx("b@example.com"), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrRunConflict)
	require.Equal(t, RunRunning, f.runs.rows["d-s3"].Status)
}

func TestMarkStalledRunFailed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		age      time.Duration
		trail    []string
		auditErr error
		verified bool
		want     error
		evidence runEvidence
	}{
		{name: "a run still in flight is not released", age: 5 * time.Minute, trail: []string{AuditActionExecuteIntent},
			verified: true, want: ErrRunNotStalled},
		{name: "intent with no result needs verification", age: time.Hour, trail: []string{AuditActionExecuteIntent},
			want: ErrCloudStateUnverified},
		{name: "intent with no result, verified", age: time.Hour, trail: []string{AuditActionExecuteIntent},
			verified: true, evidence: evidenceIntentWithoutResult},
		{name: "a recorded result still needs verification", age: time.Hour,
			trail: []string{AuditActionExecuteIntent, AuditActionExecute}, want: ErrCloudStateUnverified},
		{name: "an unreadable trail needs verification", age: time.Hour, auditErr: errors.New("clickhouse down"),
			want: ErrCloudStateUnverified},
		{name: "an unreadable trail, verified", age: time.Hour, auditErr: errors.New("clickhouse down"),
			verified: true, evidence: evidenceUnknown},
		{name: "no intent row: the call never went out", age: time.Hour, trail: []string{AuditActionDryRun},
			evidence: evidenceNoIntent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDecisionFixture(t, execConnector(), nil)
			stalledRun(f, tc.age, tc.trail...)
			if tc.auditErr != nil {
				f.svc.decisions.Audit = failingAuditReader{tc.auditErr}
			}
			run, err := f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", tc.verified, "checked the console")
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.Equal(t, RunRunning, f.runs.rows["d-s3"].Status, "a refused release leaves the run held")
				return
			}
			require.NoError(t, err)
			require.Equal(t, RunFailed, run.Status)
			require.Contains(t, run.Error, "marked failed by b@example.com")
			require.Contains(t, run.Error, string(tc.evidence))
			require.Contains(t, run.Error, "checked the console")

			last := f.audit.events[len(f.audit.events)-1]
			require.Equal(t, AuditActionRunMarkedFailed, last.Action)
			require.Equal(t, "b@example.com", last.Actor)
			d := details(t, last)
			require.Equal(t, string(tc.evidence), d["evidence"])
			require.Equal(t, tc.verified, d["verified"])

			// Released, the fix may be retried by a click.
			_, _, err = f.svc.RunDecision(adminCtx("b@example.com"), "d-s3", nil, "", decisionRequest)
			require.ErrorIs(t, err, ErrNoExecutionRole, "the retry reaches the credential step")
		})
	}
}

func TestMarkStalledRunFailed_RefusesWhatIsNotRunning(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	_, err := f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", true, "")
	require.ErrorIs(t, err, ErrRunNotStalled, "no run at all")

	for _, status := range []RunStatus{RunSucceeded, RunFailed, RunAwaitingSecondAdmin} {
		f.runs.rows["d-s3"] = DecisionRun{DecisionID: "d-s3", Status: status, UpdatedAt: time.Now().Add(-time.Hour)}
		_, err := f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", true, "")
		require.ErrorIs(t, err, ErrRunNotStalled, string(status))
		require.Equal(t, status, f.runs.rows["d-s3"].Status)
	}

	_, err = f.svc.MarkStalledRunFailed(context.Background(), "d-s3", true, "")
	require.ErrorIs(t, err, ErrNoPrincipal)
}

type failingAuditReader struct{ err error }

func (f failingAuditReader) DecisionAudit(context.Context, string, time.Time) ([]AuditEvent, error) {
	return nil, f.err
}

func (f failingAuditReader) DecisionRunEvents(context.Context, string, time.Time) ([]AuditEvent, error) {
	return nil, f.err
}

// More dry runs than a page cannot push the intent row out of the evidence
// read; and a full page of intent/result rows reads as unknown, never as
// "no intent".
func TestMarkStalledRunFailed_DryRunsCannotHideTheIntent(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	dry := make([]string, DecisionRunEventsLimit+5)
	for i := range dry {
		dry[i] = AuditActionDryRun
	}
	stalledRun(f, time.Hour, append(dry, AuditActionExecuteIntent)...)
	require.Equal(t, evidenceIntentWithoutResult, f.svc.stalledRunEvidence(context.Background(), f.runs.rows["d-s3"]),
		"the intent row is found past a page of dry runs, not lost to the page cap")
	_, err := f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", false, "")
	require.ErrorIs(t, err, ErrCloudStateUnverified)

	f = newDecisionFixture(t, execConnector(), nil)
	full := make([]string, DecisionRunEventsLimit)
	for i := range full {
		full[i] = AuditActionExecuteFailed
	}
	stalledRun(f, time.Hour, full...)
	require.Equal(t, evidenceUnknown, f.svc.stalledRunEvidence(context.Background(), f.runs.rows["d-s3"]))
}

// A released run that finishes late cannot overwrite the retry's state.
func TestFinishRun_LateAttemptDoesNotOverwriteTheRetry(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	stalledRun(f, time.Hour, AuditActionExecuteIntent)
	stale := f.runs.rows["d-s3"]
	_, err := f.svc.MarkStalledRunFailed(adminCtx("b@example.com"), "d-s3", true, "")
	require.NoError(t, err)
	retry := stale
	retry.Status, retry.CreatedAt = RunRunning, time.Now().Add(time.Minute)
	f.runs.rows["d-s3"] = retry

	_, _, _ = f.svc.finishRun(context.Background(), testTargets["d-s3"], stale, Principal{Name: "a"}, ExecutionResult{Detail: "late"}, nil)
	require.Equal(t, RunRunning, f.runs.rows["d-s3"].Status, "the retry is still the one running")
}

// The cloud call's own timeout sits well inside the stall window.
func TestExecutionTimeoutIsWellInsideTheStallWindow(t *testing.T) {
	require.Less(t, ExecutionTimeout, RunStallAfter/2)
}
