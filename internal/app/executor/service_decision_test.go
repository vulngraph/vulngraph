package executor

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeTargets map[string]DecisionTarget

func (f fakeTargets) DecisionTarget(_ context.Context, id string) (DecisionTarget, error) {
	t, ok := f[id]
	if !ok {
		return DecisionTarget{}, ErrDecisionNotFound
	}
	return t, nil
}

type fakeOwners map[string][]string

func (f fakeOwners) ConnectorsCollecting(_ context.Context, assetID string) ([]string, error) {
	return f[assetID], nil
}

// fakeRuns mirrors the claim rules of the decision_executions queries.
type fakeRuns struct {
	rows map[string]DecisionRun
	now  func() time.Time
}

func (f *fakeRuns) Get(_ context.Context, id string) (DecisionRun, bool, error) {
	r, ok := f.rows[id]
	return r, ok, nil
}

func (f *fakeRuns) Claim(_ context.Context, run DecisionRun) (DecisionRun, bool, error) {
	if r, ok := f.rows[run.DecisionID]; ok {
		expired := r.Status == RunAwaitingSecondAdmin && r.GrantExpiresAt.Before(f.now())
		if r.Status != RunFailed && !expired {
			return DecisionRun{}, false, nil
		}
	}
	run.CreatedAt, run.UpdatedAt = f.now(), f.now()
	f.rows[run.DecisionID] = run
	return run, true, nil
}

func (f *fakeRuns) ClaimApproved(_ context.Context, id, by, byID string) (DecisionRun, bool, error) {
	r, ok := f.rows[id]
	if !ok || r.Status != RunAwaitingSecondAdmin || !f.now().Before(r.GrantExpiresAt) || r.RequestedByID == byID {
		return DecisionRun{}, false, nil
	}
	r.Status, r.ExecutedBy, r.ExecutedByID = RunRunning, by, byID
	f.rows[id] = r
	return r, true, nil
}

func (f *fakeRuns) Finish(ctx context.Context, id string, claimedAt time.Time, status RunStatus, detail, errText string) error {
	if err := ctx.Err(); err != nil {
		return err // like pgx on a dead context
	}
	r, ok := f.rows[id]
	if !ok || r.Status != RunRunning || !r.CreatedAt.Equal(claimedAt) {
		return errors.New("not running, or a different attempt")
	}
	r.Status, r.Detail, r.Error, r.GrantToken = status, detail, errText, ""
	f.rows[id] = r
	return nil
}

func (f *fakeRuns) FailStalled(_ context.Context, id string, staleAfter time.Duration, errText string) (DecisionRun, bool, error) {
	r, ok := f.rows[id]
	releasable := r.Status == RunOutcomeUnknown || (r.Status == RunRunning && r.UpdatedAt.Before(f.now().Add(-staleAfter)))
	if !ok || !releasable {
		return DecisionRun{}, false, nil
	}
	r.Status, r.Error, r.GrantToken, r.UpdatedAt = RunFailed, errText, "", f.now()
	f.rows[id] = r
	return r, true, nil
}

type fakeDecisionOutcomes struct{ recorded []DecisionTarget }

func (f *fakeDecisionOutcomes) RecordExecuted(ctx context.Context, t DecisionTarget, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.recorded = append(f.recorded, t)
	return nil
}

// DecisionAudit reads back what the service wrote, by the decision_id tag —
// oldest first and capped at 100 rows of any action, like selectDecisionAudit.
func (f *fakeAuditor) DecisionAudit(_ context.Context, decisionID string, _ time.Time) ([]AuditEvent, error) {
	var out []AuditEvent
	for _, e := range f.tagged(decisionID) {
		if len(out) < 100 {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeAuditor) tagged(decisionID string) []AuditEvent {
	var out []AuditEvent
	for _, e := range f.events {
		var d map[string]any
		if json.Unmarshal([]byte(e.Details), &d) == nil && d["decision_id"] == decisionID {
			out = append(out, e)
		}
	}
	return out
}

// DecisionRunEvents mirrors the CH query: intent and result rows only, capped.
func (f *fakeAuditor) DecisionRunEvents(_ context.Context, decisionID string, _ time.Time) ([]AuditEvent, error) {
	var out []AuditEvent
	for _, e := range f.tagged(decisionID) {
		switch e.Action {
		case AuditActionExecuteIntent, AuditActionExecute, AuditActionExecuteFailed:
			if len(out) < DecisionRunEventsLimit {
				out = append(out, e)
			}
		}
	}
	return out, nil
}

// ── fixtures ──────────────────────────────────────────────────────────────────

const (
	ec2ARN = "arn:aws:ec2:eu-west-1:1:instance/i-abc"
	s3ARN  = "arn:aws:s3:::logs"
)

var testTargets = fakeTargets{
	// ec2_stop: destructive, needs a second admin; confirm by typing i-abc.
	"d-stop": {DecisionID: "d-stop", FindingID: "f-stop", ActionClass: "isolate", AwaitingHuman: true,
		ResourceType: "ec2_instance", ResourceID: ec2ARN, Region: "eu-west-1"},
	// s3_block_public: reversible, one admin's click runs it.
	"d-s3": {DecisionID: "d-s3", FindingID: "f-s3", ActionClass: "remediate", AwaitingHuman: true,
		ResourceType: "s3_bucket", ResourceID: s3ARN, Region: "eu-west-1"},
	// sg_rule_remove: the finding does not carry the rule, so a person types it.
	"d-sg": {DecisionID: "d-sg", FindingID: "f-sg", ActionClass: "remediate", AwaitingHuman: true,
		ResourceType: "security_group", ResourceID: "sg-1", Region: "eu-west-1"},
	// ec2_stop with no region on the finding: the connector's region fills it.
	"d-noregion": {DecisionID: "d-noregion", FindingID: "f-nr", ActionClass: "isolate", AwaitingHuman: true,
		ResourceType: "ec2_instance", ResourceID: "i-xyz"},
}

// execConnector is a read_write AWS connector whose execution role is set but
// equals its collection role: the plan reads as runnable, and Execute stops at
// the credential check (ErrNoExecutionRole) with no network — proof every gate
// before the cloud call passed.
func execConnector() connector.Connector {
	return connector.Connector{ID: "conn-1", Name: "prod", Type: connector.TypeAWS, Mode: connector.ModeReadWrite,
		Config: map[string]string{"region": "eu-west-1", "role_arn": "arn:aws:iam::1:role/collect",
			ConfigExecuteRoleARN: "arn:aws:iam::1:role/collect"}}
}

type decisionFixture struct {
	svc      *Service
	runs     *fakeRuns
	audit    *fakeAuditor
	outcomes *fakeDecisionOutcomes
}

func newDecisionFixture(t *testing.T, c connector.Connector, owners fakeOwners) decisionFixture {
	t.Helper()
	f := decisionFixture{
		runs:     &fakeRuns{rows: map[string]DecisionRun{}, now: time.Now},
		audit:    &fakeAuditor{},
		outcomes: &fakeDecisionOutcomes{},
	}
	if owners == nil {
		owners = fakeOwners{ec2ARN: {"conn-1"}, s3ARN: {"conn-1"}, "sg-1": {"conn-1"}, "i-xyz": {"conn-1"}}
	}
	f.svc = NewService(&fakeConnectors{c: c}).WithAudit(f.audit).WithApprovals(testApprover(t)).
		WithDecisions(DecisionDeps{Targets: testTargets, Owners: owners, Runs: f.runs, Outcomes: f.outcomes, Audit: f.audit})
	return f
}

func youngAdminCtx(email string) context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: "uid:" + email, Email: email, Role: auth.RoleAdmin,
		CreatedAt: time.Now().Add(-time.Hour)})
}

// ── plan ──────────────────────────────────────────────────────────────────────

// Every reason a fix cannot run from Vulngraph lands as guidance_only with the
// reason spelled out, and binding it is refused — Vulngraph never guesses an
// owner or works around a connector that cannot write.
func TestPlanDecision_GuidanceOnly(t *testing.T) {
	readOnly := execConnector()
	readOnly.Mode = connector.ModeReadOnly
	noExecRole := execConnector()
	delete(noExecRole.Config, ConfigExecuteRoleARN)
	gcp := execConnector()
	gcp.Type = connector.TypeGCP

	targets := fakeTargets{
		"observed": {DecisionID: "observed", ActionClass: "observe", ResourceType: "s3_bucket", ResourceID: s3ARN},
		"gone":     {DecisionID: "gone", ActionClass: "remediate", AwaitingHuman: true},
		"no-fit":   {DecisionID: "no-fit", ActionClass: "remediate", AwaitingHuman: true, ResourceType: "rds_instance", ResourceID: "db-1"},
		"s3":       testTargets["d-s3"],
	}
	for _, tc := range []struct {
		name     string
		decision string
		c        connector.Connector
		owners   fakeOwners
		reason   string
	}{
		{"not awaiting a person", "observed", execConnector(), nil, "not waiting on a person"},
		{"finding gone", "gone", execConnector(), nil, "could not be loaded"},
		{"no executor action fits", "no-fit", execConnector(), nil, "No executor action"},
		{"no connector collects it", "s3", execConnector(), fakeOwners{}, "No connector currently collects"},
		{"two connectors collect it", "s3", execConnector(), fakeOwners{s3ARN: {"conn-1", "conn-2"}}, "will not guess"},
		{"wrong connector type", "s3", gcp, fakeOwners{s3ARN: {"conn-1"}}, "needs a aws one"},
		{"read-only connector", "s3", readOnly, fakeOwners{s3ARN: {"conn-1"}}, "to run fixes from Vulngraph."},
		{"no execution role", "s3", noExecRole, fakeOwners{s3ARN: {"conn-1"}}, ConfigExecuteRoleARN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDecisionFixture(t, tc.c, tc.owners)
			f.svc.decisions.Targets = targets
			p, err := f.svc.PlanDecision(context.Background(), tc.decision)
			require.NoError(t, err)
			require.Equal(t, PlanGuidanceOnly, p.State)
			require.Contains(t, p.Reason, tc.reason)

			_, _, err = f.svc.DryRunDecision(adminCtx("a@example.com"), tc.decision, nil, decisionRequest)
			require.ErrorIs(t, err, ErrNotRunnable)
			_, _, err = f.svc.RunDecision(adminCtx("a@example.com"), tc.decision, nil, "", decisionRequest)
			require.ErrorIs(t, err, ErrNotRunnable)
			require.Empty(t, f.runs.rows, "nothing claimed")
		})
	}
}

func TestPlanDecision_ReadyOrNeedsInput(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	ctx := context.Background()

	p, err := f.svc.PlanDecision(ctx, "d-s3")
	require.NoError(t, err)
	require.Equal(t, PlanReady, p.State)
	require.Equal(t, ActionS3BlockPublic, p.Action)
	require.Equal(t, "prod", p.ConnectorName)
	require.Equal(t, map[string]string{ParamBucketName: "logs", ParamRegion: "eu-west-1"}, p.Params)
	require.Empty(t, p.Inputs)
	require.False(t, p.RequiresSecondAdmin)

	p, err = f.svc.PlanDecision(ctx, "d-sg")
	require.NoError(t, err)
	require.Equal(t, PlanNeedsInput, p.State)
	require.Equal(t, []string{ParamCIDR, ParamFromPort, ParamProtocol, ParamToPort}, p.Inputs)
	require.Equal(t, "sg-1", p.Params[ParamGroupID])

	p, err = f.svc.PlanDecision(ctx, "d-stop")
	require.NoError(t, err)
	require.Equal(t, PlanReady, p.State)
	require.True(t, p.RequiresSecondAdmin)

	p, err = f.svc.PlanDecision(ctx, "d-noregion")
	require.NoError(t, err)
	require.Equal(t, PlanReady, p.State, "the connector's region fills the gap, as the execution itself would")
	require.Equal(t, []string{ParamRegion}, p.Inputs, "still offered, so a person can name another region")

	_, err = f.svc.PlanDecision(ctx, "d-unknown")
	require.ErrorIs(t, err, ErrDecisionNotFound)
}

// ── dry run ───────────────────────────────────────────────────────────────────

func TestDryRunDecision_TypedInputsNeverOverrideTheFinding(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	ctx := adminCtx("a@example.com")
	rule := map[string]string{ParamProtocol: "tcp", ParamFromPort: "22", ParamToPort: "22", ParamCIDR: "0.0.0.0/0"}

	bp, res, err := f.svc.DryRunDecision(ctx, "d-sg", rule, decisionRequest)
	require.NoError(t, err)
	require.True(t, res.DryRun)
	require.Contains(t, res.Detail, "DRY RUN — nothing was changed")
	require.Contains(t, res.Detail, bp.Change)
	require.Contains(t, bp.Change, "security group sg-1")
	require.Empty(t, bp.ConfirmText, "a reversible rule revoke needs no typed confirmation")
	require.Equal(t, "d-sg", details(t, f.audit.events[0])["decision_id"], "the dry run is in the decision's trail")

	_, _, err = f.svc.DryRunDecision(ctx, "d-sg", map[string]string{ParamGroupID: "sg-other", ParamCIDR: "0.0.0.0/0"}, decisionRequest)
	require.ErrorIs(t, err, ErrBadParams, "the resource comes from the decision, never from what was typed")

	_, _, err = f.svc.DryRunDecision(ctx, "d-sg", map[string]string{ParamProtocol: "tcp"}, decisionRequest)
	require.ErrorIs(t, err, ErrBadParams)
	require.Contains(t, err.Error(), ParamCIDR, "the missing input is named")

	bp, _, err = f.svc.DryRunDecision(ctx, "d-stop", nil, decisionRequest)
	require.NoError(t, err)
	require.True(t, bp.Destructive)
	require.Equal(t, "i-abc", bp.ConfirmText, "a destructive fix is confirmed by typing what it changes")
}

// ── run ───────────────────────────────────────────────────────────────────────

func TestRunDecision_ReversibleFixRunsOnOneAdminsYes(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	ctx := adminCtx("a@example.com")

	run, _, err := f.svc.RunDecision(ctx, "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrNoExecutionRole, "every gate passed and the cloud call was reached")
	require.Equal(t, RunFailed, run.Status)
	require.Equal(t, RunFailed, f.runs.rows["d-s3"].Status)
	require.Contains(t, f.runs.rows["d-s3"].Error, ConfigExecuteRoleARN)
	require.Equal(t, "a@example.com", f.runs.rows["d-s3"].ExecutedBy)
	require.Empty(t, f.outcomes.recorded, "a failed run is not an outcome")

	p, err := f.svc.PlanDecision(ctx, "d-s3")
	require.NoError(t, err)
	require.True(t, p.AuditKnown)
	var actions []string
	for _, e := range p.Audit {
		actions = append(actions, e.Action)
	}
	require.Equal(t, []string{AuditActionExecuteIntent, AuditActionExecuteFailed}, actions)

	// A failed run can be tried again.
	_, _, err = f.svc.RunDecision(ctx, "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrNoExecutionRole)
}

func TestRunDecision_DoneOrHeldIsNotRunAgain(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	for _, status := range []RunStatus{RunSucceeded, RunRunning} {
		f.runs.rows["d-s3"] = DecisionRun{DecisionID: "d-s3", Status: status}
		_, _, err := f.svc.RunDecision(adminCtx("a@example.com"), "d-s3", nil, "", decisionRequest)
		require.ErrorIs(t, err, ErrRunConflict, string(status))
	}
	for _, e := range f.audit.events {
		require.NotEqual(t, AuditActionExecuteIntent, e.Action)
	}
}

// The two-person rule through two clicks: the first admin's yes mints the
// grant, a different, old-enough admin's typed confirmation runs it — and
// every other combination is refused before the cloud call.
func TestRunDecision_DestructiveFixTakesTwoAdmins(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	alice, bob := adminCtx("alice@example.com"), adminCtx("bob@example.com")

	_, _, err := f.svc.RunDecision(alice, "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalRequired, "one admin alone cannot run a destructive fix")
	require.Empty(t, f.runs.rows)

	_, err = f.svc.RequestDecisionApproval(alice, "d-stop", nil, "i-wrong", decisionRequest)
	require.ErrorIs(t, err, ErrConfirmationMismatch)
	_, err = f.svc.RequestDecisionApproval(youngAdminCtx("new@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalInvalid, "the first admin mints the grant, so their account must be old enough")

	run, err := f.svc.RequestDecisionApproval(alice, "d-stop", nil, "i-abc", decisionRequest)
	require.NoError(t, err)
	require.Equal(t, RunAwaitingSecondAdmin, run.Status)
	require.Equal(t, "alice@example.com", run.RequestedBy)
	require.NotEmpty(t, run.GrantToken)
	require.Equal(t, "stop EC2 instance i-abc in eu-west-1 (the workload goes offline)", run.Plan)

	_, err = f.svc.RequestDecisionApproval(bob, "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrRunConflict, "a live request is not replaced")

	_, _, err = f.svc.RunDecision(alice, "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalInvalid, "the requester cannot be the second admin")
	_, _, err = f.svc.RunDecision(youngAdminCtx("fresh@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalInvalid, "a fresh account cannot be the second person")
	_, _, err = f.svc.RunDecision(bob, "d-stop", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrConfirmationMismatch)
	require.Equal(t, RunAwaitingSecondAdmin, f.runs.rows["d-stop"].Status, "no refusal spent the request")
	for _, e := range f.audit.events {
		require.NotEqual(t, AuditActionExecuteIntent, e.Action, "nothing was about to run yet")
	}

	run, _, err = f.svc.RunDecision(bob, "d-stop", map[string]string{ParamInstanceID: "i-other"}, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrNoExecutionRole, "the grant verified; the credential check is next")
	require.Equal(t, RunFailed, run.Status)
	require.Equal(t, "bob@example.com", f.runs.rows["d-stop"].ExecutedBy)
	require.Empty(t, f.runs.rows["d-stop"].GrantToken, "a spent grant is dropped")

	var intent map[string]any
	for _, e := range f.audit.events {
		if e.Action == AuditActionExecuteIntent {
			intent = details(t, e)
			require.Equal(t, "bob@example.com", e.Actor)
		}
	}
	require.NotNil(t, intent)
	require.Equal(t, "alice@example.com", intent["approved_by"])
	require.Equal(t, "d-stop", intent["decision_id"])
	require.Equal(t, "i-abc", intent["params"].(map[string]any)[ParamInstanceID], "the request's params, not the typed ones")
}

// A live request is not confirmable once its decision stops waiting on a
// person, or once the plan can no longer run from Vulngraph: the second admin's
// click re-checks the decision, not just the request.
func TestRunDecision_ApprovedRequestRechecksTheDecision(t *testing.T) {
	readOnly := execConnector()
	readOnly.Mode = connector.ModeReadOnly
	for name, mutate := range map[string]func(f decisionFixture){
		"decision resolved": func(f decisionFixture) {
			targets := maps.Clone(testTargets)
			d := targets["d-stop"]
			d.AwaitingHuman = false
			targets["d-stop"] = d
			f.svc.decisions.Targets = targets
		},
		"connector now read-only": func(f decisionFixture) {
			f.svc.connectors = &fakeConnectors{c: readOnly}
		},
		"resource moved to another connector": func(f decisionFixture) {
			other := execConnector()
			other.ID = "conn-2"
			f.svc.connectors = &fakeConnectors{c: other}
			f.svc.decisions.Owners = fakeOwners{ec2ARN: {"conn-2"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newDecisionFixture(t, execConnector(), nil)
			_, err := f.svc.RequestDecisionApproval(adminCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
			require.NoError(t, err)
			mutate(f)

			_, _, err = f.svc.RunDecision(adminCtx("bob@example.com"), "d-stop", nil, "i-abc", decisionRequest)
			require.ErrorIs(t, err, ErrNotRunnable)
			require.Equal(t, RunAwaitingSecondAdmin, f.runs.rows["d-stop"].Status, "the refusal did not claim the run")
			for _, e := range f.audit.events {
				require.NotEqual(t, AuditActionExecuteIntent, e.Action, "nothing was about to run")
			}
		})
	}
}

// An expired request cannot be confirmed: the click falls back to a fresh
// run, which a destructive fix refuses.
func TestRunDecision_ExpiredRequestIsNotConfirmable(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	_, err := f.svc.RequestDecisionApproval(adminCtx("alice@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.NoError(t, err)
	r := f.runs.rows["d-stop"]
	r.GrantExpiresAt = time.Now().Add(-time.Second)
	f.runs.rows["d-stop"] = r

	_, _, err = f.svc.RunDecision(adminCtx("bob@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.ErrorIs(t, err, ErrApprovalRequired)

	run, err := f.svc.RequestDecisionApproval(adminCtx("bob@example.com"), "d-stop", nil, "i-abc", decisionRequest)
	require.NoError(t, err, "an expired request can be made again")
	require.Equal(t, "bob@example.com", run.RequestedBy)
}

// Only the executor's actual result reaches the outcome ledger.
func TestFinishRun_RecordsAnOutcomeOnlyForAFixThatRan(t *testing.T) {
	f := newDecisionFixture(t, execConnector(), nil)
	me := Principal{ID: "uid:a", Name: "a@example.com"}
	target := testTargets["d-s3"]

	f.runs.rows["d-s3"] = DecisionRun{DecisionID: "d-s3", Status: RunRunning}
	run, res, err := f.svc.finishRun(context.Background(), target, f.runs.rows["d-s3"], me,
		ExecutionResult{Detail: "blocked all public access on S3 bucket logs"}, nil)
	require.NoError(t, err)
	require.Equal(t, RunSucceeded, run.Status)
	require.Equal(t, "blocked all public access on S3 bucket logs", res.Detail)
	require.Equal(t, RunSucceeded, f.runs.rows["d-s3"].Status)
	require.Equal(t, []DecisionTarget{target}, f.outcomes.recorded)

	f.runs.rows["d-s3"] = DecisionRun{DecisionID: "d-s3", Status: RunRunning}
	run, _, err = f.svc.finishRun(context.Background(), target, f.runs.rows["d-s3"], me, ExecutionResult{}, ErrExecutionFailed)
	require.ErrorIs(t, err, ErrExecutionFailed)
	require.Equal(t, RunFailed, run.Status)
	require.Len(t, f.outcomes.recorded, 1, "a failed execution records nothing")
}

func TestDecisionMethods_RefuseWhenUnwired(t *testing.T) {
	svc := NewService(awsRW())
	_, err := svc.PlanDecision(context.Background(), "d-s3")
	require.ErrorIs(t, err, ErrDecisionsUnwired)
	_, _, err = svc.RunDecision(adminCtx("a@example.com"), "d-s3", nil, "", decisionRequest)
	require.ErrorIs(t, err, ErrDecisionsUnwired)
}
