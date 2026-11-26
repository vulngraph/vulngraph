package executor

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
)

func verifyErr(a *Approver, token, connectorID string, action Action, plan string, executor Principal) error {
	_, err := a.Verify(token, connectorID, action, plan, executor)
	return err
}

// failingIntentAuditor fails only the pre-execution intent write.
type failingIntentAuditor struct{ events []AuditEvent }

func (f *failingIntentAuditor) RecordAudit(_ context.Context, e AuditEvent) error {
	f.events = append(f.events, e)
	if e.Action == AuditActionExecuteIntent {
		return errors.New("clickhouse down")
	}
	return nil
}

func awsRW() *fakeConnectors {
	return &fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}
}

func details(t *testing.T, e AuditEvent) map[string]any {
	t.Helper()
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(e.Details), &d))
	return d
}

// The intent row lands before the cloud call; the result row after it.
func TestExecute_WritesIntentBeforeTheCloudCall(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(awsRW()).WithAudit(audit)

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"},
		Reason: "instance needed for incident triage",
	})
	require.ErrorIs(t, err, ErrNoExecutionRole, "the call was reached (and failed on credentials)")
	require.Len(t, audit.events, 2)
	require.Equal(t, AuditActionExecuteIntent, audit.events[0].Action)
	require.Equal(t, AuditActionExecuteFailed, audit.events[1].Action)
	intent := details(t, audit.events[0])
	require.Equal(t, "block all public access on S3 bucket logs-bucket (eu-west-1)", intent["plan"])
	require.Equal(t, "instance needed for incident triage", intent["reason"])
	require.Equal(t, "instance needed for incident triage", details(t, audit.events[1])["reason"])
}

// No intent row, no mutation: a dark audit trail refuses the call rather than
// running it unaudited.
func TestExecute_IntentWriteFailureRefusesExecution(t *testing.T) {
	audit := &failingIntentAuditor{}
	svc := NewService(awsRW()).WithAudit(audit)

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"},
	})
	require.ErrorIs(t, err, ErrAuditUnavailable)
	require.NotErrorIs(t, err, ErrNoExecutionRole, "the cloud call was never reached")
}

// Dry runs mutate nothing, so they need no intent row.
func TestExecute_DryRunWritesNoIntent(t *testing.T) {
	audit := &failingIntentAuditor{}
	svc := NewService(awsRW()).WithAudit(audit)
	res, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"}, DryRun: true,
	})
	require.NoError(t, err)
	require.True(t, res.DryRun)
	require.Len(t, audit.events, 1)
	require.Equal(t, AuditActionDryRun, audit.events[0].Action)
}

// The display name is spoofable (an API key's is its own name); the user id
// is what attributes the row.
func TestAudit_RowsCarryTheActingUserID(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(awsRW()).WithAudit(audit).WithApprovals(testApprover(t))
	key := auth.ContextWithUser(context.Background(), auth.User{ID: "u-alice", Email: "alice@example.com (api-key)",
		Role: auth.RoleAdmin, CreatedAt: time.Now().Add(-48 * time.Hour), AdminSince: adminTime(time.Now().Add(-48 * time.Hour)), AuthorityVersion: 1})

	_, _ = svc.Execute(key, ExecutionRequest{ConnectorID: "conn-1", Action: ActionS3BlockPublic, Params: map[string]string{ParamBucketName: "logs-bucket"}})
	_, err := svc.Approve(key, ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-1"}})
	require.NoError(t, err)

	require.NotEmpty(t, audit.events)
	for _, e := range audit.events {
		require.Equal(t, "alice@example.com (api-key)", e.Actor, "the name stays for display")
		require.Equal(t, "u-alice", details(t, e)["actor_user_id"], e.Action)
	}
}

// adminCreatedAt is an admin principal whose account was created at created.
func adminCreatedAt(email string, created time.Time) context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: "uid:" + email, Email: email, Role: auth.RoleAdmin, CreatedAt: created, AdminSince: adminTime(created), AuthorityVersion: 1})
}

func TestApprove_RefusesYoungAccounts(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	svc := NewService(awsRW()).WithApprovals(testApprover(t)).WithMinApproverAge(24 * time.Hour)
	svc.now = func() time.Time { return now }
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-1"}}

	_, err := svc.Approve(adminCreatedAt("new@example.com", now.Add(-2*time.Hour)), req)
	require.ErrorIs(t, err, ErrApprovalInvalid)
	require.Contains(t, err.Error(), "admin for at least 24h0m0s")

	_, err = svc.Approve(adminCreatedAt("old@example.com", now.Add(-48*time.Hour)), req)
	require.NoError(t, err)
}

// The floor counts from the later of created_at and admin_since: an old account
// promoted just now is as young as a new one, and an admin whose promotion was
// never recorded cannot approve. Migration 8 starts their continuous tenure
// at upgrade time. An unknown created_at is also refused.
func TestApprove_AccountAgeCountsFromAdminSince(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	old := now.Add(-400 * 24 * time.Hour)
	tests := []struct {
		name       string
		created    time.Time
		adminSince time.Time
		refused    string
	}{
		{"old account promoted an hour ago is refused", old, now.Add(-time.Hour), "admin for 1h0m0s"},
		{"old account promoted just now is refused", old, now, "admin for 0s"},
		{"old account promoted two days ago is allowed", old, now.Add(-48 * time.Hour), ""},
		{"long-time admin is allowed", old, old.Add(time.Hour), ""},
		{"unknown administrator tenure is refused", old, time.Time{}, "administrator tenure"},
		{"young account with no admin_since is refused", now.Add(-2 * time.Hour), time.Time{}, "admin for 2h0m0s"},
		{"unknown created_at is refused despite an old admin_since", time.Time{}, old, "age is unknown"},
		{"unknown created_at and admin_since is refused", time.Time{}, time.Time{}, "age is unknown"},
	}
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-1"}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(awsRW()).WithApprovals(testApprover(t)).WithMinApproverAge(24 * time.Hour)
			svc.now = func() time.Time { return now }
			ctx := auth.ContextWithUser(context.Background(), auth.User{ID: "uid:a", Email: "a@example.com", Role: auth.RoleAdmin,
				CreatedAt: tc.created, AdminSince: tc.adminSince, AuthorityVersion: 1})
			_, err := svc.Approve(ctx, req)
			if tc.refused == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrApprovalInvalid)
			require.Contains(t, err.Error(), tc.refused)
		})
	}
}

// A principal with no account age (zero CreatedAt) never approves — not even
// with the age floor configured to zero, where the arithmetic alone would let
// a zero time through as an ancient account.
func TestApprove_UnknownAccountAgeFailsClosed(t *testing.T) {
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-1"}}
	for _, minAge := range []time.Duration{DefaultMinApproverAccountAge, 0} {
		svc := NewService(awsRW()).WithApprovals(testApprover(t)).WithMinApproverAge(minAge)
		_, err := svc.Approve(adminCreatedAt("ghost@example.com", time.Time{}), req)
		require.ErrorIs(t, err, ErrApprovalInvalid, "min age %s", minAge)
		require.Contains(t, err.Error(), "age is unknown")
	}
}

// RequireGrant (the MCP seam) makes every real execution need a second
// admin's grant, including actions that are otherwise grant-free.
func TestExecute_RequireGrantGatesNonDestructiveActions(t *testing.T) {
	svc := NewService(awsRW()).WithApprovals(testApprover(t))
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionS3BlockPublic,
		Params: map[string]string{ParamBucketName: "logs-bucket"}, RequireGrant: true}

	_, err := svc.Execute(adminCtx("agent@example.com"), req)
	require.ErrorIs(t, err, ErrApprovalRequired)

	dry := req
	dry.DryRun = true
	res, err := svc.Execute(adminCtx("agent@example.com"), dry)
	require.NoError(t, err, "a dry run needs no grant")
	require.Contains(t, res.Detail, "requires an approval grant")

	_, err = svc.Approve(adminCtx("human@example.com"), ExecutionRequest{ConnectorID: "conn-1", Action: ActionS3BlockPublic,
		Params: map[string]string{ParamBucketName: "logs-bucket"}})
	require.ErrorIs(t, err, ErrApprovalNotRequired, "without RequireGrant no grant is minted for a non-destructive action")

	grant, err := svc.Approve(adminCtx("human@example.com"), req)
	require.NoError(t, err)
	req.ApprovalToken = grant.Token
	_, err = svc.Execute(adminCtx("agent@example.com"), req)
	require.ErrorIs(t, err, ErrNoExecutionRole, "the grant passes the gate; credentials are the next control")

	_, err = svc.Execute(adminCtx("human@example.com"), req)
	require.ErrorIs(t, err, ErrApprovalInvalid, "the approver cannot also be the executor")
}

// Approver and executor on the same address is flagged in the audit trail.
func TestExecute_SharedAddressWithTheApproverIsFlagged(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(awsRW()).WithAudit(audit).WithApprovals(testApprover(t))
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-1"}}

	grant, err := svc.Approve(auth.ContextWithClientIP(adminCtx("alice@example.com"), "203.0.113.7"), req)
	require.NoError(t, err)
	req.ApprovalToken = grant.Token

	audit.events = nil
	_, _ = svc.Execute(auth.ContextWithClientIP(adminCtx("bob@example.com"), "203.0.113.7"), req)
	require.NotEmpty(t, audit.events)
	for _, e := range audit.events {
		d := details(t, e)
		require.Equal(t, true, d["approver_same_ip"], e.Action)
		require.Equal(t, "alice@example.com", d["approved_by"])
		require.Equal(t, "uid:alice@example.com", d["approver_user_id"])
	}

	audit.events = nil
	_, _ = svc.Execute(auth.ContextWithClientIP(adminCtx("bob@example.com"), "198.51.100.9"), req)
	for _, e := range audit.events {
		require.NotContains(t, details(t, e), "approver_same_ip")
	}
}

// The age floor covers BOTH halves of a grant. Applied to the approver only,
// one admin with an old account approves and a second admin account they
// created minutes ago executes — the two-person rule satisfied by one person.
func TestExecute_RefusesYoungExecutorAccounts(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	svc := NewService(awsRW()).WithApprovals(testApprover(t)).WithMinApproverAge(24 * time.Hour)
	svc.now = func() time.Time { return now }
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-1"}}

	grant, err := svc.Approve(adminCreatedAt("old@example.com", now.Add(-48*time.Hour)), req)
	require.NoError(t, err)
	req.ApprovalToken = grant.Token

	_, err = svc.Execute(adminCreatedAt("new@example.com", now.Add(-2*time.Hour)), req)
	require.ErrorIs(t, err, ErrApprovalInvalid)
	require.Contains(t, err.Error(), "executing account")

	_, err = svc.Execute(adminCreatedAt("ghost@example.com", time.Time{}), req)
	require.ErrorIs(t, err, ErrApprovalInvalid, "an executor of unknown age fails closed")

	_, err = svc.Execute(adminCreatedAt("veteran@example.com", now.Add(-72*time.Hour)), req)
	require.ErrorIs(t, err, ErrNoExecutionRole, "an old executor passes the gate; credentials are the next control")
}
