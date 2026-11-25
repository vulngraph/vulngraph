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

type fakeAuditor struct {
	events []AuditEvent
	err    error
}

func (f *fakeAuditor) RecordAudit(_ context.Context, e AuditEvent) error {
	f.events = append(f.events, e)
	return f.err
}

type fakeConnectors struct {
	c   connector.Connector
	err error
}

func (f *fakeConnectors) Get(context.Context, string) (connector.Connector, error) {
	return f.c, f.err
}

// adminCtx is an authenticated admin whose account is old enough to approve.
func adminCtx(email string) context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: "uid:" + email, Email: email, Role: auth.RoleAdmin,
		CreatedAt: time.Now().Add(-365 * 24 * time.Hour)})
}

// A rejected execution is as auditable as a successful one: "who tried to
// disable which key and was refused" is what an investigation needs.
func TestExecute_FailedAttemptIsAudited(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(&fakeConnectors{c: connector.Connector{
		ID: "conn-1", Type: connector.TypeAWS, Mode: connector.ModeReadOnly,
	}}).WithAudit(audit)

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1",
		Action:      ActionIAMKeyDisable,
		Params:      map[string]string{ParamKeyID: "AKIA123", ParamUsername: "svc"},
	})
	require.ErrorIs(t, err, ErrCapabilityMissing)

	require.Len(t, audit.events, 1)
	e := audit.events[0]
	require.Equal(t, AuditActionExecuteFailed, e.Action)
	require.Equal(t, "ops@example.com", e.Actor)
	require.Equal(t, AuditTargetConnector, e.TargetType)
	require.Equal(t, "conn-1", e.TargetID)
	require.False(t, e.TS.IsZero())

	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(e.Details), &details))
	require.Equal(t, string(ActionIAMKeyDisable), details["action"])
	require.NotEmpty(t, details["error"])
	require.Equal(t, map[string]any{"key_id": "AKIA123", "username": "svc"}, details["params"])
}

// An unauthenticated context must produce an explicitly un-attributed row, not
// a missing one — a mutation with no known actor is the thing to surface.
func TestExecute_UnknownActorIsRecordedNotDropped(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(&fakeConnectors{err: errors.New("no such connector")}).WithAudit(audit)

	_, err := svc.Execute(context.Background(), ExecutionRequest{ConnectorID: "conn-x", Action: ActionEC2Stop})
	require.Error(t, err)
	require.Len(t, audit.events, 1)
	require.Equal(t, AuditActorUnknown, audit.events[0].Actor)
}

// A failing audit sink must not turn a completed (or failed) cloud call into a
// different outcome for the caller.
func TestExecute_AuditFailureDoesNotChangeResult(t *testing.T) {
	audit := &fakeAuditor{err: errors.New("clickhouse down")}
	svc := NewService(&fakeConnectors{c: connector.Connector{
		ID: "conn-1", Type: connector.TypeGCP, Mode: connector.ModeReadWrite,
	}}).WithAudit(audit)

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionSGRuleRemove,
	})
	require.ErrorIs(t, err, ErrCapabilityMissing, "the audit failure must not mask the real error")
	require.Len(t, audit.events, 1)
}

// A nil sink is the "no ClickHouse wired" case and must not panic.
func TestExecute_NoAuditorIsSafe(t *testing.T) {
	svc := NewService(&fakeConnectors{err: errors.New("nope")})
	_, err := svc.Execute(context.Background(), ExecutionRequest{ConnectorID: "c", Action: ActionEC2Stop})
	require.Error(t, err)
}

func TestExecute_AuditTimestampIsUTC(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(&fakeConnectors{err: errors.New("nope")}).WithAudit(audit)
	svc.now = func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.FixedZone("CEST", 2*3600)) }

	_, _ = svc.Execute(context.Background(), ExecutionRequest{ConnectorID: "c", Action: ActionEC2Stop})
	require.Len(t, audit.events, 1)
	require.Equal(t, time.UTC, audit.events[0].TS.Location())
	require.Equal(t, 10, audit.events[0].TS.Hour())
}
