package suppress

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeAuditor struct {
	events []AuditEvent
	err    error
}

func (f *fakeAuditor) RecordAudit(_ context.Context, e AuditEvent) error {
	f.events = append(f.events, e)
	return f.err
}

func auditedService(t *testing.T) (*Service, *fakeAuditor) {
	t.Helper()
	audit := &fakeAuditor{}
	return NewService(newFakeRepo()).WithAudit(audit), audit
}

// Upsert overwrites the previous actor and reason, so the only record that the
// first suppression ever happened is its audit row.
func TestSuppress_OverwritingReSuppressionLeavesBothRows(t *testing.T) {
	svc, audit := auditedService(t)
	ctx := context.Background()

	_, err := svc.SuppressUntil(ctx, "f-1", "false positive", "alice@example.com", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	_, err = svc.SuppressUntil(ctx, "f-1", "accepted risk", "bob@example.com", time.Now().Add(24*time.Hour))
	require.NoError(t, err)

	require.Len(t, audit.events, 2)
	require.Equal(t, "alice@example.com", audit.events[0].Actor)
	require.Equal(t, "bob@example.com", audit.events[1].Actor)
	for i, want := range []string{"false positive", "accepted risk"} {
		var d map[string]any
		require.NoError(t, json.Unmarshal([]byte(audit.events[i].Details), &d))
		require.Equal(t, want, d["reason"])
		require.Equal(t, AuditActionSuppress, audit.events[i].Action)
		require.Equal(t, AuditTargetFinding, audit.events[i].TargetType)
		require.Equal(t, "f-1", audit.events[i].TargetID)
	}
}

// Unsuppress is a hard DELETE: without the audit row a suppress→unsuppress
// cycle returns the database to its original state with no trace of either.
func TestUnsuppress_IsAudited(t *testing.T) {
	svc, audit := auditedService(t)
	ctx := context.Background()

	_, err := svc.SuppressUntil(ctx, "f-1", "why", "alice@example.com", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.NoError(t, svc.Unsuppress(ctx, "f-1", "bob@example.com"))

	require.Len(t, audit.events, 2)
	require.Equal(t, AuditActionUnsuppress, audit.events[1].Action)
	require.Equal(t, "bob@example.com", audit.events[1].Actor)
	require.Equal(t, "f-1", audit.events[1].TargetID)
}

// A failed unsuppress changed nothing, so it must not produce an audit row.
func TestUnsuppress_NotFoundIsNotAudited(t *testing.T) {
	svc, audit := auditedService(t)
	require.ErrorIs(t, svc.Unsuppress(context.Background(), "ghost", "bob@example.com"), ErrNotFound)
	require.Empty(t, audit.events)
}

func TestBulkOperations_AreAuditedPerFinding(t *testing.T) {
	svc, audit := auditedService(t)
	ctx := context.Background()

	n, err := svc.SuppressMany(ctx, []string{"f-1", "f-2", "f-3"}, "batch triage", "alice@example.com", time.Now().Add(30*day))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Len(t, audit.events, 3)

	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(audit.events[0].Details), &d))
	require.Equal(t, true, d["bulk"], "bulk rows must be distinguishable from single-finding ones")

	n, err = svc.UnsuppressMany(ctx, []string{"f-1", "f-2"}, "bob@example.com")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Len(t, audit.events, 5)
	require.Equal(t, AuditActionUnsuppress, audit.events[4].Action)
	require.Equal(t, "bob@example.com", audit.events[4].Actor)
}

func TestSuppress_MissingActorIsRecordedAsUnknown(t *testing.T) {
	svc, audit := auditedService(t)
	_, err := svc.SuppressUntil(context.Background(), "f-1", "why", "", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	require.Equal(t, AuditActorUnknown, audit.events[0].Actor)
}

// A failing audit sink must not roll back or fail a committed state change.
func TestSuppress_AuditFailureStillSucceeds(t *testing.T) {
	audit := &fakeAuditor{err: errors.New("clickhouse down")}
	svc := NewService(newFakeRepo()).WithAudit(audit)

	sup, err := svc.SuppressUntil(context.Background(), "f-1", "why", "alice@example.com", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, "f-1", sup.FindingID)
}

// A rejected suppression (no reason) never reached storage, so no audit row.
func TestSuppress_ValidationFailureIsNotAudited(t *testing.T) {
	svc, audit := auditedService(t)
	_, err := svc.SuppressUntil(context.Background(), "f-1", "", "alice@example.com", time.Now().Add(24*time.Hour))
	require.ErrorIs(t, err, ErrMissingReason)
	require.Empty(t, audit.events)
}

// A renewal moves the expiry, so the audit row keeps the expiry it replaced and
// whether the exception had already lapsed — the overwritten row is gone.
func TestReview_IsAuditedWithPreviousExpiry(t *testing.T) {
	audit := &fakeAuditor{}
	repo := newFakeRepo()
	svc := clockedService(repo).WithAudit(audit)
	ctx := context.Background()
	repo.rows["f-1"] = Suppression{FindingID: "f-1", Reason: "why", ExpiresAt: testNow.Add(-day)}

	_, err := svc.Review(ctx, "f-1", "carol@example.com", testNow.Add(90*day))
	require.NoError(t, err)

	require.Len(t, audit.events, 1)
	e := audit.events[0]
	require.Equal(t, AuditActionReview, e.Action)
	require.Equal(t, "carol@example.com", e.Actor)
	require.Equal(t, "f-1", e.TargetID)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(e.Details), &d))
	require.Equal(t, testNow.Add(90*day).Format(time.RFC3339), d["expires_at"])
	require.Equal(t, testNow.Add(-day).Format(time.RFC3339), d["previous_expires_at"])
	require.Equal(t, true, d["was_expired"])
}

// A rejected or missing renewal changed nothing, so no audit row.
func TestReview_FailureIsNotAudited(t *testing.T) {
	audit := &fakeAuditor{}
	repo := newFakeRepo()
	svc := clockedService(repo).WithAudit(audit)
	ctx := context.Background()

	_, err := svc.Review(ctx, "ghost", "carol@example.com", testNow.Add(day))
	require.ErrorIs(t, err, ErrNotFound)

	repo.rows["f-1"] = Suppression{FindingID: "f-1", ExpiresAt: testNow.Add(day)}
	_, err = svc.Review(ctx, "f-1", "carol@example.com", testNow.Add(400*day))
	require.ErrorIs(t, err, ErrExpiryTooFar)
	require.Empty(t, audit.events)
}
