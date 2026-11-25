//go:build integration

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
// The claim rules live in SQL (ClaimDecisionExecution's WHERE), so they are
// exercised against real Postgres, not a fake.
func TestPGDecisionRuns_ClaimRules(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	runs := NewPGDecisionRuns(pool)

	id := "it-decision-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM decision_executions WHERE decision_id = $1", id)
		require.NoError(t, err)
	})

	_, ok, err := runs.Get(ctx, id)
	require.NoError(t, err)
	require.False(t, ok)

	request := DecisionRun{
		DecisionID: id, FindingID: "f1", ConnectorID: "c1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"}, Plan: "stop EC2 instance i-abc in eu-west-1",
		Status: RunAwaitingSecondAdmin, RequestedBy: "alice", RequestedByID: "u-alice",
		GrantToken: "grant", GrantExpiresAt: time.Now().Add(ApprovalTTL),
	}
	got, ok, err := runs.Claim(ctx, request)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, map[string]string{ParamInstanceID: "i-abc"}, got.Params)
	require.Equal(t, "grant", got.GrantToken)

	_, ok, err = runs.Claim(ctx, request)
	require.NoError(t, err)
	require.False(t, ok, "a live request is held")

	_, ok, err = runs.ClaimApproved(ctx, id, "alice", "u-alice")
	require.NoError(t, err)
	require.False(t, ok, "the requester cannot take their own request")

	got, ok, err = runs.ClaimApproved(ctx, id, "bob", "u-bob")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, RunRunning, got.Status)
	_, ok, err = runs.ClaimApproved(ctx, id, "carol", "u-carol")
	require.NoError(t, err)
	require.False(t, ok, "one click runs it")

	require.NoError(t, runs.Finish(ctx, id, got.CreatedAt, RunFailed, "", "boom"))
	got, ok, err = runs.Get(ctx, id)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, RunFailed, got.Status)
	require.Equal(t, "boom", got.Error)
	require.Empty(t, got.GrantToken, "the spent grant is dropped")
	require.Equal(t, "bob", got.ExecutedBy)

	rerun := request
	rerun.Status, rerun.GrantToken, rerun.GrantExpiresAt = RunRunning, "", time.Time{}
	got, ok, err = runs.Claim(ctx, rerun)
	require.NoError(t, err)
	require.True(t, ok, "a failed run can be taken again")
	require.True(t, got.GrantExpiresAt.IsZero())
	require.NoError(t, runs.Finish(ctx, id, got.CreatedAt.Add(-time.Second), RunSucceeded, "stale", ""))
	again, _, err := runs.Get(ctx, id)
	require.NoError(t, err)
	require.Equal(t, RunRunning, again.Status, "a different attempt's result does not land")
	require.NoError(t, runs.Finish(ctx, id, got.CreatedAt, RunSucceeded, "stopped", ""))

	_, ok, err = runs.Claim(ctx, rerun)
	require.NoError(t, err)
	require.False(t, ok, "a fix that ran is not run again")
}

// A run left in running by a crash mid-call is never taken over on age; only
// FailStalled releases it, and only once it is older than the cut-off.
func TestPGDecisionRuns_StalledRunIsReleasedOnlyByHand(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	runs := NewPGDecisionRuns(pool)

	id := "it-stalled-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM decision_executions WHERE decision_id = $1", id)
		require.NoError(t, err)
	})
	run := DecisionRun{
		DecisionID: id, FindingID: "f1", ConnectorID: "c1", Action: ActionS3BlockPublic,
		Params: map[string]string{ParamBucketName: "b"}, Plan: "block", Status: RunRunning,
		RequestedBy: "alice", RequestedByID: "u-alice", ExecutedBy: "alice", ExecutedByID: "u-alice",
	}
	_, ok, err := runs.Claim(ctx, run)
	require.NoError(t, err)
	require.True(t, ok)

	_, ok, err = runs.FailStalled(ctx, id, RunStallAfter, "released")
	require.NoError(t, err)
	require.False(t, ok, "a run that just started is in flight, not stalled")

	_, err = pool.Exec(ctx, "UPDATE decision_executions SET updated_at = now() - interval '3 hours' WHERE decision_id = $1", id)
	require.NoError(t, err)
	_, ok, err = runs.Claim(ctx, run)
	require.NoError(t, err)
	require.False(t, ok, "a stalled run must never be re-claimed automatically — its cloud call may have happened")

	got, ok, err := runs.FailStalled(ctx, id, RunStallAfter, "released")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, RunFailed, got.Status)
	require.Equal(t, "released", got.Error)

	_, ok, err = runs.Claim(ctx, run)
	require.NoError(t, err)
	require.True(t, ok, "once released by hand, a retry may claim it")
}

// An outcome-unknown run is held like a running one, and released by hand
// without waiting out the stall window.
func TestPGDecisionRuns_OutcomeUnknownIsHeldUntilReleased(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	runs := NewPGDecisionRuns(pool)

	id := "it-unknown-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM decision_executions WHERE decision_id = $1", id)
		require.NoError(t, err)
	})
	run := DecisionRun{
		DecisionID: id, FindingID: "f1", ConnectorID: "c1", Action: ActionS3BlockPublic,
		Params: map[string]string{ParamBucketName: "b"}, Plan: "block", Status: RunRunning,
		RequestedBy: "alice", RequestedByID: "u-alice", ExecutedBy: "alice", ExecutedByID: "u-alice",
	}
	got, ok, err := runs.Claim(ctx, run)
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, runs.Finish(ctx, id, got.CreatedAt, RunOutcomeUnknown, "", "result unknown"))

	_, ok, err = runs.Claim(ctx, run)
	require.NoError(t, err)
	require.False(t, ok, "an outcome-unknown run is never re-claimed by a click")

	released, ok, err := runs.FailStalled(ctx, id, RunStallAfter, "verified")
	require.NoError(t, err)
	require.True(t, ok, "released at once: nothing is in flight")
	require.Equal(t, RunFailed, released.Status)
}

func TestCHAuditRepo_DecisionRunEventsSkipsDryRuns(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHAuditRepo(ch)

	conn := "it-conn-runev-" + time.Now().Format("150405.000000")
	decision := "it-decision-runev-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE audit_events DELETE WHERE target_id = ?", conn) })
	ts := time.Now().UTC().Truncate(time.Second)
	for i, a := range []string{AuditActionDryRun, AuditActionApprove, AuditActionExecuteIntent} {
		require.NoError(t, repo.RecordAudit(ctx, AuditEvent{TS: ts.Add(time.Duration(i) * time.Second), Actor: "a", Action: a,
			TargetType: AuditTargetConnector, TargetID: conn, Details: `{"decision_id":"` + decision + `"}`}))
	}
	events, err := repo.DecisionRunEvents(ctx, decision, ts.Add(-time.Minute))
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, AuditActionExecuteIntent, events[0].Action)
}

func TestCHAuditRepo_DecisionAudit(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHAuditRepo(ch)

	conn := "it-conn-" + time.Now().Format("150405.000000")
	decision := "it-decision-" + time.Now().Format("150405.000000")
	t.Cleanup(func() { _ = ch.Exec(ctx, "ALTER TABLE audit_events DELETE WHERE target_id = ?", conn) })
	ts := time.Now().UTC().Truncate(time.Second)
	for i, e := range []AuditEvent{
		{TS: ts, Actor: "a", Action: AuditActionDryRun, TargetType: AuditTargetConnector, TargetID: conn,
			Details: `{"decision_id":"` + decision + `"}`},
		{TS: ts.Add(time.Second), Actor: "a", Action: AuditActionExecuteIntent, TargetType: AuditTargetConnector, TargetID: conn,
			Details: `{"decision_id":"` + decision + `"}`},
		{TS: ts.Add(2 * time.Second), Actor: "a", Action: AuditActionExecute, TargetType: AuditTargetConnector, TargetID: conn,
			Details: `{"decision_id":"other"}`},
	} {
		require.NoError(t, repo.RecordAudit(ctx, e), i)
	}

	events, err := repo.DecisionAudit(ctx, decision, ts.Add(-time.Minute))
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, AuditActionDryRun, events[0].Action, "oldest first")
	require.Equal(t, AuditActionExecuteIntent, events[1].Action)
}

// Single use is enforced by the primary key, so it is exercised against real
// Postgres: the second redemption of a grant affects no row.
func TestPGGrantLedger_RedeemsOnce(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, "postgres://graph:graph@localhost:5432/graph?sslmode=disable", db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	ledger := NewPGGrantLedger(pool)

	hash := "it-grant-" + time.Now().Format("150405.000000")
	t.Cleanup(func() {
		_, err := pool.Exec(ctx, "DELETE FROM executor_grant_redemptions WHERE grant_hash = $1", hash)
		require.NoError(t, err)
	})

	ok, err := ledger.Redeem(ctx, hash, "u-bob", time.Now().Add(ApprovalTTL))
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = ledger.Redeem(ctx, hash, "u-carol", time.Now().Add(ApprovalTTL))
	require.NoError(t, err)
	require.False(t, ok, "a redeemed grant cannot be redeemed again")
}
