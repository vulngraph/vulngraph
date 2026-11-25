package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// insertAudit appends one row to the shared insert-only audit trail. Same table
// and column order as respond's decision trail — one table, one shape, so
// "everything a human or agent did" is a single query.
const insertAudit = `INSERT INTO audit_events (id, ts, actor, action, target_type, target_id, details)`

const auditWriteTimeout = 5 * time.Second

// CHAuditRepo persists executor audit events in ClickHouse.
type CHAuditRepo struct {
	ch *db.CH
}

func NewCHAuditRepo(ch *db.CH) *CHAuditRepo { return &CHAuditRepo{ch: ch} }

// RecordAudit appends one audit event. audit_events is a plain MergeTree, so
// this is an append — nothing here ever overwrites an earlier row.
func (r *CHAuditRepo) RecordAudit(ctx context.Context, e AuditEvent) error {
	id := dbutil.DeterministicID(e.TargetID, e.Action, e.Actor, e.TS.Format(time.RFC3339Nano))

	// Bounded independently of the caller: the cloud mutation has already
	// happened by the time we get here, so a slow ClickHouse must not hold the
	// request open, and a cancelled request must not lose the audit row.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()

	err := r.ch.Batch(writeCtx, insertAudit, func(b driver.Batch) error {
		return b.Append(id, e.TS, e.Actor, e.Action, e.TargetType, e.TargetID, e.Details)
	})
	if err != nil {
		return fmt.Errorf("RecordAudit: %w", err)
	}
	return nil
}

// selectDecisionAudit fetches the executor rows one decision's run wrote,
// oldest first. The ts lower bound keeps it a range read on the (ts, id)
// sort key. executor.refused rows are left out: any admin key can write them
// at will, and under the oldest-first LIMIT they would push a later run's
// rows out of the panel. They are kept in audit_events.
const selectDecisionAudit = `
	SELECT ts, actor, action, target_type, target_id, details
	FROM audit_events
	WHERE ts >= ?
	  AND action IN ('executor.dry_run', 'executor.approve', 'executor.execute_intent',
	                 'executor.execute', 'executor.execute_failed', 'executor.execute_outcome_unknown',
	                 'executor.run_marked_failed')
	  AND JSONExtractString(details, 'decision_id') = ?
	ORDER BY ts, id
	LIMIT 100`

// selectDecisionRunEvents fetches only the intent and result rows of one
// decision's runs, oldest first — the stalled-run check's evidence. Dry runs
// and approvals are filtered out in the query so they cannot crowd the
// intent row out of the LIMIT.
const selectDecisionRunEvents = `
	SELECT ts, actor, action, target_type, target_id, details
	FROM audit_events
	WHERE ts >= ?
	  AND action IN ('executor.execute_intent', 'executor.execute', 'executor.execute_failed',
	                 'executor.execute_outcome_unknown')
	  AND JSONExtractString(details, 'decision_id') = ?
	ORDER BY ts, id
	LIMIT ?`

const auditReadTimeout = 10 * time.Second

// DecisionAudit returns the executor audit rows tagged with decisionID since
// the given time.
func (r *CHAuditRepo) DecisionAudit(ctx context.Context, decisionID string, since time.Time) ([]AuditEvent, error) {
	out, err := r.selectEvents(ctx, selectDecisionAudit, since.UTC(), decisionID)
	if err != nil {
		return nil, fmt.Errorf("DecisionAudit: %w", err)
	}
	return out, nil
}

func (r *CHAuditRepo) selectEvents(ctx context.Context, query string, args ...any) ([]AuditEvent, error) {
	qCtx, cancel := context.WithTimeout(ctx, auditReadTimeout)
	defer cancel()
	var out []AuditEvent
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var e AuditEvent
			if err := rows.Scan(&e.TS, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &e.Details); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, e)
		}
		return rows.Err()
	}, query, args...)
	return out, err
}

// DecisionRunEvents returns the intent and result rows tagged with
// decisionID since the given time, at most DecisionRunEventsLimit.
func (r *CHAuditRepo) DecisionRunEvents(ctx context.Context, decisionID string, since time.Time) ([]AuditEvent, error) {
	out, err := r.selectEvents(ctx, selectDecisionRunEvents, since.UTC(), decisionID, DecisionRunEventsLimit)
	if err != nil {
		return nil, fmt.Errorf("DecisionRunEvents: %w", err)
	}
	return out, nil
}

// PGDecisionRuns stores each decision's execution state in Postgres
// (decision_executions).
type PGDecisionRuns struct {
	q *sqlcgen.Queries
}

func NewPGDecisionRuns(pool *pgxpool.Pool) *PGDecisionRuns {
	return &PGDecisionRuns{q: sqlcgen.New(pool)}
}

// Get returns the decision's run; ok is false when it has none.
func (r *PGDecisionRuns) Get(ctx context.Context, decisionID string) (DecisionRun, bool, error) {
	row, err := r.q.GetDecisionExecution(ctx, decisionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return DecisionRun{}, false, nil
	}
	if err != nil {
		return DecisionRun{}, false, fmt.Errorf("Get: %w", err)
	}
	run, err := decisionRunFromRow(row)
	if err != nil {
		return DecisionRun{}, false, fmt.Errorf("Get: %w", err)
	}
	return run, true, nil
}

// Claim inserts the run, or takes over one that failed or whose grant expired.
// ok is false when another click holds the decision, it is running (however
// long ago it started — see FailStalled), or its fix already ran.
func (r *PGDecisionRuns) Claim(ctx context.Context, run DecisionRun) (DecisionRun, bool, error) {
	params, err := json.Marshal(run.Params)
	if err != nil {
		return DecisionRun{}, false, fmt.Errorf("Claim: %w", err)
	}
	arg := sqlcgen.ClaimDecisionExecutionParams{
		DecisionID: run.DecisionID, FindingID: run.FindingID, ConnectorID: run.ConnectorID,
		Action: string(run.Action), Params: params, Plan: run.Plan, Status: string(run.Status),
		RequestedBy: run.RequestedBy, RequestedByID: run.RequestedByID, GrantToken: run.GrantToken,
		ExecutedBy: run.ExecutedBy, ExecutedByID: run.ExecutedByID,
	}
	if !run.GrantExpiresAt.IsZero() {
		arg.GrantExpiresAt = pgtype.Timestamptz{Time: run.GrantExpiresAt, Valid: true}
	}
	row, err := r.q.ClaimDecisionExecution(ctx, arg)
	return claimed(row, err)
}

// ClaimApproved takes a live second-admin request for an admin other than
// the one who made it. ok is false when there is none to take.
func (r *PGDecisionRuns) ClaimApproved(ctx context.Context, decisionID, executedBy, executedByID string) (DecisionRun, bool, error) {
	row, err := r.q.ClaimApprovedDecisionExecution(ctx, sqlcgen.ClaimApprovedDecisionExecutionParams{
		DecisionID: decisionID, ExecutedBy: executedBy, ExecutedByID: executedByID,
	})
	return claimed(row, err)
}

// Finish records a running claim's result and drops its grant.
func (r *PGDecisionRuns) Finish(ctx context.Context, decisionID string, claimedAt time.Time, status RunStatus, detail, errText string) error {
	err := r.q.FinishDecisionExecution(ctx, sqlcgen.FinishDecisionExecutionParams{
		DecisionID: decisionID, Status: string(status), Detail: detail, Error: errText, ClaimedAt: claimedAt,
	})
	if err != nil {
		return fmt.Errorf("Finish: %w", err)
	}
	return nil
}

// FailStalled marks a run failed if it is still running and has not been
// updated for staleAfter, on the database clock. ok is false when it
// finished or moved in between.
func (r *PGDecisionRuns) FailStalled(ctx context.Context, decisionID string, staleAfter time.Duration, errText string) (DecisionRun, bool, error) {
	row, err := r.q.FailStalledDecisionExecution(ctx, sqlcgen.FailStalledDecisionExecutionParams{
		DecisionID: decisionID, Error: errText, StaleAfterSeconds: staleAfter.Seconds(),
	})
	return claimed(row, err)
}

func claimed(row sqlcgen.DecisionExecution, err error) (DecisionRun, bool, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return DecisionRun{}, false, nil
	}
	if err != nil {
		return DecisionRun{}, false, fmt.Errorf("claim: %w", err)
	}
	run, err := decisionRunFromRow(row)
	if err != nil {
		return DecisionRun{}, false, fmt.Errorf("claim: %w", err)
	}
	return run, true, nil
}

func decisionRunFromRow(row sqlcgen.DecisionExecution) (DecisionRun, error) {
	var params map[string]string
	if err := json.Unmarshal(row.Params, &params); err != nil {
		return DecisionRun{}, fmt.Errorf("decode params: %w", err)
	}
	run := DecisionRun{
		DecisionID: row.DecisionID, FindingID: row.FindingID, ConnectorID: row.ConnectorID,
		Action: Action(row.Action), Params: params, Plan: row.Plan, Status: RunStatus(row.Status),
		RequestedBy: row.RequestedBy, RequestedByID: row.RequestedByID, GrantToken: row.GrantToken,
		ExecutedBy: row.ExecutedBy, ExecutedByID: row.ExecutedByID,
		Detail: row.Detail, Error: row.Error, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	if row.GrantExpiresAt.Valid {
		run.GrantExpiresAt = row.GrantExpiresAt.Time
	}
	return run, nil
}

// PGGrantLedger records approval-grant redemptions in Postgres, shared by every
// serve replica.
type PGGrantLedger struct {
	q *sqlcgen.Queries
}

func NewPGGrantLedger(pool *pgxpool.Pool) *PGGrantLedger {
	return &PGGrantLedger{q: sqlcgen.New(pool)}
}

// Redeem inserts the grant's redemption; ok is false when it was already
// there. Redemptions of grants that expired a day ago are purged first — they
// guard nothing, an expired grant is refused on its expiry — and a failed purge
// only delays that cleanup, so it is logged rather than refusing the execution.
func (r *PGGrantLedger) Redeem(ctx context.Context, grantHash, byID string, expiresAt time.Time) (bool, error) {
	if err := r.q.PurgeExpiredExecutorGrants(ctx, time.Now().Add(-24*time.Hour)); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("executor: purging expired grant redemptions failed")
	}
	n, err := r.q.RedeemExecutorGrant(ctx, sqlcgen.RedeemExecutorGrantParams{
		GrantHash: grantHash, RedeemedByID: byID, ExpiresAt: expiresAt,
	})
	if err != nil {
		return false, fmt.Errorf("Redeem: %w", err)
	}
	return n == 1, nil
}
