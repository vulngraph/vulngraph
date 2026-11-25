package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// A decision run left in `running` by a pod that died mid-call is never taken
// over automatically: its cloud change may already have happened, and a retry
// would run it twice. An admin releases it by hand, and when the audit trail
// says the call may have gone out (an intent row with no result, or a trail
// that cannot be read) they must attest that they checked the resource first.

// RunStallAfter is how long a run must have been running before an admin may
// release it — long past ExecutionTimeout, so a release never races a call
// that is still in flight.
const RunStallAfter = 15 * time.Minute

// runEvidence is what the audit trail says about a stalled run's cloud call.
type runEvidence string

const (
	// evidenceNoIntent: no intent row, so the call never went out — the
	// intent row is written before every cloud call or the call is refused.
	evidenceNoIntent runEvidence = "no_intent"
	// evidenceIntentWithoutResult: the call may have gone out and its result
	// was never recorded — the double-run case.
	evidenceIntentWithoutResult runEvidence = "intent_without_result"
	// evidenceResultRecorded: the call's result is in the trail but the run's
	// state was never updated.
	evidenceResultRecorded runEvidence = "result_recorded"
	// evidenceUnknown: the trail could not be read.
	evidenceUnknown runEvidence = "unknown"
)

// stallSkew widens the trail read below the run's creation, so a clock
// difference between Postgres and this process cannot hide the run's intent
// row. A previous attempt's rows caught by it only ever read as "may have
// run", the side that asks for verification.
const stallSkew = time.Minute

// MarkStalledRunFailed releases a decision run that has been running for
// longer than RunStallAfter: it is marked failed (so a later click may retry
// it) and the release is audited. verified is the admin's attestation that
// they checked the resource; it is required unless the trail proves the cloud
// call never went out.
func (s *Service) MarkStalledRunFailed(ctx context.Context, decisionID string, verified bool, note string) (DecisionRun, error) {
	me, err := requirePerson(ctx)
	if err != nil {
		return DecisionRun{}, fmt.Errorf("%w: decision %s", err, decisionID)
	}
	d := s.decisions
	if d == nil {
		return DecisionRun{}, ErrDecisionsUnwired
	}
	run, ok, err := d.Runs.Get(ctx, decisionID)
	if err != nil {
		return DecisionRun{}, fmt.Errorf("MarkStalledRunFailed: %w", err)
	}
	if !ok || (run.Status != RunRunning && run.Status != RunOutcomeUnknown) {
		return DecisionRun{}, fmt.Errorf("%w: it is not running", ErrRunNotStalled)
	}
	// An outcome-unknown run has already ended (cut off), so there is nothing
	// in flight to wait out; a running one may still be mid-call.
	staleBefore := s.now().Add(-RunStallAfter)
	if run.Status == RunRunning && !run.UpdatedAt.Before(staleBefore) {
		return DecisionRun{}, fmt.Errorf("%w: it started %s ago and may still be in flight; it can be released after %s",
			ErrRunNotStalled, s.now().Sub(run.UpdatedAt).Truncate(time.Second), RunStallAfter)
	}
	evidence := s.stalledRunEvidence(ctx, run)
	if run.Status == RunOutcomeUnknown {
		// The intent row was written by definition; whatever else the trail
		// shows, only the admin's check settles what happened.
		evidence = evidenceIntentWithoutResult
	}
	if evidence != evidenceNoIntent && !verified {
		return DecisionRun{}, fmt.Errorf("%w: the audit trail says %s for %q; check the resource, then release it with verified set",
			ErrCloudStateUnverified, evidence, run.Plan)
	}
	errText := fmt.Sprintf("marked failed by %s after the run stalled (audit trail: %s)", me.Name, evidence)
	if note != "" {
		errText += ": " + note
	}
	got, ok, err := d.Runs.FailStalled(ctx, decisionID, RunStallAfter, errText)
	if err != nil {
		return DecisionRun{}, fmt.Errorf("MarkStalledRunFailed: %w", err)
	}
	if !ok {
		return DecisionRun{}, fmt.Errorf("%w: it finished or changed while being released", ErrRunNotStalled)
	}
	s.recordRelease(ctx, got, evidence, verified, note)
	return got, nil
}

// stalledRunEvidence reads the run's trail: whether its latest intent row has
// a result after it.
func (s *Service) stalledRunEvidence(ctx context.Context, run DecisionRun) runEvidence {
	events, err := s.decisions.Audit.DecisionRunEvents(ctx, run.DecisionID, run.CreatedAt.Add(-stallSkew))
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("decision_id", run.DecisionID).
			Msg("executor: stalled run's audit trail unavailable; release needs verification")
		return evidenceUnknown
	}
	if len(events) >= DecisionRunEventsLimit {
		// The page may have cut off the rows that matter.
		return evidenceUnknown
	}
	evidence := evidenceNoIntent
	for _, e := range events {
		switch e.Action {
		case AuditActionExecuteIntent:
			evidence = evidenceIntentWithoutResult
		case AuditActionExecute, AuditActionExecuteFailed:
			if evidence == evidenceIntentWithoutResult {
				evidence = evidenceResultRecorded
			}
		}
	}
	return evidence
}

// recordRelease puts the release, and what the admin attested, in the same
// trail as the run it released.
func (s *Service) recordRelease(ctx context.Context, run DecisionRun, evidence runEvidence, verified bool, note string) {
	if s.audit == nil {
		return
	}
	event := s.auditEvent(ctx, AuditActionRunMarkedFailed, run.ConnectorID, map[string]any{
		"decision_id": run.DecisionID,
		"action":      string(run.Action),
		"plan":        run.Plan,
		"evidence":    string(evidence),
		"verified":    verified,
		"note":        note,
	})
	if err := s.audit.RecordAudit(ctx, event); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("decision_id", run.DecisionID).
			Msg("executor: AUDIT WRITE FAILED — a stalled run was released with no audit row")
	}
}
