package govern

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AuditActionExecution is the trail row for a decision whose fix ran.
const AuditActionExecution = "governor_execution"

// RecordExecution records a decision's fix that the executor actually carried
// out (approve-and-run). Running it was the person's yes, so the decision is
// resolved as approved and leaves the queue; the trail gets a row; and the
// outcome ledger gets one success sample for the (action class, asset type)
// key — the only success the ledger ever learns, because it is a real result
// rather than an intention. Keyed by the decision, so a repeat stores one.
func (s *Service) RecordExecution(ctx context.Context, fix ExecutedFix) error {
	found, err := s.findings.ByIDs(ctx, []string{fix.FindingID})
	if err != nil {
		return fmt.Errorf("RecordExecution: %w", err)
	}
	var f finding.Finding
	if len(found) > 0 {
		f = found[0]
	}
	// The verdict snapshots the decision's current fingerprint, as Resolve
	// does, so a later material change re-surfaces the finding.
	pending, err := s.pending.ListPending(ctx, pendingScanLimit, fix.ActionClass)
	if err != nil {
		return fmt.Errorf("RecordExecution: %w", err)
	}
	fingerprint := ""
	for _, e := range pending {
		if e.FindingID == fix.FindingID {
			fingerprint = e.Fingerprint
		}
	}

	now := s.now()
	note := "fix executed from decision " + fix.DecisionID
	if err := s.verdicts.Upsert(ctx, fix.FindingID, f.CheckID+"|"+fix.ActionClass, VerdictApproved, fix.Actor, note, fingerprint); err != nil {
		return fmt.Errorf("RecordExecution: %w", err)
	}
	details, err := json.Marshal(map[string]string{"decision_id": fix.DecisionID, "action_class": fix.ActionClass})
	if err != nil {
		return fmt.Errorf("RecordExecution: %w", err)
	}
	if err := s.audit.Record(ctx, respond.AuditEvent{
		ID: fix.FindingID + ":executed:" + fix.DecisionID, TS: now, Actor: fix.Actor,
		Action: AuditActionExecution, TargetType: "finding", TargetID: fix.FindingID, Details: string(details),
	}); err != nil {
		return fmt.Errorf("RecordExecution: audit: %w", err)
	}

	if f.ResourceType == "" {
		// Same rule as Resolve: evidence filed under an empty asset type would
		// describe nothing.
		log.FromContext(ctx).Warn().Str("finding_id", fix.FindingID).
			Msg("govern: executed-fix outcome skipped — finding's asset type unknown")
		return nil
	}
	if err := s.outcomes.Record(ctx, memory.Outcome{
		ActionClass: fix.ActionClass, AssetType: f.ResourceType, Success: true,
		DecidedBy: "executor", OccurredAt: now, DedupeKey: "executed:" + fix.DecisionID,
	}); err != nil {
		return fmt.Errorf("RecordExecution: outcome: %w", err)
	}
	return nil
}
