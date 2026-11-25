package finding

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/auth"
)

// Audit actions the manual resolve writes to audit_events (target_type
// AuditTargetFinding, target_id the finding id).
const (
	AuditActionResolve        = "finding.resolve"         // details: reason, severity, score_band, must_fix_class
	AuditActionResolveRefused = "finding.resolve_refused" // an API key asked to close a finding only a person may; details: refusal
	AuditTargetFinding        = "finding"
)

// AuditRecorder writes the audit_events row of an action (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

// WithAudit records manual resolves, and their API-key refusals, in audit_events.
func (s *Service) WithAudit(a AuditRecorder) *Service { s.audit = a; return s }

// WithAgentGuard sets the rule an API-key resolve must pass (enrich.AgentRefusal,
// injected because enrich imports this package): it names why a finding may not
// be closed by a caller that may be an agent, or "" when it may. Without it
// every API-key resolve is refused.
func (s *Service) WithAgentGuard(refusal func(Finding) string) *Service { s.agent = refusal; return s }

func (s *Service) record(ctx context.Context, action, id string, details map[string]any) {
	if s.audit != nil {
		s.audit.Record(ctx, action, AuditTargetFinding, id, details)
	}
}

// ResolveManually marks one finding resolved by a person's decision, with
// ReasonManual and the person's free-text reason and identity in the
// finding's metadata (resolved_reason, resolved_by), and writes a
// finding.resolve audit row: the metadata is overwritten by a later
// resolution, the row is not.
//
// On an API key, which an agent may hold, the finding must pass the agent
// guard: a critical, must-fix, page/high-band or unscored finding is refused
// with ErrNeedsPerson (audited as finding.resolve_refused) and nothing is
// written.
func (s *Service) ResolveManually(ctx context.Context, id, reason, by string) (Finding, error) {
	f, err := s.repo.Get(ctx, id)
	if err != nil {
		return Finding{}, fmt.Errorf("ResolveManually: %w", err)
	}
	if _, viaKey := auth.APIKeyFromContext(ctx); viaKey {
		why := "urgency cannot be checked"
		if s.agent != nil {
			why = s.agent(f)
		}
		if why != "" {
			s.record(ctx, AuditActionResolveRefused, id, map[string]any{"refusal": why})
			return Finding{}, fmt.Errorf("ResolveManually: %w", &NeedsPersonError{Reason: why})
		}
	}
	if f.Metadata == nil {
		f.Metadata = map[string]string{}
	}
	f.Metadata["resolved_reason"] = reason
	f.Metadata["resolved_by"] = by
	// Resolve sets ResolvedAt on this slice's element; it is read back from
	// here rather than re-fetched, because a read right after a ClickHouse
	// write can miss it.
	toResolve := []Finding{f}
	if err := s.Resolve(ctx, toResolve, ReasonManual); err != nil {
		return Finding{}, fmt.Errorf("ResolveManually: %w", err)
	}
	s.record(ctx, AuditActionResolve, id, map[string]any{
		"reason": reason, "severity": string(f.Severity), "score_band": f.ScoreBand, "must_fix_class": f.MustFixClass,
	})
	return toResolve[0], nil
}
