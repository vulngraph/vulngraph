package policy

import (
	"context"
	"fmt"
)

// Store is the repository interface the Service depends on.
type Store interface {
	Get(ctx context.Context) (Policy, error)
	// Update stores p and returns the threshold and rules it replaced.
	Update(ctx context.Context, p Policy) (Policy, error)
}

// AuditRecorder writes the audit_events row of an admin action that has taken
// effect, and reports its own write failures (audit.Service).
type AuditRecorder interface {
	Record(ctx context.Context, action, targetType, targetID string, details map[string]any)
}

// Service provides business logic for the remediation policy.
type Service struct {
	store Store
	audit AuditRecorder // nil: no audit rows (tests)
}

// NewService returns a Service backed by store.
func NewService(store Store) *Service { return &Service{store: store} }

// WithAudit records every policy change, before and after, in audit_events.
func (s *Service) WithAudit(a AuditRecorder) *Service {
	s.audit = a
	return s
}

// Get returns the current remediation policy.
func (s *Service) Get(ctx context.Context) (Policy, error) {
	p, err := s.store.Get(ctx)
	if err != nil {
		return Policy{}, fmt.Errorf("policy.Get: %w", err)
	}
	return p, nil
}

// Update validates and persists the given policy.
func (s *Service) Update(ctx context.Context, p Policy) error {
	if err := validate(p); err != nil {
		return err
	}
	before, err := s.store.Update(ctx, p)
	if err != nil {
		return fmt.Errorf("policy.Update: %w", err)
	}
	if s.audit != nil {
		s.audit.Record(ctx, AuditActionUpdate, AuditTargetPolicy, "default", map[string]any{
			"before": auditView(before), "after": auditView(p),
		})
	}
	return nil
}

func auditView(p Policy) map[string]any {
	rules := p.ActionRules
	if rules == nil {
		rules = map[string]ActionMode{}
	}
	return map[string]any{"suggest_threshold": p.SuggestThreshold, "action_rules": rules}
}

func validate(p Policy) error {
	if p.SuggestThreshold < 0 || p.SuggestThreshold > 100 {
		return ErrBadThreshold
	}
	for class, mode := range p.ActionRules {
		if !ValidMode(mode) {
			return fmt.Errorf("%w: %s is %q", ErrBadMode, class, mode)
		}
	}
	return nil
}
