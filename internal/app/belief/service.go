package belief

import (
	"context"
	"fmt"
	"time"
)

// Store is the persistence seam the service depends on (CHRepo implements it).
type Store interface {
	Upsert(ctx context.Context, bs []Belief) error
	// GetByFinding returns the effective belief (see Effective).
	GetByFinding(ctx context.Context, findingID string) (Belief, error)
	// GetByProvenance returns the finding's current belief of one provenance.
	GetByProvenance(ctx context.Context, findingID, provenance string) (Belief, error)
	// CrystallizationInputs returns every corroboration-survivor adjudicator belief
	// (confirmed, never downgraded by the gate) reduced to its structural signature
	// + verdict — the anti-collapse-safe ground truth the miner crystallizes from.
	CrystallizationInputs(ctx context.Context) ([]CrystallizationInput, error)
	// AdjudicationCandidates returns the eligible finding ids to adjudicate this
	// sweep, least-recently-adjudicated first — the coverage cursor that advances
	// through the backlog instead of re-reading the same score-desc head.
	AdjudicationCandidates(ctx context.Context, minScore uint8, staleBefore time.Time, limit int) ([]string, error)
}

// Service forms and reads grounded beliefs. This slice is deterministic; the
// slice-2 adjudicator will hang off the same service.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService wires the belief store.
func NewService(store Store) *Service { return &Service{store: store, now: time.Now} }

// Form reconciles a grounded belief from the cited inputs, enforces the grounding
// contract, persists it, and returns it.
func (s *Service) Form(ctx context.Context, in SeverityInputs) (Belief, error) {
	b := Reconcile(in, s.now())
	if err := b.Validate(); err != nil {
		return Belief{}, fmt.Errorf("Form: %w", err)
	}
	if err := s.store.Upsert(ctx, []Belief{b}); err != nil {
		return Belief{}, fmt.Errorf("Form: persist: %w", err)
	}
	return b, nil
}

// Get returns the current belief for a finding.
func (s *Service) Get(ctx context.Context, findingID string) (Belief, error) {
	return s.store.GetByFinding(ctx, findingID)
}
