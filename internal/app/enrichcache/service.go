package enrichcache

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Repo persists enrich-cache entries and alert state. PGRepo implements it.
type Repo interface {
	Get(ctx context.Context, findingID string) (Entry, error)
	Upsert(ctx context.Context, e Entry) error
	// InvalidateFingerprints forces the next enrich of each finding past the
	// change-gate (used by post-correlate invalidation), keeping the rest of
	// its entry.
	InvalidateFingerprints(ctx context.Context, findingIDs []string) error
	// LastFullPassVersion / SetLastFullPassVersion track the LogicVersion a full
	// corpus re-enrichment last completed for (see LogicVersion).
	LastFullPassVersion(ctx context.Context) (string, error)
	SetLastFullPassVersion(ctx context.Context, v string) error
	AlertState(ctx context.Context, findingID string) (AlertState, error)
	RecordAlert(ctx context.Context, s AlertState) error
	ClearAlertStates(ctx context.Context, findingIDs []string) error
	PruneAlertStates(ctx context.Context, olderThan time.Time) (int64, error)
}

// Service is the read/write seam the enrich worker depends on.
type Service struct {
	repo Repo
}

func NewService(repo Repo) *Service { return &Service{repo: repo} }

// Get returns the cached entry for a finding, or ErrNotFound.
func (s *Service) Get(ctx context.Context, findingID string) (Entry, error) {
	e, err := s.repo.Get(ctx, findingID)
	if err != nil {
		return Entry{}, fmt.Errorf("Get: %w", err)
	}
	return e, nil
}

// Put upserts the entry (keyed by finding ID).
func (s *Service) Put(ctx context.Context, e Entry) error {
	if err := s.repo.Upsert(ctx, e); err != nil {
		return fmt.Errorf("Put: %w", err)
	}
	return nil
}

// InvalidateFingerprints forces the next enrich of each finding past the
// change-gate.
func (s *Service) InvalidateFingerprints(ctx context.Context, findingIDs []string) error {
	if err := s.repo.InvalidateFingerprints(ctx, findingIDs); err != nil {
		return fmt.Errorf("InvalidateFingerprints: %w", err)
	}
	return nil
}

// AlertState returns the urgency a finding last alerted at, or ErrNotFound.
func (s *Service) AlertState(ctx context.Context, findingID string) (AlertState, error) {
	a, err := s.repo.AlertState(ctx, findingID)
	if err != nil {
		return AlertState{}, fmt.Errorf("AlertState: %w", err)
	}
	return a, nil
}

// RecordAlert stores the urgency a finding just alerted at.
func (s *Service) RecordAlert(ctx context.Context, a AlertState) error {
	if err := s.repo.RecordAlert(ctx, a); err != nil {
		return fmt.Errorf("RecordAlert: %w", err)
	}
	return nil
}

// FindingsResolved ends the alert episode of each resolved finding: its alert
// history is forgotten, so a regression (the same deterministic id reopened by
// a later observation) alerts again, and its input fingerprint is cleared, so
// that regression is re-enriched on its first visit instead of waiting out the
// freshness backstop. finding.Service calls it after every resolve. Both writes
// are attempted; the error joins whichever failed.
func (s *Service) FindingsResolved(ctx context.Context, findingIDs []string) error {
	err := errors.Join(
		s.repo.ClearAlertStates(ctx, findingIDs),
		s.repo.InvalidateFingerprints(ctx, findingIDs),
	)
	if err != nil {
		return fmt.Errorf("FindingsResolved: %w", err)
	}
	return nil
}

// PruneAlertStates drops alert state for findings not enriched since
// olderThan — findings gone without a resolve.
func (s *Service) PruneAlertStates(ctx context.Context, olderThan time.Time) (int64, error) {
	n, err := s.repo.PruneAlertStates(ctx, olderThan)
	if err != nil {
		return 0, fmt.Errorf("PruneAlertStates: %w", err)
	}
	return n, nil
}

// FullPassNeeded reports whether the deployed LogicVersion differs from the one a
// full corpus pass last completed for — i.e. whether enrichment semantics changed
// without every finding having been reprocessed since. Fail-safe: a read error
// reports true, because re-running a full pass is recoverable and skipping one
// leaves the corpus silently serving stale verdicts.
func (s *Service) FullPassNeeded(ctx context.Context) (bool, string, error) {
	last, err := s.repo.LastFullPassVersion(ctx)
	if err != nil {
		return true, last, err
	}
	return last != LogicVersion, last, nil
}

// MarkFullPassComplete records that a full pass finished for the deployed version.
func (s *Service) MarkFullPassComplete(ctx context.Context) error {
	return s.repo.SetLastFullPassVersion(ctx, LogicVersion)
}
