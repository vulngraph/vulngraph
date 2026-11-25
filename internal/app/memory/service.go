package memory

import (
	"context"
	"fmt"
	"math"
	"time"
)

// Decay and banding parameters.
const (
	// halfLife is how long until an outcome's weight halves — recent outcomes
	// dominate, behaviour from a quarter ago barely counts.
	halfLife = 30 * 24 * time.Hour
	// MinEffectiveN is the minimum decay-weighted evidence required before we
	// trust a confidence at all; below it we escalate (safe harbor). Exported so
	// consumers (govern's teaching-value queue ordering) can measure the gap to
	// this threshold without duplicating the constant.
	MinEffectiveN = 3.0
	highThreshold = 0.8
	medThreshold  = 0.5
)

// lambda is the decay rate derived from the half-life: w = e^(-lambda*age).
var lambda = math.Ln2 / halfLife.Hours()

// Repo persists and retrieves outcomes. PGRepo implements it.
type Repo interface {
	Record(ctx context.Context, o Outcome) error
	Recent(ctx context.Context, actionClass, assetType string, limit int) ([]Outcome, error)
	// RecentByAsset returns outcomes for an asset type across all action classes —
	// the "how have we historically fared on this kind of asset" signal used by
	// enrichment, where no action class is known yet.
	RecentByAsset(ctx context.Context, assetType string, limit int) ([]Outcome, error)
}

const recentLimit = 500

type Service struct {
	repo Repo
	now  func() time.Time
}

// Option configures a Service.
type Option func(*Service)

// WithClock overrides the decay clock. Production leaves this at time.Now;
// tests inject a fixed clock so the age math in computeConfidence (now -
// OccurredAt) is pinned instead of drifting by real elapsed time between
// calls.
func WithClock(now func() time.Time) Option { return func(s *Service) { s.now = now } }

func NewService(repo Repo, opts ...Option) *Service {
	s := &Service{repo: repo, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Record stores the outcome of an executed action.
func (s *Service) Record(ctx context.Context, o Outcome) error {
	if o.OccurredAt.IsZero() {
		o.OccurredAt = s.now()
	}
	if err := s.repo.Record(ctx, o); err != nil {
		return fmt.Errorf("Record: %w", err)
	}
	return nil
}

// Confidence computes the assessment for an (action class, asset type).
func (s *Service) Confidence(ctx context.Context, actionClass, assetType string) (Confidence, error) {
	outcomes, err := s.repo.Recent(ctx, actionClass, assetType, recentLimit)
	if err != nil {
		return Confidence{}, fmt.Errorf("Confidence: %w", err)
	}
	return computeConfidence(outcomes, s.now()), nil
}

// AssetConfidence computes the assessment for an asset type across all
// action classes — used by enrichment scoring, which runs before any action
// class is chosen. Same decay math, broader window.
func (s *Service) AssetConfidence(ctx context.Context, assetType string) (Confidence, error) {
	outcomes, err := s.repo.RecentByAsset(ctx, assetType, recentLimit)
	if err != nil {
		return Confidence{}, fmt.Errorf("AssetConfidence: %w", err)
	}
	return computeConfidence(outcomes, s.now()), nil
}

// computeConfidence is the pure decay math, split out so it is exhaustively
// table-testable without a database.
func computeConfidence(outcomes []Outcome, now time.Time) Confidence {
	var weightedSuccess, totalWeight float64
	for _, o := range outcomes {
		ageHours := now.Sub(o.OccurredAt).Hours()
		if ageHours < 0 {
			ageHours = 0
		}
		w := math.Exp(-lambda * ageHours)
		totalWeight += w
		if o.Success {
			weightedSuccess += w
		}
	}

	c := Confidence{EffectiveN: totalWeight, SampleCount: len(outcomes)}
	if totalWeight < MinEffectiveN {
		c.Band = BandInsufficient
		return c
	}
	c.Score = weightedSuccess / totalWeight
	switch {
	case c.Score >= highThreshold:
		c.Band = BandHigh
	case c.Score >= medThreshold:
		c.Band = BandMedium
	default:
		c.Band = BandLow
	}
	return c
}
