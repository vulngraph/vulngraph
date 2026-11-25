package findingctx

import (
	"context"
	"fmt"
	"sync"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Findings fetches a finding by id. finding.Service implements it.
type Findings interface {
	Get(ctx context.Context, id string) (finding.Finding, error)
}

// ContextBuilder assembles the connected-graph context (blast/peers/exposure/
// provenance). respond.Service implements it.
type ContextBuilder interface {
	Context(ctx context.Context, f finding.Finding) (respond.ContextPack, error)
}

// Reasoner reads the cached reasoning decision. reasoncache.Service implements it.
type Reasoner interface {
	Get(ctx context.Context, findingID string) (reasoncache.Entry, error)
}

// FactorReader reads the per-source score breakdown. enrich.Service implements it.
type FactorReader interface {
	Factors(ctx context.Context, findingID string) ([]enrich.Factor, error)
}

// Suppressions reads one finding's suppression standing. suppress.Service
// implements it.
type Suppressions interface {
	State(ctx context.Context, findingID string) (suppress.State, error)
}

type Service struct {
	findings     Findings
	context      ContextBuilder
	reason       Reasoner
	factors      FactorReader
	suppressions Suppressions // nil => suppression standing unknown
}

func NewService(f Findings, c ContextBuilder, r Reasoner, fr FactorReader) *Service {
	return &Service{findings: f, context: c, reason: r, factors: fr}
}

// WithSuppressions wires the suppression read, so the detail view's
// Suppress/Unsuppress toggle reflects the finding's real standing.
func (s *Service) WithSuppressions(sp Suppressions) *Service { s.suppressions = sp; return s }

// Context assembles the full detail for one finding. The finding must exist
// (propagates finding.ErrNotFound); reasoning and factors degrade gracefully —
// a not-yet-reasoned or not-yet-enriched finding still returns its graph context.
func (s *Service) Context(ctx context.Context, id string) (FindingContext, error) {
	f, err := s.findings.Get(ctx, id)
	if err != nil {
		return FindingContext{}, fmt.Errorf("Context: %w", err)
	}

	// The three reads below are independent: context (blast + peers) is the
	// critical path, while reasoning and factors are best-effort. Run all three
	// concurrently — the critical path determines wall-clock time.
	var (
		pack    respond.ContextPack
		packErr error

		reasonEntry reasoncache.Entry
		factors     []enrich.Factor

		suppression      suppress.State
		suppressionKnown bool

		wg sync.WaitGroup
	)

	logger := log.FromContext(ctx)

	wg.Add(4)
	go func() {
		defer wg.Done()
		// Critical path: a panic here must fail the request, not crash the pod.
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", id).Msg("findingctx: context build panicked")
				packErr = fmt.Errorf("Context: panic building context: %v", r)
			}
		}()
		pack, packErr = s.context.Context(ctx, f)
	}()
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", id).Msg("findingctx: reasoning read panicked; skipped")
			}
		}()
		reasonEntry, _ = s.reason.Get(ctx, id)
	}()
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", id).Msg("findingctx: factors read panicked; skipped")
			}
		}()
		factors, _ = s.factors.Factors(ctx, id)
	}()
	go func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", id).Msg("findingctx: suppression read panicked; standing unknown")
			}
		}()
		if s.suppressions == nil {
			return
		}
		st, err := s.suppressions.State(ctx, id)
		if err != nil {
			// Unknown, not "not suppressed": the response says so (suppression_known).
			logger.Warn().Err(err).Str("finding_id", id).Msg("findingctx: suppression read failed; standing unknown")
			return
		}
		suppression, suppressionKnown = st, true
	}()
	wg.Wait()

	if packErr != nil {
		return FindingContext{}, fmt.Errorf("Context: %w", packErr)
	}

	out := FindingContext{
		ContextPack: pack, Factors: factors, Narrative: buildNarrative(pack),
		Suppression: suppression, SuppressionKnown: suppressionKnown,
	}
	if reasonEntry.ActionClass != "" {
		out.Reasoning = &Reasoning{
			ActionClass:      reasonEntry.ActionClass,
			Summary:          reasonEntry.Summary,
			Rationale:        reasonEntry.Rationale,
			Outcome:          reasonEntry.Outcome,
			ConfidenceBand:   reasonEntry.ConfidenceBand,
			ConfidenceScore:  reasonEntry.ConfidenceScore,
			EffectiveN:       reasonEntry.EffectiveN,
			SampleCount:      reasonEntry.SampleCount,
			BlastRadius:      reasonEntry.BlastRadius,
			BlastRadiusKnown: reasonEntry.BlastRadiusKnown,
			CoVeConcerns:     reasonEntry.CoVeConcerns,
			// Recompute the safety band live from the pack's current impact + the
			// cached action class, so the band the detail view shows always matches
			// the dependents/usage evidence beside it (the cached band can lag a
			// graph change until the next reasoning sweep). Falls back to the cached
			// band only if the finding has no live impact context.
			SafetyBand: liveSafetyBand(reasonEntry, pack),
			DecidedAt:  reasonEntry.DecidedAt,
		}
	}
	return out, nil
}

// liveSafetyBand recomputes the safety band from the finding's current impact and
// the cached action class, keeping the displayed band consistent with the live
// dependents/usage evidence rendered next to it.
func liveSafetyBand(e reasoncache.Entry, pack respond.ContextPack) string {
	return respond.SafetyBandFor(respond.ActionClass(e.ActionClass), pack)
}
