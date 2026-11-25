package enrich

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Source is one intelligence input to a finding's enriched score, and the single
// extension point of this package. A new capability (identity, drift, attack
// paths, supply chain, threat intel, …) plugs in by implementing Source and
// being added to the slice wired in cmd/graph/worker.go — the scorer and the
// service never change. Each Source owns its own weighting and caps; the scorer
// only aggregates Factors.
type Source interface {
	// Name identifies the source in the score breakdown.
	Name() string
	// Evaluate returns this source's contribution for a finding. The bool reports
	// whether the source applied (false = not relevant, contribute nothing). A
	// non-nil error means the source was unavailable for this finding; the service
	// degrades gracefully, scores without it, and reports it in
	// Score.Unmeasured. A source may pair an error with applied=true to keep a
	// fail-safe factor (a ceiling it would otherwise lose) — the factor is kept
	// and the source is still reported unmeasured.
	Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error)
}
