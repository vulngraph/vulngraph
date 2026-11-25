package compliance

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// Connectors lists the configured connectors. connector.Service implements
// it; the rollup reads it to know which clouds SHOULD have evidence, so a
// cloud whose connector never produced an asset is in scope and unknown,
// not silently out of scope.
type Connectors interface {
	List(ctx context.Context, enabledOnly bool) ([]connector.Connector, error)
}

// collectorProviders maps a collecting connector type to the benchmark
// provider it evidences. aws_org is absent: it lists accounts and manages
// one aws connector per account, which carry the collection.
var collectorProviders = map[connector.Type]string{
	connector.TypeAWS:        "aws",
	connector.TypeGCP:        "gcp",
	connector.TypeAzure:      "azure",
	connector.TypeKubernetes: "kubernetes",
}

// cloudEvidence derives, per provider, whether the inventory can vouch for
// it. A cloud is stale when any of its enabled connectors has gone longer
// than connector.DefaultStaleAfter (24h) without a successful sync, never
// succeeded, or keeps finishing Partial (connector.PartiallyStale) — the
// health signals the Connectors page already shows. A cloud with a
// connector but no inventory, or inventory no enabled connector refreshes,
// is stale too.
func cloudEvidence(conns []connector.Connector, inventory map[string]bool, now time.Time) map[string]CloudEvidence {
	out := map[string]CloudEvidence{}
	never := map[string]bool{}
	for _, c := range conns {
		p, ok := collectorProviders[c.Type]
		if !ok || !c.Enabled {
			continue
		}
		ce := out[p]
		ce.Provider = p
		ce.Connectors++
		if c.Stale(now, connector.DefaultStaleAfter) || c.PartiallyStale(connector.DefaultPartialStreakThreshold) {
			ce.Stale = true
		}
		switch {
		case c.LastSuccessAt == nil:
			never[p] = true
		case ce.EvidenceAsOf.IsZero() || c.LastSuccessAt.Before(ce.EvidenceAsOf):
			ce.EvidenceAsOf = *c.LastSuccessAt
		}
		out[p] = ce
	}
	for p := range inventory {
		ce := out[p]
		ce.Provider = p
		ce.HasInventory = true
		out[p] = ce
	}
	for p, ce := range out {
		if never[p] {
			ce.EvidenceAsOf, ce.Stale = time.Time{}, true
		}
		if ce.Connectors == 0 || !ce.HasInventory {
			ce.Stale = true
		}
		out[p] = ce
	}
	return out
}

// sortedClouds is the clouds in provider order, for the response.
func sortedClouds(m map[string]CloudEvidence) []CloudEvidence {
	out := make([]CloudEvidence, 0, len(m))
	for _, ce := range m {
		out = append(out, ce)
	}
	slices.SortFunc(out, func(a, b CloudEvidence) int { return strings.Compare(a.Provider, b.Provider) })
	return out
}

func (s *Service) clouds(ctx context.Context, inventory map[string]bool) (map[string]CloudEvidence, error) {
	conns, err := s.conns.List(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("clouds: %w", err)
	}
	return cloudEvidence(conns, inventory, s.now()), nil
}
