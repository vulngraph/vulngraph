package enrich

import (
	"context"
	"errors"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// OwnerResolver resolves an asset's single owner (asset.ResolveOwnership's
// tiers). asset.Service implements it.
type OwnerResolver interface {
	ResolveOwner(ctx context.Context, a asset.Asset, tagKeys []string) (asset.Ownership, error)
}

// WithOwnerResolver enables stamping each finding's owner (ADR 089). tagKeys is
// the operator's owner-tag list (asset.OwnerTagKeys); nil means the defaults.
// Without a resolver the owner stays unresolved (OwnerSource ""), which routing
// treats as unowned — never silently as some team's.
func WithOwnerResolver(r OwnerResolver, tagKeys []string) Option {
	return func(s *Service) { s.owners, s.ownerTagKeys = r, tagKeys }
}

// seedRead is the outcome of the single seed-asset fetch Enrich shares between
// its assessments: whether it ran at all, and how it failed if it did.
type seedRead struct {
	asset   asset.Asset
	fetched bool
	err     error
}

// usable reports whether the read is evidence about the asset: it ran and
// either found the asset or established that it is not in inventory.
func (r seedRead) usable() bool {
	return r.fetched && (r.err == nil || errors.Is(r.err, asset.ErrNotFound))
}

// routingOf resolves the finding's owner and environment. Fail-soft in the
// direction routing can tolerate: anything unmeasured comes back as the zero
// value (owner unresolved, environment ""), which the store and the API keep
// distinct from a resolved "none"/"unknown". A failed graph read is never
// reported as "unowned".
func (s *Service) routingOf(ctx context.Context, f finding.Finding, seed seedRead, score uint8) (asset.Ownership, string) {
	// Runner routing costs several graph reads per finding, so it runs only for a
	// package finding scored into the high band or above — the only ones that
	// can alert. Below that the purl keeps its own (unowned, unknown) routing.
	if isSupplyChainPackage(f) && s.runners != nil && s.owners != nil && score >= ThresholdHigh {
		o, env, err := s.packageRouting(ctx, f)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("finding_id", f.ID).
				Msg("enrich: package runner routing failed; owner and environment left unresolved")
			return asset.Ownership{}, ""
		}
		return o, env
	}
	env := ""
	if seed.usable() {
		// A resource absent from inventory classifies as unknown: no tag, no
		// namespace, no account says otherwise — a real answer, not a gap.
		env = string(asset.ClassifyEnvironment(seed.asset).Env)
	}
	if s.owners == nil || !seed.usable() {
		return asset.Ownership{}, env
	}
	if f.ResourceID == "" {
		return asset.Ownership{Source: asset.OwnerSourceNone}, env
	}
	a := seed.asset
	if a.ID == "" {
		// Not in inventory yet: its tags are unknown, but defined_in edges are
		// keyed by resource id and may already say who declares it.
		a = asset.Asset{ID: f.ResourceID}
	}
	o, err := s.owners.ResolveOwner(ctx, a, s.ownerTagKeys)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("finding_id", f.ID).
			Msg("enrich: owner resolution failed; owner left unresolved")
		return asset.Ownership{}, env
	}
	return o, env
}
