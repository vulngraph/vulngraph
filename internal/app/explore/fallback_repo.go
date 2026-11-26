package explore

import "context"

// FallbackRepo prefers a primary repo (Ladybug RPC) and falls back to a secondary
// (ClickHouse BFS) when the primary errors OR when it answers empty for an
// ID-keyed lookup — so the structured graph views stay up if the Ladybug engine is
// briefly unavailable, and a node Ladybug does not hold (filterLadybugAssets pruned it)
// is answered from the authoritative store instead of reported absent. See
// emptyIsMiss in tiered_repo.go for why emptiness must be a miss here.
type FallbackRepo struct {
	primary  Repo
	fallback Repo
	obs      TierObserver // nil = no metric
}

// NewFallbackRepo wires a primary repo with a fallback. If primary is nil it
// returns the fallback directly (no wrapper overhead). observer is optional
// (pass at most one); nil or omitted disables the fall-through counter.
func NewFallbackRepo(primary, fallback Repo, observer ...TierObserver) Repo {
	if primary == nil {
		return fallback
	}
	r := &FallbackRepo{primary: primary, fallback: fallback}
	if len(observer) > 0 {
		r.obs = observer[0]
	}
	return r
}

func (r *FallbackRepo) MatchSeed(ctx context.Context, m NodeMatch, limit int) ([]Node, error) {
	if inventorySeed(m) {
		return r.fallback.MatchSeed(ctx, m, limit)
	}
	nodes, err := r.primary.MatchSeed(ctx, m, limit)
	if err != nil {
		return r.fallback.MatchSeed(ctx, m, limit)
	}
	if emptyIsMiss(len(nodes), m.IDs) {
		r.observe("seed")
		return r.fallback.MatchSeed(ctx, m, limit)
	}
	return nodes, nil
}

func (r *FallbackRepo) Neighbors(ctx context.Context, ids, edgeTypes []string, dir Direction) ([]Edge, []Node, bool, error) {
	edges, nodes, truncated, err := r.primary.Neighbors(ctx, ids, edgeTypes, dir)
	if err != nil {
		return r.fallback.Neighbors(ctx, ids, edgeTypes, dir)
	}
	if emptyIsMiss(len(edges), ids) {
		r.observe("neighbors")
		return r.fallback.Neighbors(ctx, ids, edgeTypes, dir)
	}
	return mergeInventoryNeighbors(ctx, r.fallback, ids, edgeTypes, dir, edges, nodes, truncated)
}

func (r *FallbackRepo) observe(op string) {
	if r.obs != nil {
		r.obs.ObserveGraphTierFallthrough(op)
	}
}
