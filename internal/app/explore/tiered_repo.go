package explore

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// readyer is satisfied by *graphstore.Service — set to true only after
// SyncFromSources completes. Tiers skip an unready primary rather than
// returning its empty-but-successful result during the initial sync window.
type readyer interface{ Ready() bool }

// isReady returns true when src either doesn't implement readyer (e.g. worker
// RPC, CH BFS) or explicitly reports ready.
func isReady(src any) bool {
	if r, ok := src.(readyer); ok {
		return r.Ready()
	}
	return true
}

// TierObserver counts fall-throughs a Ladybug tier caused by answering EMPTY rather
// than by failing. *obs.Metrics satisfies it (ObserveGraphTierFallthrough) —
// declared here, not imported from internal/obs, so this domain stays free of an
// infra import.
//
// This is the only externally visible difference between "the graph does not
// contain this node" and "nothing is connected to this node", so it is the metric
// that proves emptyIsMiss is actually reached in a deployment rather than
// shipped inert.
type TierObserver interface {
	ObserveGraphTierFallthrough(op string)
}

// emptyIsMiss reports whether an empty-but-successful primary answer must be
// treated as a MISS and passed down the tier chain instead of returned.
//
// Ladybug holds a filtered projection of ClickHouse: filterLadybugAssets prunes any
// asset with no retention edge and no risk score, which includes
// large numbers of dns_record and dns_zone assets (potentially a substantial
// fraction of the pre-prune graph). Asking Ladybug about one of those ids returns zero rows and a nil error,
// which is byte-identical to "this id does not exist" — and, because both tier
// wrappers switched on `err == nil` alone, that empty answer short-circuited the
// ClickHouse tier that still holds the asset AND its edges. A GET
// /api/graph/expand on a pruned record answered 200 {"nodes":[],"edges":[]}, and
// a seeded view answered 400 ErrNoSeed, for an asset the inventory lists.
//
// Zero rows is a finding, not a pass: the honest move is to ask the
// authoritative store, which answers correctly. Only ID-keyed lookups fall
// through. A selector seed (types/provider with no ids) is deliberately excluded:
// its empty answer means "no such assets in the traversable graph", which is a
// true statement about the graph, and falling through would seed views with the
// very isolated nodes the prune exists to keep out.
func emptyIsMiss(nodeCount int, ids []string) bool {
	return nodeCount == 0 && len(ids) > 0
}

// TieredRepo tries three repos in order: primary → secondary → fallback.
// With serveLadybug enabled, primary is the serve pod's own in-process Ladybug
// (zero network hop), secondary is the worker Ladybug RPC, fallback is
// ClickHouse BFS. A tier is passed over while it is not ready (the serve
// Ladybug's initial sync window on pod start), when it errors, and when an
// ID-keyed lookup comes back empty (emptyIsMiss). The serve pod rebuilds its
// Ladybug from CH on its own 30-min cadence.
type TieredRepo struct {
	primary   Repo
	secondary Repo
	fallback  Repo
	obs       TierObserver // nil = no metric
}

// NewTieredRepo wires the three tiers. observer is optional (pass at most one);
// nil or omitted disables the fall-through counter.
func NewTieredRepo(primary, secondary, fallback Repo, observer ...TierObserver) Repo {
	r := &TieredRepo{primary: primary, secondary: secondary, fallback: fallback}
	if len(observer) > 0 {
		r.obs = observer[0]
	}
	return r
}

func (r *TieredRepo) MatchSeed(ctx context.Context, m NodeMatch, limit int) ([]Node, error) {
	if inventorySeed(m) {
		return r.fallback.MatchSeed(ctx, m, limit)
	}
	empties := 0
	if isReady(r.primary) {
		if nodes, err := r.primary.MatchSeed(ctx, m, limit); err == nil {
			if !emptyIsMiss(len(nodes), m.IDs) {
				return nodes, nil
			}
			empties++
		}
	}
	if nodes, err := r.secondary.MatchSeed(ctx, m, limit); err == nil {
		if !emptyIsMiss(len(nodes), m.IDs) {
			return nodes, nil
		}
		empties++
	}
	if empties > 0 {
		r.observe("seed")
	}
	return r.fallback.MatchSeed(ctx, m, limit)
}

func (r *TieredRepo) Neighbors(ctx context.Context, ids, edgeTypes []string, dir Direction) ([]Edge, []Node, bool, error) {
	empties := 0
	if isReady(r.primary) {
		if edges, nodes, truncated, err := r.primary.Neighbors(ctx, ids, edgeTypes, dir); err == nil {
			if !emptyIsMiss(len(edges), ids) {
				return mergeInventoryNeighbors(ctx, r.fallback, ids, edgeTypes, dir, edges, nodes, truncated)
			}
			empties++
		}
	}
	if edges, nodes, truncated, err := r.secondary.Neighbors(ctx, ids, edgeTypes, dir); err == nil {
		if !emptyIsMiss(len(edges), ids) {
			return mergeInventoryNeighbors(ctx, r.fallback, ids, edgeTypes, dir, edges, nodes, truncated)
		}
		empties++
	}
	if empties > 0 {
		r.observe("neighbors")
	}
	return r.fallback.Neighbors(ctx, ids, edgeTypes, dir)
}

// observe records that a Ladybug tier answered EMPTY for an ID-keyed lookup and the
// ClickHouse tier was consulted because of it — never for an ordinary tier error,
// which is already visible as a Ladybug failure.
func (r *TieredRepo) observe(op string) {
	if r.obs != nil {
		r.obs.ObserveGraphTierFallthrough(op)
	}
}

// TieredCypherRunner tries primary, then secondary Ladybug. No ClickHouse BFS
// fallback for raw Cypher (BFS can't execute arbitrary Cypher).
type TieredCypherRunner struct {
	primary   CypherRunner
	secondary CypherRunner
}

func NewTieredCypherRunner(primary, secondary CypherRunner) CypherRunner {
	return &TieredCypherRunner{primary: primary, secondary: secondary}
}

func (r *TieredCypherRunner) RunCypher(ctx context.Context, query string, maxNodes, maxEdges int) (Result, error) {
	if isReady(r.primary) {
		res, err := r.primary.RunCypher(ctx, query, maxNodes, maxEdges)
		if err == nil || errors.Is(err, ErrInvalidQuery) {
			// A rejected query is rejected by every tier; retrying it on the
			// worker only spends its single Cypher pool.
			return res, err
		}
	}
	res, err := r.secondary.RunCypher(ctx, query, maxNodes, maxEdges)
	if err != nil {
		// Both tiers exhausted: raw Cypher has no ClickHouse fallback
		// (BFS can't execute arbitrary Cypher), so this is the point
		// where the query genuinely fails, not just a primary hiccup. Distinguish
		// it from an ordinary secondary error so it can be alerted on: an
		// unremarkable error gives the operator no signal that BOTH Ladybug tiers
		// are down at once.
		log.FromContext(ctx).Error().Err(err).
			Bool("both_ladybug_tiers_exhausted", true).
			Msg("explore: raw Cypher failed on both Ladybug tiers — no ClickHouse fallback for arbitrary Cypher")
	}
	return res, err
}

// TieredStats reports the graph-engine state of whichever Ladybug tier
// TieredCypherRunner would serve from: the primary (serve replica) once it is
// ready, otherwise the secondary (worker RPC). Reporting the primary alone would
// call the engine not ready during the replica's initial sync, while Cypher is
// in fact answered by the worker.
type TieredStats struct {
	primary   NodeStatsProvider
	secondary NodeStatsProvider
}

func NewTieredStats(primary, secondary NodeStatsProvider) *TieredStats {
	return &TieredStats{primary: primary, secondary: secondary}
}

// serving returns the tier that answers queries now, with its health.
func (t *TieredStats) serving(ctx context.Context) (NodeStatsProvider, GraphHealth, error) {
	if hl, err := t.primary.GraphHealth(ctx); err == nil && hl.Ready {
		return t.primary, hl, nil
	}
	hl, err := t.secondary.GraphHealth(ctx)
	if err != nil {
		return nil, GraphHealth{}, fmt.Errorf("TieredStats: %w", err)
	}
	return t.secondary, hl, nil
}

func (t *TieredStats) GraphHealth(ctx context.Context) (GraphHealth, error) {
	_, hl, err := t.serving(ctx)
	return hl, err
}

func (t *TieredStats) NodeCounts(ctx context.Context) (assets, roles, repos int64, err error) {
	src, _, err := t.serving(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("TieredStats.NodeCounts: %w", err)
	}
	assets, roles, repos, err = src.NodeCounts(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("TieredStats.NodeCounts: %w", err)
	}
	return assets, roles, repos, nil
}
