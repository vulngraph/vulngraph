package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// cypherProfileResolver is the exact method set internal/jobs's unexported
// cypherTargetResolver interface requires. Named here, in cmd/graph, only so
// this package can hold a properly nil-able interface-typed variable for it —
// it cannot name jobs's unexported interface directly, and a variable typed
// as a concrete *ladybugCypherTargetResolver pointer would turn "not configured"
// (nil) into a non-nil interface wrapping a nil pointer once assigned into
// jobs.Deps.CypherResolver's interface field, defeating ScanProfileWorker's
// nil check.
type cypherProfileResolver interface {
	ResolveFromCypher(ctx context.Context, query string) ([]scan.Target, error)
}

// cypherResolverAssets is the asset-lookup surface ladybugCypherTargetResolver needs.
// *asset.Service satisfies it. Narrowed to an interface so a fake can stand in
// for tests without a live ClickHouse connection.
type cypherResolverAssets interface {
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// graphReadiness reports whether the graph engine behind a CypherRunner
// actually has data. Both *graphstore.Service (local, worker.go) and
// *explore.LadybugRPCRepo (RPC, scanner.go) implement NodeCounts, so the type
// assertion in ResolveFromCypher below picks it up on either topology.
//
// This exists because an empty or mid-rebuild Ladybug answers RunCypher with a
// plain HTTP 200 and {"nodes":[]} — indistinguishable, at the RunCypher call
// site, from a query that legitimately matches nothing. Without this check a
// cold graph swap silently resolves to zero targets instead of failing with a
// clear "graph has zero nodes" error.
type graphReadiness interface {
	NodeCounts(ctx context.Context) (assets, roles, repos int64, err error)
}

// ladybugCypherTargetResolver satisfies internal/jobs's unexported
// cypherTargetResolver interface (ResolveFromCypher): it runs a profile's
// TargetQuery through whichever
// explore.CypherRunner the pod has access to — the local *graphstore.Service
// on the all-in-one worker, or an explore.LadybugRPCRepo dialed at LADYBUG_RPC_URL
// on the split-topology scanner pod (see worker.go / scanner.go) — then maps
// the returned Asset nodes back to scan targets via asset.Service.ByIDs, the
// same way ProfileService.ResolveTargets does for the no-TargetQuery path.
//
// Defined here, not in internal/jobs, because it depends on explore.CypherRunner
// and asset.Service both — cmd/graph is where the layering rules permit assembling
// dependencies from multiple app packages into one worker adapter.
type ladybugCypherTargetResolver struct {
	cypher explore.CypherRunner
	assets cypherResolverAssets
}

// targetBudgetNodes is the node budget target resolution runs a profile's
// Cypher under. It is scan.MaxTargets PLUS ONE, and the +1 is the whole point:
// repo_cypher's consumption loop marks a result truncated when it has already
// collected budget.MaxNodes rows and another row is still pending, so a budget
// of exactly MaxTargets leaves a fully-populated `LIMIT MaxTargets` preset one
// row away from being rejected as truncated. Sizing one row above the cap makes
// "a bounded preset always resolves, an unbounded query always fails" an
// invariant of the arithmetic rather than an off-by-one that happens to work.
//
// It is deliberately NOT graphstore.DefaultBudget.MaxNodes: that is a graph
// renderer budget, sized for what the explore UI can usefully draw, and its
// value colliding with scan.MaxTargets is coincidence, not design.
const targetBudgetNodes = scan.MaxTargets + 1

// ResolveFromCypher runs query and returns the scan targets it resolves to.
// An empty match (no nodes) returns an empty, non-error slice — Work() in
// internal/jobs/scan_profile.go is the one that decides whether zero targets
// is fatal for a TargetQuery profile, not this resolver.
func (r *ladybugCypherTargetResolver) ResolveFromCypher(ctx context.Context, query string) ([]scan.Target, error) {
	logger := log.FromContext(ctx)

	// Refuse to trust a cold/rebuilding/unreachable graph's answer at all —
	// see graphReadiness's doc comment.
	if gr, ok := r.cypher.(graphReadiness); ok {
		assetCount, _, _, err := gr.NodeCounts(ctx)
		if err != nil {
			return nil, fmt.Errorf("ladybugCypherTargetResolver.ResolveFromCypher: graph readiness check: %w", err)
		}
		if assetCount == 0 {
			return nil, fmt.Errorf("ladybugCypherTargetResolver.ResolveFromCypher: graph reports zero asset nodes (cold, mid-rebuild, or unreachable) — refusing to resolve TargetQuery against it")
		}
	}

	res, err := r.cypher.RunCypher(ctx, query, targetBudgetNodes, graphstore.DefaultBudget.MaxEdges)
	if err != nil {
		return nil, fmt.Errorf("ladybugCypherTargetResolver.ResolveFromCypher: %w", err)
	}

	// DefaultBudget (graphstore/domain.go) is a graph renderer budget, sized
	// for what the explore UI can usefully draw — it is not a scan-scope
	// guarantee, and its collision with scan.MaxTargets is coincidence, not
	// design. A profile whose TargetQuery matches more nodes than that gets
	// Truncated=true and an arbitrary subset of an unbounded match, which
	// would silently scan a fraction of the intended estate while still
	// reporting StatusCompleted.
	//
	// Fail loudly instead of shipping the clamped set, matching the
	// precedent in explore/dspm.go's runDSPMAggregate (Truncated → error, not
	// a degraded-but-usable partial result): a truncated target LIST is
	// unusable input to a security scan's scope decision, and silently
	// completing with it would report "scanned" for assets that were never
	// touched. The fix is "don't run with a clamped set" up front, not "let
	// the operator notice after the fact".
	if res.Truncated {
		return nil, fmt.Errorf("ladybugCypherTargetResolver.ResolveFromCypher: query hit the %d-node budget — the result is truncated and cannot be trusted as the profile's complete target set (a target query must carry LIMIT %d, as every scan.TargetPresets entry does)", targetBudgetNodes, scan.MaxTargets)
	}

	// The same rule for an engine that flagged its multi-hop results (a node
	// table above one Ladybug node group): the match may be missing targets,
	// and a scan run over it would report the absent ones as never in scope.
	if res.MultiHopMayBeIncomplete {
		return nil, errors.New("ladybugCypherTargetResolver.ResolveFromCypher: the graph engine flagged multi-hop results as possibly incomplete (a node table is above one Ladybug node group, ladybug#1341) — refusing to resolve TargetQuery against it")
	}

	ids := make([]string, 0, len(res.Nodes))
	for _, n := range res.Nodes {
		if n.ID != "" {
			ids = append(ids, n.ID)
		}
	}
	if len(ids) == 0 {
		logger.Info().Int("nodes", len(res.Nodes)).Msg("cypher target resolution funnel: query matched no nodes")
		return nil, nil
	}

	assets, err := r.assets.ByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("ladybugCypherTargetResolver.ResolveFromCypher: ByIDs: %w", err)
	}

	targets := scan.TargetsFromAssets(assets)

	// Log every stage of the nodes → ids → assets → targets funnel: ids can
	// be fewer than nodes (non-Asset nodes / blank IDs), assets fewer than
	// ids (asset.Service.ByIDs silently drops unknown ids), and targets fewer
	// than assets (targetsFor skips anything with neither Domain nor
	// PublicIP, and dedupes by URL) — any of these can turn 500 matched
	// nodes into a handful of targets with nothing else visible. Work() in
	// internal/jobs/scan_profile.go treats a full collapse to zero targets as
	// a failure; this makes a partial collapse at least observable.
	logger.Info().
		Int("nodes", len(res.Nodes)).
		Int("ids", len(ids)).
		Int("assets", len(assets)).
		Int("targets", len(targets)).
		Msg("cypher target resolution funnel")

	return targets, nil
}
