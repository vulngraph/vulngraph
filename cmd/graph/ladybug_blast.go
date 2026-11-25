package main

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ladybugBlastMaxNodes caps the blast walk node budget — mirrors asset.maxNodeBudget.
const ladybugBlastMaxNodes = 500

// signalGraph is the Ladybug surface ladybugPeerFindings/ladybugGraphCtx need.
// *graphstore.Service satisfies it. Narrowed to an interface (rather than the
// concrete type) so a not-found NodeSignals response can be exercised in a unit
// test without a live Ladybug connection.
type signalGraph interface {
	Ready() bool
	TryNodeSignals(ctx context.Context, id string) (graphstore.NodeSignals, error)
}

// ─── Peer findings from ladybug signals ─────────────────────────────────────────

// ladybugPeerFindings implements enrich.ResourceFindings using ladybug node signal
// columns instead of querying ClickHouse. It synthesizes ciem_privesc and
// exposure "virtual" findings from n.PrivescCount and n.Exposed which are
// pre-computed from the finding rollup at ladybug sync time.
//
// This replaces the two identical CH peer-findings reads that AttackPaths and
// ToxicCombo each fire independently — making both sources zero-CH-query.
type ladybugPeerFindings struct {
	graph signalGraph
	// fallback is the ClickHouse-backed peer-findings reader (finding.Service),
	// used whenever Ladybug is unavailable or its pool is busy. Without it, peer
	// findings silently return nil during a rebuild/deploy window → AttackPaths
	// and ToxicCombo lose their bonus → genuinely toxic findings score LOW and
	// (because enrich swallows source errors as "degrading") that low score is
	// persisted. CH is the source of truth, so the fallback keeps scoring correct.
	fallback interface {
		List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	}
}

func (k *ladybugPeerFindings) List(ctx context.Context, f finding.Filter) ([]finding.Finding, error) {
	if f.ResourceID == "" {
		return nil, nil
	}
	// Use Ladybug signals only when the graph is ready AND a non-blocking read
	// succeeds AND the node was actually found. Any other state (not ready, pool
	// busy, lookup error, or not found — err==nil with sig.InternetHops still
	// ReachUnknown, see the IsExposedEdge comment below) falls back to ClickHouse
	// so the window between deploy and a populated graph never under-scores
	// AttackPaths / ToxicCombo, and a pruned/not-yet-loaded resource never reports
	// zero peer findings for one it actually has.
	if k.graph.Ready() {
		sig, err := k.graph.TryNodeSignals(ctx, f.ResourceID)
		if err == nil && sig.InternetHops != graphstore.ReachUnknown {
			peers := make([]finding.Finding, 0, sig.PrivescCount+1)
			for i := 0; i < sig.PrivescCount; i++ {
				peers = append(peers, finding.Finding{Type: "ciem_privesc", ResourceID: f.ResourceID})
			}
			if sig.Exposed {
				peers = append(peers, finding.Finding{Type: "exposure", ResourceID: f.ResourceID})
			}
			return peers, nil
		}
	}
	if k.fallback != nil {
		return k.fallback.List(ctx, f)
	}
	return nil, nil
}

// ─── Fingerprint context from ladybug ───────────────────────────────────────────

// ladybugGraphCtx implements jobs.GraphContextProvider using ladybug node signals
// instead of CH queries. The enrichment fingerprint fires on EVERY enrich job
// (including cache-hit no-ops), so making it ladybug-backed eliminates 2 CH reads
// per job across every finding every sweep.
type ladybugGraphCtx struct {
	graph signalGraph
	// fallbacks when ladybug is not ready or returns an error
	assetsFallback interface {
		IsExposedEdge(ctx context.Context, assetID string) (bool, error)
	}
	findingsFallback interface {
		ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
	}
}

func (g *ladybugGraphCtx) IsExposedEdge(ctx context.Context, resourceID string) (bool, error) {
	if g.graph.Ready() {
		// TryNodeSignals (non-blocking): a cache hit is free; on a miss it returns
		// ErrPoolBusy immediately when the pool is saturated rather than blocking
		// the enrich queue. Both fingerprint lookups (IsExposed + PrivescBucket)
		// share the same cached NodeSignals result. Any error → ClickHouse fallback
		// (authoritative), so a busy pool never mis-fingerprints.
		//
		// err==nil alone is not enough: nodeSignalByID only queries Asset/IamRole,
		// so a resourceID it can't find (pruned by filterLadybugAssets, not yet loaded
		// mid-rebuild, or simply not an Asset/IamRole) returns a nil error with the
		// Go zero-value NodeSignals — Exposed=false. Trusting that would fingerprint
		// a genuinely exposed resource as clean and permanently cache the false
		// negative. InternetHops==ReachUnknown is NodeSignals' own "not found /
		// couldn't determine" sentinel (see the field doc on service.go) — the same
		// check InternetHops() below already applies before trusting its result.
		sig, err := g.graph.TryNodeSignals(ctx, resourceID)
		if err == nil && sig.InternetHops != graphstore.ReachUnknown {
			return sig.Exposed, nil
		}
	}
	return g.assetsFallback.IsExposedEdge(ctx, resourceID)
}

// InternetHops reports the resource's transitive internet reachability from the
// Ladybug node signal (see graphstore reach.go). ok=false means "unknown" (graph not
// ready, pool busy, or node not found) — the reachability source contributes
// nothing rather than guess, so absence of data never promotes or demotes. There
// is deliberately no ClickHouse fallback: a per-finding reverse BFS in CH is
// exactly the cost the Ladybug signal exists to avoid.
func (g *ladybugGraphCtx) InternetHops(ctx context.Context, resourceID string) (int, bool, error) {
	if !g.graph.Ready() {
		return 0, false, nil
	}
	sig, err := g.graph.TryNodeSignals(ctx, resourceID)
	if err != nil {
		return 0, false, err
	}
	if sig.InternetHops == graphstore.ReachUnknown {
		return 0, false, nil // node not an Asset/IamRole or absent
	}
	return sig.InternetHops, true, nil
}

func (g *ladybugGraphCtx) PrivescBucket(ctx context.Context, resourceID string) (string, error) {
	if g.graph.Ready() {
		// See the not-found guard comment on IsExposedEdge above: err==nil is not
		// "found" for nodeSignalByID, and trusting a not-found PrivescCount=0
		// zero-value here would fingerprint a resource with real ciem_privesc
		// findings as having none, permanently caching the false negative.
		sig, err := g.graph.TryNodeSignals(ctx, resourceID)
		if err == nil && sig.InternetHops != graphstore.ReachUnknown {
			return enrichcache.PrivescBucketFor(sig.PrivescCount), nil
		}
	}
	// Fall back to CH: load all findings for the resource and count ciem_privesc.
	findings, err := g.findingsFallback.ByResourceIDs(ctx, []string{resourceID})
	if err != nil {
		return "0", err
	}
	count := 0
	for _, f := range findings {
		if f.Type == "ciem_privesc" {
			count++
		}
	}
	return enrichcache.PrivescBucketFor(count), nil
}

// ladybugBlastProvider implements respond.BlastRadiusProvider using the retained
// Go-side adjacency (graphstore.blastAdjacency, built at sync time from the same
// edge slice SyncFromSources already has — see graphstore/blast_adjacency.go)
// for the graph traversal, and ClickHouse for the seed asset's provenance fields
// (Tags, Metadata, DiscoveredAt, LastSeen — not carried by the retained
// adjacency either, matching what the Ladybug-backed path it replaces carried).
//
// This replaces many sequential ClickHouse graph_edges BFS queries per
// enrichment with a couple of in-memory map lookups. Falls back to
// asset.Service.BlastRadius when the retained adjacency has not been built yet
// (startup, before the first successful sync) or when the seed is not a node in
// it (pruned by filterLadybugAssets, or genuinely unknown).
//
// The dependency is a narrow interface rather than the concrete service so the
// fall-back decisions above are unit-testable. *graphstore.Service and
// *asset.Service satisfy blastGraph/blastAssets.
type ladybugBlastProvider struct {
	graph  blastGraph
	assets blastAssets
}

// blastGraph is the retained-adjacency surface ladybugBlastProvider needs.
// *graphstore.Service satisfies it.
type blastGraph interface {
	// BlastSeed resolves seedID to its asset representation, or ok=false when
	// seedID is not a loaded node (pruned, unknown, or no build has completed
	// yet) — the caller falls back to the ClickHouse BFS.
	BlastSeed(seedID string) (asset.Asset, bool)
	// TryBlastNeighbors returns the outbound edges and reached-node assets for
	// the given frontier, or ok=false when the retained adjacency has not been
	// built yet — the caller falls back to the ClickHouse BFS.
	TryBlastNeighbors(ids []string) (edges []asset.Edge, nodes []asset.Asset, ok bool)
}

// blastAssets is the ClickHouse surface ladybugBlastProvider falls back to.
// *asset.Service satisfies it.
type blastAssets interface {
	BlastRadius(ctx context.Context, seedID string, maxDepth int) (asset.BlastRadius, error)
	ResolveID(ctx context.Context, identifier string) (string, error)
}

// ResolveID canonicalizes a finding's ResourceID to an asset ID. Delegated to
// the asset service (ClickHouse): Ladybug's MatchSeed is ID-keyed, so it cannot
// resolve the name-keyed identifiers this exists to handle.
func (k *ladybugBlastProvider) ResolveID(ctx context.Context, identifier string) (string, error) {
	return k.assets.ResolveID(ctx, identifier)
}

// BlastRadius returns the connected graph for seedID using the retained
// Go-side adjacency (graphstore.blastAdjacency). Falls back to CH BFS when
// that adjacency has not been built yet (startup, before the first successful
// sync) or when a hop reports it is unavailable, avoiding long stalls that a
// busy Ladybug pool could otherwise cause. Seed asset is resolved from the
// retained adjacency (zero CH reads). It carries Provider, AccountID, Region
// but not Tags/Metadata (owner/env tags), so provenance omits team/environment
// — acceptable for the reasoning decide path, and unchanged from the Ladybug-backed
// path this replaces.
func (k *ladybugBlastProvider) BlastRadius(ctx context.Context, seedID string, maxDepth int) (asset.BlastRadius, error) {
	// A seed MISS is not "no blast radius": the retained adjacency is built
	// from the same filtered node set Ladybug was, and filterLadybugAssets prunes
	// every asset with no retention edge and no risk score — a real population
	// that can still carry open findings. Returning the walk's empty result for
	// those would hand respond.Decide a typeless one-asset blast radius with a
	// nil error, silently under-reporting exposure for a live compromise.
	// Delegate to the ClickHouse BFS instead — the authoritative answer.
	seed, ok := k.graph.BlastSeed(seedID)
	if !ok {
		log.FromContext(ctx).Debug().Str("seed_id", seedID).
			Msg("ladybug_blast: seed not in the retained adjacency (pruned, unknown, or not yet built), falling back to CH BFS")
		return k.assets.BlastRadius(ctx, seedID, maxDepth)
	}

	// Iterative expansion at depth maxDepth over the retained in-memory
	// adjacency — a couple of map lookups per hop, far cheaper than the
	// sequential per-node CH BFS it replaces.
	seen := map[string]bool{seedID: true}
	frontier := []string{seedID}
	allAssets := []asset.Asset{seed}
	var allEdges []asset.Edge

	for depth := 0; depth < maxDepth && len(frontier) > 0; depth++ {
		kEdges, kNodes, ok := k.graph.TryBlastNeighbors(frontier)
		if !ok {
			log.FromContext(ctx).Warn().
				Str("seed_id", seedID).Int("depth", depth).
				Msg("ladybug_blast: retained adjacency unavailable mid-walk, falling back to CH BFS")
			return k.assets.BlastRadius(ctx, seedID, maxDepth)
		}

		var nextFrontier []string
		for _, n := range kNodes {
			if seen[n.ID] {
				continue
			}
			seen[n.ID] = true
			nextFrontier = append(nextFrontier, n.ID)
			allAssets = append(allAssets, n)
			if len(allAssets) >= ladybugBlastMaxNodes {
				return asset.BlastRadius{
					SeedID: seedID, Assets: allAssets, Edges: allEdges,
					MaxDepth: maxDepth, Truncated: true,
				}, nil
			}
		}

		allEdges = append(allEdges, kEdges...)
		frontier = nextFrontier
	}

	return asset.BlastRadius{
		SeedID: seedID, Assets: allAssets, Edges: allEdges, MaxDepth: maxDepth,
	}, nil
}

// ─── Supply-chain exposure via ladybug ──────────────────────────────────────────

// ladybugDeployGraph implements enrich.LadybugDeployGraph using a direct ladybug Cypher
// query for the DeploysTo relationship (Repo→Asset). Neighbors() only covers
// Asset→X and IamRole→X patterns in neighborRels — Repo→Asset is excluded,
// so Neighbors({"DeploysTo"}) would always return zero results and silently
// fall back to CH. DeployedWorkloadExposed uses a typed Cypher query that
// traverses the DeploysTo rel table.
type ladybugDeployGraph struct {
	graph *graphstore.Service
}

// DeployedExposure returns whether any workload is deployed from the given repos
// and whether any such workload carries the Exposed signal (internet-facing).
func (k *ladybugDeployGraph) DeployedExposure(ctx context.Context, repoIDs []string) (anyDeployed, anyExposed bool, err error) {
	return k.graph.DeployedWorkloadExposed(ctx, repoIDs)
}
