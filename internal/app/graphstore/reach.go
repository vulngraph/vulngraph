package graphstore

import (
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// maxReachDepth bounds the attacker-movement BFS. A resource reachable only via a
// longer chain is genuinely lower-urgency, so the cap is a correctness choice as
// much as a performance one (keeps the whole pass O(V+E) over the critical edges).
// Declared in graphschema (declare once, derive everywhere) so a display label
// elsewhere can derive its text from the same number — see graphschema.MaxReachDepth.
const maxReachDepth = graphschema.MaxReachDepth

// NewNodeSignals returns a NodeSignals with reachability defaulted to
// ReachUnknown rather than the Go zero value 0 (which means "directly
// internet-exposed"). Every construction site outside the authoritative reach
// overlay must use this — a plain NodeSignals{} literal would silently claim
// 0-hop internet exposure. Only prewarmSignalCache sets a real hop count.
func NewNodeSignals() NodeSignals {
	return NodeSignals{InternetHops: ReachUnknown}
}

// clampInternetHops collapses any out-of-domain hop count to ReachUnknown
// (fail-open). Valid values are the two sentinels and 0..maxReachHops; anything
// else (a corrupt map, an unexpected external value) must never be trusted as a
// concrete reach distance. Returns the clamped value and whether it was invalid.
func clampInternetHops(h int) (int, bool) {
	if h == ReachUnknown || h == ReachNone || (h >= 0 && h <= maxReachHops) {
		return h, false
	}
	return ReachUnknown, true
}

// IdentityZeroHop returns the number of exposed_to_internet edges dropped in the
// last build because their source was an identity (INV-1): an identity can never
// be a direct internet node. Must stay 0 in steady state; wired to an obs gauge
// that alarms on nonzero.
func (s *Service) IdentityZeroHop() int64 { return s.identityZeroHop.Load() }

// ReachabilityStats reports, over the pre-warmed node-signal cache, how many
// resources carry a concrete internet-reach distance (hops 0..maxReachHops)
// versus the total cached. Feeds the reachability_rate obs gauge — a spike
// toward 1.0 is the leading symptom of every resource being misclassified as
// internet-reachable. Lock-free: a single pass over the in-memory sync.Map.
func (s *Service) ReachabilityStats() (reachable, total int64) {
	s.nodeSignalsCache.Range(func(_, v any) bool {
		ns, ok := v.(NodeSignals)
		if !ok {
			return true
		}
		total++
		if ns.InternetHops >= 0 && ns.InternetHops <= maxReachHops {
			reachable++
		}
		return true
	})
	return reachable, total
}

// reachEdgeTypes are the directed attacker-movement edges an attacker traverses
// AFTER compromising an internet-exposed node — each points src→dst in the
// direction of progress (a workload executes_as a role; a role can_assume another;
// an asset accesses_secret). The k8s exposure chain joins this set the same way:
// internet→ingress(0)→service(1, via routes_to)→pod(2, via targets).
//
// Deliberately EXCLUDED:
//   - federated_access: an IdP/human→role edge, reachable via the federated
//     identity, not from the raw internet — excluding it keeps an SSO-only admin
//     role correctly "not internet-reachable".
//   - sg_allows_from: SG→SG, wrong granularity/direction for asset-level movement.
//   - topology edges (in_subnet/runs_in/dns_points_to): adjacency, not movement.
var reachEdgeTypes = graphschema.ReachEdgeTypes()

// inheritEdgeTypes are containment edges (pod→container→image→package) across
// which reachability is INHERITED at the same hop count instead of costing a hop.
// See graphschema.InheritEdgeTypes for why containment is neither movement nor
// plain adjacency — without it, image CVEs on an internet-reachable pod get no
// hop count at all and sit unclassified in must_fix.
var inheritEdgeTypes = graphschema.InheritEdgeTypes()

// inheritReverseEdgeTypes are containment edges recorded in the causal rather
// than the containment direction (repo -[deploys_to]→ workload), so the SOURCE
// inherits the destination's hop count. Same closure, edge read backwards.
var inheritReverseEdgeTypes = graphschema.InheritReverseEdgeTypes()

// reachRels are the rel tables the reach BFS depends on — losing rows from one of
// these at load time invalidates the reach signal (see copyStats.reachRelsDropped).
var reachRels = graphschema.ReachRels()

// possibleSeedDepth is the BFS distance a `possible`-tier exposure seed enters
// at, versus 0 for a `confirmed` one.
//
// Confirmed means the collector observed an unauthenticated path; possible means
// the configuration permits or fails to prevent exposure, with one unverified
// control standing in the way. That one control is exactly one hop of attacker
// work, so the tier is expressed as distance rather than as a separate signal
// channel — NodeSignals.InternetHops is a 4-state int both the must-fix
// classifier and the reachability scorer already understand, so a possible-tier
// entry scores at the 1-hop weight instead of the direct one, with no new field
// or SchemaVersion bump.
//
// It is still reachable (hops <= maxReachDepth): the contained gate in
// enrich.classifyMustFix stops firing on these resources, so a privesc finding
// is judged on its merits instead of being demoted for an internet path the
// graph had refused to draw.
const possibleSeedDepth = 1

// seedDepthFor returns the BFS start depth for an exposed_to_internet edge.
// An edge with no tier property is confirmed: every network-derived exposure
// omits it deliberately.
func seedDepthFor(e asset.Edge) int {
	if e.Properties[asset.EdgePropPublicAccess] == asset.PublicAccessPossible {
		return possibleSeedDepth
	}
	return 0
}

// reachOverlay is the pair of edge-derived facts every node row needs: the
// CONFIRMED-tier exposure set and the attacker-movement hop count. Both are pure
// functions of the edge slice, and one sweep needs them in three places — the load
// digest's node walk, the loader's node walk, and the post-swap signal-cache
// prewarm.
//
// Computed once and shared rather than re-derived at each site: besides avoiding
// three redundant passes over the full edge slice, it removes the risk of the
// three sites disagreeing — node_rows.go documents that `exposed[id]` and
// `hops[id] == 0` are deliberately NOT the same predicate, and an independently
// re-derived pair drifting apart is a real defect class.
type reachOverlay struct {
	exposed map[string]bool
	hops    map[string]int
	// identityDropped is the INV-1 count: exposed_to_internet edges whose source is
	// an identity, which can never be a 0-hop seed. Feeds the identity_zero_hop gauge.
	identityDropped int
}

// newReachOverlay derives the overlay from the edge slice. This is the ONLY place
// internetHops and exposedSeedSet are called from production code —
// TestReachOverlayIsDerivedInOnePlace pins that, because a fourth caller is a fourth
// full pass over the edge slice and a fourth chance for the two predicates to drift.
func newReachOverlay(edges []asset.Edge) reachOverlay {
	hops, dropped := internetHops(edges)
	return reachOverlay{exposed: exposedSeedSet(edges), hops: hops, identityDropped: dropped}
}

// signalsFor overlays the topology-derived fields onto a resource's finding-derived
// signals. notReached is ReachNone when the edge fetch was complete and ReachUnknown
// when it was not (fail open — see streamNodeRows).
func (o reachOverlay) signalsFor(id string, s NodeSignals, notReached int) NodeSignals {
	s.Exposed = o.exposed[id]
	s.ToxicCombo = s.Exposed && s.PrivescCount > 0
	if h, ok := o.hops[id]; ok {
		s.InternetHops = h
	} else {
		s.InternetHops = notReached
	}
	return s
}

// internetHops computes, for every node reachable from an internet-exposed seed,
// the shortest attacker-movement distance to it (0 = directly exposed, 1..N =
// transitively reachable). Nodes not in the returned map are not reachable within
// maxReachDepth. Pure and cheap: a bounded multi-source BFS over the in-memory
// edge slice, mirroring how `exposed` is derived in buildNodeRows.
//
// The second return is the count of exposed_to_internet edges dropped because
// their source is an identity (INV-1): a principal is never itself a node on the
// internet, so it can never be a 0-hop seed. Dropping it means such an identity
// is scored via its real transitive reach instead of a false direct exposure; the
// count feeds the identity_zero_hop obs gauge, which must stay 0.
func internetHops(edges []asset.Edge) (map[string]int, int) {
	// Forward adjacency over attacker-movement edges only.
	adj := make(map[string][]string)
	inheritAdj := make(map[string][]string)
	seedDepth := make(map[string]int)
	identitySeedsDropped := 0
	for _, e := range edges {
		switch {
		case e.EdgeType == "exposed_to_internet":
			if graphschema.IsIdentityType(e.SrcType) {
				identitySeedsDropped++ // INV-1: an identity is never an internet seed
				continue
			}
			if e.SrcID == "" || e.SrcID == InternetNodeID {
				continue
			}
			// The exposed asset is the entry point. Its distance is graded by the
			// tier the collector could prove: see possibleSeedDepth.
			d := seedDepthFor(e)
			if cur, ok := seedDepth[e.SrcID]; !ok || d < cur {
				seedDepth[e.SrcID] = d
			}
		case reachEdgeTypes[e.EdgeType]:
			adj[e.SrcID] = append(adj[e.SrcID], e.DstID)
		case inheritEdgeTypes[e.EdgeType]:
			inheritAdj[e.SrcID] = append(inheritAdj[e.SrcID], e.DstID)
		case inheritReverseEdgeTypes[e.EdgeType]:
			// Same containment closure, edge read backwards: the workload contains
			// the repo's code even though the producer emits repo → workload.
			inheritAdj[e.DstID] = append(inheritAdj[e.DstID], e.SrcID)
		}
	}

	// Seeds enter the frontier at their own depth, so a possible-tier entry point
	// starts one hop in rather than at the origin. Sorted, because the frontier
	// order at a given depth must not depend on map iteration.
	byDepth := make(map[int][]string, 2)
	for id, d := range seedDepth {
		byDepth[d] = append(byDepth[d], id)
	}
	for d := range byDepth {
		sort.Strings(byDepth[d])
	}

	hops := make(map[string]int)
	var frontier []string
	for depth := 0; depth <= maxReachDepth; depth++ {
		for _, s := range byDepth[depth] {
			if _, ok := hops[s]; ok {
				continue // already reached at an equal-or-shorter distance
			}
			hops[s] = depth
			frontier = append(frontier, s)
		}
		if depth == maxReachDepth || len(frontier) == 0 {
			continue // at the cap we still admit seeds, we just stop expanding
		}
		var next []string
		for _, id := range frontier {
			for _, dst := range adj[id] {
				if dst == "" {
					continue
				}
				if _, seen := hops[dst]; seen {
					continue // already reached at an equal-or-shorter distance
				}
				hops[dst] = depth + 1
				next = append(next, dst)
			}
		}
		frontier = next
	}

	// Containment closure: everything inside a reached node is reachable AT that
	// node's distance. Runs to a fixpoint over inheritAdj rather than for a fixed
	// number of levels, so pod→container→image→package works without hard-coding
	// the chain's length.
	//
	// Relaxes to the MINIMUM rather than keeping the first value written: a shared
	// container image reachable from multiple pods at different distances must
	// take the shortest, or its hop count (and must_fix classification) would
	// depend on nondeterministic traversal order.
	//
	// Terminates because a node is only re-enqueued when its distance strictly
	// decreases, bounded below by zero. Seed order is sorted so the traversal is
	// reproducible.
	inheritFrontier := make([]string, 0, len(hops))
	for id := range hops {
		inheritFrontier = append(inheritFrontier, id)
	}
	sort.Strings(inheritFrontier)
	for len(inheritFrontier) > 0 {
		var next []string
		for _, id := range inheritFrontier {
			for _, dst := range inheritAdj[id] {
				if dst == "" {
					continue
				}
				if cur, seen := hops[dst]; seen && cur <= hops[id] {
					continue // already at least as close
				}
				hops[dst] = hops[id] // inherited, not incremented
				next = append(next, dst)
			}
		}
		inheritFrontier = next
	}
	return hops, identitySeedsDropped
}

// prewarmSignalCache clears the node-signal cache and repopulates it for EVERY
// loaded node, overlaying the authoritative BFS reach so the cache never serves
// the poisoned zero-value InternetHops (see the lastHops field doc in
// service.go). Callers that just rebuilt topology stash the fresh hops AND node
// list via setLastHops first; RefreshSignals (no topology change) reuses the
// stored pair.
//
// Two passes over disjoint id sets:
//  1. sigByResource — every finding-bearing resource, whether or not it is a
//     loaded Ladybug node (this cache is keyed by resource id, not graph membership).
//  2. lastNodeIDs minus whatever pass 1 already wrote — every OTHER loaded node,
//     i.e. one with no finding-signal-rollup entry. Without this second pass,
//     lookups fell through to Ladybug for every finding-free node, which is most of
//     the graph. The stored value is not a guess: Ladybug's own signal columns for
//     that node were written from this same sigByResource snapshot, so a cache
//     miss would return the same zero finding-fields anyway. signalsFor still
//     overlays the real Exposed/ToxicCombo/InternetHops from ov, so a
//     finding-free but internet-reachable node still reports its true hop count.
func (s *Service) prewarmSignalCache(sigByResource map[string]NodeSignals) {
	ov, reachDone, nodeIDs := s.lastReach()

	notReached := ReachNone
	if !reachDone {
		notReached = ReachUnknown
	}
	s.nodeSignalsCache.Range(func(k, _ any) bool { s.nodeSignalsCache.Delete(k); return true })
	s.blastRadiusCache.Range(func(k, _ any) bool { s.blastRadiusCache.Delete(k); return true })
	for id, sig := range sigByResource {
		// Exposed, ToxicCombo and InternetHops are topology-derived — no
		// SignalSource populates them, so the rollup carries zero values (which for
		// InternetHops means "0-hop exposed", not "unknown"). Overlay all three from
		// the last topology build instead of trusting the rollup's zeros.
		s.nodeSignalsCache.Store(id, ov.signalsFor(id, sig, notReached))
	}
	for _, id := range nodeIDs {
		if _, ok := sigByResource[id]; ok {
			continue // already written above from the real rollup entry
		}
		// A zero-value NodeSignals is safe here: signalsFor always overwrites
		// InternetHops and recomputes ToxicCombo from Exposed && PrivescCount>0, so
		// a finding-free node lands correctly at ToxicCombo=false.
		s.nodeSignalsCache.Store(id, ov.signalsFor(id, NodeSignals{}, notReached))
	}
}

// setLastHops stashes the reach overlay AND the full loaded-node-id list from a
// topology build so a later signal-only refresh (which has no edges and no fresh
// asset list) can still overlay correct reach, recompute toxic_combo, and
// pre-warm every loaded node's cache entry — not only the finding-bearing ones.
func (s *Service) setLastHops(ov reachOverlay, reachComplete bool, nodeIDs []string) {
	s.lastHopsMu.Lock()
	s.lastOverlay, s.lastReachDone, s.lastNodeIDs = ov, reachComplete, nodeIDs
	s.lastHopsMu.Unlock()
}

// lastReach returns the stashed overlay, completeness flag, and loaded-node-id
// list under one read lock, so a refresh cannot observe a torn triple.
func (s *Service) lastReach() (reachOverlay, bool, []string) {
	s.lastHopsMu.RLock()
	defer s.lastHopsMu.RUnlock()
	return s.lastOverlay, s.lastReachDone, s.lastNodeIDs
}

// assetIDs extracts the id column from an asset slice, in order. Used to stash
// the loaded-node-id list for prewarmSignalCache's full-coverage pass.
func assetIDs(assets []asset.Asset) []string {
	ids := make([]string, len(assets))
	for i := range assets {
		ids[i] = assets[i].ID
	}
	return ids
}
