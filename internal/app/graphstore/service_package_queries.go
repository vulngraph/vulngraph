package graphstore

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

const inventorySeedLimit = 100

type PackageNameReader interface {
	FindPackageVersions(context.Context, string, int) ([]asset.Asset, error)
}

func (s *Service) WithPackageInventory(repo explore.Repo, names PackageNameReader) *Service {
	s.packageInventory = repo
	s.packageNames = names
	return s
}

func (s *Service) runInventoryQuery(ctx context.Context, name string, params map[string]string) (explore.Result, error) {
	if s.packageInventory == nil || s.packageNames == nil {
		return explore.Result{}, fmt.Errorf("package inventory queries are not configured")
	}
	var seeds []explore.Node
	var steps []explore.Traverse
	var truncated bool
	switch name {
	case "package_source_repos", "package_running_workloads":
		if params["name"] == "" {
			return explore.Result{}, &explore.QueryRejection{Reason: "package name is required"}
		}
		rows, err := s.packageNames.FindPackageVersions(ctx, params["name"], inventorySeedLimit+1)
		if err != nil {
			return explore.Result{}, fmt.Errorf("package lookup: %w", err)
		}
		truncated = len(rows) > inventorySeedLimit
		for _, a := range rows[:min(len(rows), inventorySeedLimit)] {
			if a.Type == "package" {
				seeds = append(seeds, explore.Node{ID: a.ID, Type: a.Type, Name: a.Name, Score: int(a.RiskScore), InternetHops: ReachUnknown})
			}
		}
		if name == "package_source_repos" {
			steps = []explore.Traverse{{EdgeTypes: []string{"depends_on"}, Direction: explore.DirectionIn}}
		} else {
			steps = []explore.Traverse{{EdgeTypes: []string{"runs_package"}, Direction: explore.DirectionIn}, {EdgeTypes: []string{"runs_image"}, Direction: explore.DirectionIn}}
		}
	case "repo_package_dependencies":
		var err error
		seeds, err = s.packageInventory.MatchSeed(ctx, explore.NodeMatch{Types: []string{"github_repo"}}, inventorySeedLimit+1)
		if err != nil {
			return explore.Result{}, fmt.Errorf("repository seeds: %w", err)
		}
		truncated = len(seeds) > inventorySeedLimit
		seeds = seeds[:min(len(seeds), inventorySeedLimit)]
		steps = []explore.Traverse{{EdgeTypes: []string{"depends_on"}, Direction: explore.DirectionOut}}
	case "supply_chain_exposure", "high_risk_package_dependents":
		threshold := 40
		if name == "high_risk_package_dependents" {
			threshold = 61
		}
		query := fmt.Sprintf("MATCH (app:Asset) WHERE app.score >= %d AND app.internet_hops >= 0 RETURN app ORDER BY app.score DESC, app.id LIMIT %d", threshold, inventorySeedLimit+1)
		result, err := s.RunCypher(ctx, query, inventorySeedLimit+1, 1)
		if err != nil {
			return explore.Result{}, err
		}
		seeds = result.Nodes
		truncated = result.Truncated || len(seeds) > inventorySeedLimit
		seeds = seeds[:min(len(seeds), inventorySeedLimit)]
		steps = []explore.Traverse{{EdgeTypes: []string{"runs_package"}, Direction: explore.DirectionOut}}
		if name == "high_risk_package_dependents" {
			steps = append(steps, explore.Traverse{EdgeTypes: []string{"depends_on"}, Direction: explore.DirectionIn})
		}
	case "workloads_with_kev_packages", "kev_packages_on_exposed_assets":
		snapshot := s.packageSeeds.Load()
		if !s.synced.Load() || snapshot == nil {
			return explore.Result{}, fmt.Errorf("package signals are not ready")
		}
		seeds, truncated = snapshot.nodes, snapshot.truncated
		steps = []explore.Traverse{{EdgeTypes: []string{"runs_package"}, Direction: explore.DirectionIn}}
	default:
		return explore.Result{}, fmt.Errorf("unsupported inventory query %q", name)
	}
	if len(seeds) == 0 {
		return explore.Result{Truncated: truncated}.NonNil(), nil
	}
	ids := make([]string, len(seeds))
	for i, n := range seeds {
		ids[i] = n.ID
	}
	result, err := explore.NewService(s.packageInventory).Run(ctx, explore.GraphQuerySpec{
		Seed: explore.NodeMatch{IDs: ids}, Traverse: steps, MaxNodes: 2000, MaxEdges: 5000,
	})
	if err != nil {
		return explore.Result{}, fmt.Errorf("package inventory traversal: %w", err)
	}
	result.Truncated = result.Truncated || truncated
	if name == "kev_packages_on_exposed_assets" {
		kept := result.Edges[:0]
		for _, e := range result.Edges {
			sig, err := s.NodeSignals(ctx, e.SrcID)
			if err != nil {
				return explore.Result{}, fmt.Errorf("runtime exposure: %w", err)
			}
			if sig.InternetHops == ReachUnknown {
				result.Truncated = true
			}
			if sig.InternetHops >= 0 {
				kept = append(kept, e)
			}
		}
		result.Edges = kept
	}
	if name == "high_risk_package_dependents" {
		dependent := map[string]bool{}
		for _, e := range result.Edges {
			if e.EdgeType == "depends_on" {
				dependent[e.DstID] = true
			}
		}
		kept := result.Edges[:0]
		for _, e := range result.Edges {
			if dependent[e.DstID] {
				kept = append(kept, e)
			}
		}
		result.Edges = kept
	}
	// A named relationship query reports connected matches, not seed nodes that
	// had no membership. Bounded walks always carry their truncation flag.
	connected := map[string]bool{}
	for _, e := range result.Edges {
		connected[e.SrcID] = true
		connected[e.DstID] = true
	}
	seedByID := map[string]explore.Node{}
	for _, n := range seeds {
		seedByID[n.ID] = n
	}
	kept := result.Nodes[:0]
	for _, n := range result.Nodes {
		if !connected[n.ID] {
			continue
		}
		if seed, ok := seedByID[n.ID]; ok {
			n.Score = seed.Score
		}
		n.InternetHops = ReachUnknown
		if cached, ok := s.nodeSignalsCache.Load(n.ID); ok {
			sig := cached.(NodeSignals)
			n.MaxScore = sig.MaxScore
			n.HasKEV = sig.HasKEV
			n.Exploitable = sig.Exploitable
			n.Exposed = sig.Exposed
			n.InternetHops = sig.InternetHops
		}
		kept = append(kept, n)
	}
	result.Nodes = kept
	return result.NonNil(), nil
}

type packageSeedSet struct {
	nodes     []explore.Node
	truncated bool
}

// Publish a bounded immutable view so concurrent queries cannot observe a
// half-cleared signal cache during refresh.
func kevPackageSeeds(signals map[string]NodeSignals) *packageSeedSet {
	if signals == nil {
		return nil
	}
	var seeds []explore.Node
	count := 0
	less := func(a, b explore.Node) int {
		if a.MaxScore != b.MaxScore {
			return b.MaxScore - a.MaxScore
		}
		return strings.Compare(a.ID, b.ID)
	}
	for id, sig := range signals {
		if !strings.HasPrefix(id, "pkg:") || !sig.HasKEV {
			continue
		}
		count++
		n := explore.Node{ID: id, Type: "package", HasKEV: true, MaxScore: sig.MaxScore, InternetHops: ReachUnknown}
		if len(seeds) == inventorySeedLimit && less(n, seeds[len(seeds)-1]) >= 0 {
			continue
		}
		seeds = append(seeds, n)
		slices.SortFunc(seeds, less)
		if len(seeds) > inventorySeedLimit {
			seeds = seeds[:inventorySeedLimit]
		}
	}
	return &packageSeedSet{nodes: seeds, truncated: count > inventorySeedLimit}
}
