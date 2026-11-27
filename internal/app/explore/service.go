package explore

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/graphquery"
)

// Budgets — a query can never become an unbounded ClickHouse sweep.
const (
	defaultMaxNodes = 500
	hardMaxNodes    = 2000
	defaultMaxEdges = 2000
	hardMaxEdges    = 5000
	maxHopsPerStep  = 5
)

// DeletionVerifier excludes proven-deleted identities without treating an
// unobserved identity as absent. The asset service also verifies reappearance.
type DeletionVerifier interface {
	VerifyDeletedAssets(context.Context, []string) (map[string]bool, error)
}

// Repo is the graph storage the engine reads. CHRepo implements it.
type Repo interface {
	// MatchSeed returns up to limit assets matching the seed selector.
	MatchSeed(ctx context.Context, m NodeMatch, limit int) ([]Node, error)
	// Neighbors returns the edges leaving/entering the given node IDs (filtered
	// by edgeTypes/direction), in stored src→dst orientation, and the asset nodes
	// at the far end. truncated reports that an engine-side bound cut the answer
	// short, so callers never present a partial neighbourhood as complete.
	Neighbors(ctx context.Context, ids, edgeTypes []string, dir Direction) (edges []Edge, nodes []Node, truncated bool, err error)
}

// Translator turns natural language into a query spec. internal/reason
// implements it with the configured LLM provider; it is optional (the query engine works without it).
type Translator interface {
	Translate(ctx context.Context, nl string) (GraphQuerySpec, error)
}

// CypherTranslator converts natural language to a raw Ladybug Cypher query.
// reason.CypherTranslator implements this; nil disables the NL Cypher endpoint.
type CypherTranslator interface {
	TranslateToCypher(ctx context.Context, nl string) (string, error)
}

// ErrTranslateUnavailable is returned by Translate when no translator is wired
// (e.g. no LLM provider configured).
var ErrTranslateUnavailable = errors.New("explore: query translation is not available")

type Service struct {
	repo             Repo
	translator       Translator
	cypherTranslator CypherTranslator
}

// NewService builds the engine. Pass WithTranslator to enable NL translation.
func NewService(repo Repo, opts ...Option) *Service {
	s := &Service{repo: repo}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Option configures a Service.
type Option func(*Service)

// WithTranslator enables Translate by wiring an NL→spec translator.
func WithTranslator(t Translator) Option {
	return func(s *Service) { s.translator = t }
}

// WithCypherTranslator enables NL→Cypher translation via the configured LLM provider.
func WithCypherTranslator(t CypherTranslator) Option {
	return func(s *Service) { s.cypherTranslator = t }
}

// TranslateAndRunCypher converts a natural-language question to Ladybug Cypher
// via the configured LLM provider, validates it is read-only, then executes it
// against the graph. maxNodes/maxEdges are the caller's caps: <=0 uses the
// defaults (500/2000), anything above the hard caps (2000/5000) is clamped.
func (s *Service) TranslateAndRunCypher(ctx context.Context, runner CypherRunner, nl string, maxNodes, maxEdges int) (Result, string, error) {
	if s.cypherTranslator == nil || runner == nil {
		return Result{}, "", ErrTranslateUnavailable
	}
	cypher, err := s.cypherTranslator.TranslateToCypher(ctx, nl)
	if err != nil {
		return Result{}, "", fmt.Errorf("TranslateAndRunCypher: translate: %w", err)
	}
	// Validate before any execution — LLM output never reaches Ladybug unvalidated.
	if !graphquery.IsReadOnly(cypher) {
		return Result{}, cypher, fmt.Errorf("TranslateAndRunCypher: generated query is not a permitted read-only query")
	}
	maxNodes, maxEdges = cypherCaps(maxNodes, maxEdges)
	res, err := runner.RunCypher(ctx, cypher, maxNodes, maxEdges)
	if err != nil {
		return Result{}, cypher, fmt.Errorf("TranslateAndRunCypher: execute: %w", err)
	}
	return res, cypher, nil
}

// Translate turns a natural-language question into a query spec WITHOUT running
// it — the caller reviews/edits, then submits via Run.
func (s *Service) Translate(ctx context.Context, nl string) (GraphQuerySpec, error) {
	if s.translator == nil {
		return GraphQuerySpec{}, ErrTranslateUnavailable
	}
	spec, err := s.translator.Translate(ctx, nl)
	if err != nil {
		return GraphQuerySpec{}, fmt.Errorf("Translate: %w", err)
	}
	return spec, nil
}

// Run compiles and executes a spec as a bounded breadth-first traversal.
func (s *Service) Run(ctx context.Context, spec GraphQuerySpec) (Result, error) {
	maxNodes := clamp(spec.MaxNodes, defaultMaxNodes, hardMaxNodes)
	maxEdges := clamp(spec.MaxEdges, defaultMaxEdges, hardMaxEdges)

	seeds, err := s.repo.MatchSeed(ctx, spec.Seed, maxNodes)
	if err != nil {
		return Result{}, fmt.Errorf("Run: seed: %w", err)
	}
	if len(seeds) == 0 {
		return Result{}, ErrNoSeed
	}

	res := Result{Nodes: seeds}
	seen := make(map[string]bool, len(seeds))
	frontier := make([]string, 0, len(seeds))
	for _, n := range seeds {
		seen[n.ID] = true
		frontier = append(frontier, n.ID)
	}

	for _, step := range spec.Traverse {
		dir := step.Direction
		if dir == "" {
			dir = DirectionOut
		}
		hops := clamp(step.MaxHops, 1, maxHopsPerStep)
		for h := 0; h < hops && len(frontier) > 0; h++ {
			edges, nodes, cut, err := s.repo.Neighbors(ctx, frontier, step.EdgeTypes, dir)
			if err != nil {
				return Result{}, fmt.Errorf("Run: neighbors: %w", err)
			}
			res.Truncated = res.Truncated || cut
			nodeByID := indexNodes(nodes)
			onFrontier := make(map[string]bool, len(frontier))
			for _, id := range frontier {
				onFrontier[id] = true
			}

			var next []string
			for _, e := range edges {
				if len(res.Edges) >= maxEdges {
					res.Truncated = true
					return res, nil
				}
				res.Edges = append(res.Edges, e)

				dstID := farEndpoint(e, dir, onFrontier)
				if seen[dstID] {
					continue
				}
				if len(seen) >= maxNodes {
					res.Truncated = true
					return res, nil
				}
				seen[dstID] = true
				next = append(next, dstID)
				if n, ok := nodeByID[dstID]; ok {
					res.Nodes = append(res.Nodes, n)
				} else {
					res.Nodes = append(res.Nodes, Node{ID: dstID}) // dangling endpoint
				}
			}
			frontier = next
		}
	}
	return res, nil
}

// expandNodeMax caps ExpandNode results so a highly-connected node (e.g. a
// firewall that targets every GCE instance) does not return thousands of
// nodes and crash the graph renderer.
const expandNodeMax = 150

// ExpandNode returns one node's immediate neighborhood (click-to-expand).
func (s *Service) ExpandNode(ctx context.Context, id string, edgeTypes []string, dir Direction) (Result, error) {
	if id == "" {
		return Result{}, ErrInvalidSpec
	}
	if dir == "" {
		dir = DirectionBoth
	}
	edges, nodes, truncated, err := s.repo.Neighbors(ctx, []string{id}, edgeTypes, dir)
	if err != nil {
		return Result{}, fmt.Errorf("ExpandNode: %w", err)
	}
	if len(nodes) > expandNodeMax {
		nodes = nodes[:expandNodeMax]
		truncated = true
	}
	if len(edges) > expandNodeMax {
		edges = edges[:expandNodeMax]
		truncated = true
	}
	return Result{Nodes: nodes, Edges: edges, Truncated: truncated}, nil
}

// farEndpoint returns the node id on the other side of an edge from the frontier.
// Edges arrive in stored orientation (src→dst) whichever way they were walked,
// so for "in" the source is the far end, and for "both" it is whichever end is
// not on the frontier — an inbound edge's far end is its source.
func farEndpoint(e Edge, dir Direction, frontier map[string]bool) string {
	switch dir {
	case DirectionIn:
		return e.SrcID
	case DirectionBoth:
		if frontier[e.DstID] && !frontier[e.SrcID] {
			return e.SrcID
		}
	}
	return e.DstID
}

func indexNodes(nodes []Node) map[string]Node {
	m := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		m[n.ID] = n
	}
	return m
}

// cypherCaps applies the documented Cypher result caps: <=0 is the default,
// anything above the hard cap is clamped to it.
func cypherCaps(maxNodes, maxEdges int) (int, int) {
	return clamp(maxNodes, defaultMaxNodes, hardMaxNodes), clamp(maxEdges, defaultMaxEdges, hardMaxEdges)
}

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}
