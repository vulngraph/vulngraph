package alertctx

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AssetIndex selects candidate asset ids. CHRepo implements it.
type AssetIndex interface {
	LiveIDs(ctx context.Context, ids []string) ([]string, error)
	IDsByAttribute(ctx context.Context, ips, names []string) ([]string, bool, error)
}

// Assets hydrates assets and answers direct exposure. asset.Service implements it.
type Assets interface {
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
	IsExposedEdge(ctx context.Context, assetID string) (bool, error)
}

// BlastWalker walks the attacker-direction blast radius. asset.Service
// implements it, as does the Ladybug-backed provider wired in serve.
type BlastWalker interface {
	BlastRadius(ctx context.Context, seedID string, maxDepth int) (asset.BlastRadius, error)
}

// FindingLister lists open findings. finding.Service implements it.
type FindingLister interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

// PropagatedScores reads the post-BFS risk scores the graph engine serves; the
// ClickHouse asset row only holds the pre-propagation score. An id missing from
// the result is not held by the engine.
type PropagatedScores interface {
	PropagatedRiskScores(ctx context.Context, ids []string) (map[string]uint8, error)
}

type Service struct {
	index    AssetIndex
	assets   Assets
	blast    BlastWalker
	findings FindingLister
	scores   PropagatedScores // nil: every asset reports its stored score
}

func NewService(index AssetIndex, assets Assets, blast BlastWalker, findings FindingLister) *Service {
	return &Service{index: index, assets: assets, blast: blast, findings: findings}
}

// WithPropagatedScores serves the graph-propagated risk score where the engine
// holds the asset; without it every asset reports its stored score.
func (s *Service) WithPropagatedScores(p PropagatedScores) *Service {
	s.scores = p
	return s
}

// Context resolves every identifier to graph assets and assembles a bounded
// context for each. A section that cannot be measured is returned unavailable
// with a reason, never as a zero that reads as "no risk". Every input appears in
// Result.Identifiers, resolved or not.
func (s *Service) Context(ctx context.Context, identifiers []string) (Result, error) {
	if len(identifiers) == 0 {
		return Result{}, ErrNoIdentifiers
	}
	if len(identifiers) > MaxIdentifiers {
		return Result{}, fmt.Errorf("%w: got %d, max %d", ErrTooManyIDs, len(identifiers), MaxIdentifiers)
	}
	plans := make([]plan, len(identifiers))
	for i, in := range identifiers {
		plans[i] = planFor(in)
	}

	resolutions, assets, capped := s.resolve(ctx, plans)
	res := Result{Identifiers: resolutions, Truncated: capped}

	var order []string
	seen := map[string]bool{}
	matchedBy := map[string][]IdentifierMatch{}
	for _, r := range resolutions {
		for _, m := range r.Matches {
			matchedBy[m.AssetID] = append(matchedBy[m.AssetID], IdentifierMatch{Input: clean(r.Input), MatchType: m.MatchType, Confidence: m.Confidence})
			if !seen[m.AssetID] {
				seen[m.AssetID] = true
				order = append(order, m.AssetID)
			}
		}
		if r.MoreMatches {
			res.Truncated = true
		}
	}
	if len(order) > MaxAssets {
		res.OmittedAssets = order[MaxAssets:]
		order = order[:MaxAssets]
		res.Truncated = true
	}

	res.Assets = make([]AssetContext, len(order))
	propagated := s.propagatedScores(ctx, order)
	var wg sync.WaitGroup
	sem := make(chan struct{}, subLookupConcurrency)
	for i, id := range order {
		a := assets[id]
		sum := summarize(a)
		if score, ok := propagated[id]; ok {
			sum.RiskScore, sum.RiskScoreSource = score, RiskSourceLadybug
		}
		res.Assets[i] = AssetContext{Asset: sum, MatchedBy: matchedBy[id]}
		s.fill(ctx, &wg, sem, a, &res.Assets[i])
	}
	wg.Wait()
	for i := range res.Assets {
		finish(&res.Assets[i])
		if res.Assets[i].Blast.Truncated || res.Assets[i].Findings.Truncated {
			res.Truncated = true
		}
	}
	res.Summary = resultSummary(res)
	return res, nil
}

// propagatedScores returns the graph-propagated score for the ids the engine
// holds. A failed read is logged and yields none, so every asset keeps its
// stored score, labelled RiskSourceStored.
func (s *Service) propagatedScores(ctx context.Context, ids []string) map[string]uint8 {
	if s.scores == nil || len(ids) == 0 {
		return nil
	}
	scores, err := s.scores.PropagatedRiskScores(ctx, ids)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("alertctx: propagated risk scores unavailable, serving stored scores")
		return nil
	}
	return scores
}

// resolve runs the batched candidate lookups, hydrates the candidates once and
// matches them to each plan. The bool reports that the attribute scan hit its
// candidate limit.
func (s *Service) resolve(ctx context.Context, plans []plan) ([]Resolution, map[string]asset.Asset, bool) {
	ids, ips, names := unionKeys(plans)
	var (
		idHits, attrHits []string
		capped           bool
	)
	idErr := runIf(ctx, len(ids) > 0, "id lookup", func() (err error) {
		idHits, err = s.index.LiveIDs(ctx, ids)
		return err
	})
	attrErr := runIf(ctx, len(ips)+len(names) > 0, "attribute lookup", func() (err error) {
		attrHits, capped, err = s.index.IDsByAttribute(ctx, ips, names)
		return err
	})

	candidates := dedupe(append(idHits, attrHits...))
	var hydrated []asset.Asset
	hydrateErr := runIf(ctx, len(candidates) > 0, "asset hydration", func() (err error) {
		hydrated, err = s.assets.ByIDs(ctx, candidates)
		return err
	})
	byID := make(map[string]asset.Asset, len(hydrated))
	for _, a := range hydrated {
		byID[a.ID] = a
	}
	sorted := make([]asset.Asset, 0, len(byID))
	for _, a := range byID {
		sorted = append(sorted, a)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	out := make([]Resolution, len(plans))
	for i, p := range plans {
		out[i] = matchPlan(p, sorted, lookupErrors{ids: idErr, attr: attrErr, hydrate: hydrateErr}, capped)
	}
	return out, byID, capped
}

// runIf runs fn when needed and returns a short fixed reason on failure; the
// error detail is logged, not returned to callers.
func runIf(ctx context.Context, needed bool, what string, fn func() error) string {
	if !needed {
		return ""
	}
	if err := fn(); err != nil {
		log.FromContext(ctx).Error().Err(err).Str("lookup", what).Msg("alertctx: lookup failed")
		return what + " failed"
	}
	return ""
}

type lookupErrors struct{ ids, attr, hydrate string }

// matchPlan applies a plan's lookups to the hydrated candidates. Lookup failures
// are carried into the Resolution: a failed lookup is never reported as "not
// found".
func matchPlan(p plan, assets []asset.Asset, errs lookupErrors, capped bool) Resolution {
	r := Resolution{Input: clean(p.input), Normalized: clean(p.normalized)}
	if len(p.lookups) == 0 {
		r.Status, r.Reason = StatusUnresolved, "empty identifier"
		return r
	}
	var failures []string
	usedAttr := false
	best := map[string]Match{}
	for _, l := range p.lookups {
		if reason := lookupFailure(l, errs); reason != "" {
			failures = append(failures, reason)
			continue
		}
		usedAttr = usedAttr || len(l.ips)+len(l.names) > 0
		for _, a := range assets {
			if !l.accept(a) {
				continue
			}
			if cur, ok := best[a.ID]; !ok || l.conf.rank() > cur.Confidence.rank() {
				best[a.ID] = Match{AssetID: a.ID, MatchType: l.matchType, Confidence: l.conf}
			}
		}
	}
	for _, m := range best {
		r.Matches = append(r.Matches, m)
	}
	sort.Slice(r.Matches, func(i, j int) bool {
		a, b := r.Matches[i], r.Matches[j]
		if a.Confidence.rank() != b.Confidence.rank() {
			return a.Confidence.rank() > b.Confidence.rank()
		}
		return a.AssetID < b.AssetID
	})
	if len(r.Matches) > MaxMatchesPerID {
		r.Matches, r.MoreMatches = r.Matches[:MaxMatchesPerID], true
	}

	failNote := strings.Join(dedupe(failures), "; ")
	switch {
	case len(r.Matches) > 0:
		r.Status = StatusResolved
		if failNote != "" {
			r.Reason = failNote + "; results may be incomplete"
		}
	case failNote != "":
		r.Status, r.Reason = StatusLookupFailed, failNote
	default:
		r.Status, r.Reason = StatusUnresolved, "no live asset matches"
		if capped && usedAttr {
			r.Reason += " within the candidate limit; the scan was cut off"
		}
	}
	return r
}

func lookupFailure(l lookup, e lookupErrors) string {
	switch {
	case len(l.ids) > 0 && e.ids != "":
		return e.ids
	case len(l.ips)+len(l.names) > 0 && e.attr != "":
		return e.attr
	case e.hydrate != "":
		return e.hydrate
	}
	return ""
}

func unionKeys(plans []plan) (ids, ips, names []string) {
	for _, p := range plans {
		for _, l := range p.lookups {
			ids = append(ids, l.ids...)
			ips = append(ips, l.ips...)
			names = append(names, l.names...)
		}
	}
	return dedupe(ids), dedupe(ips), dedupe(names)
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
