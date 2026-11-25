package correlate

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// viewLoader loads the correlation inventory view. CHRepo implements it.
type viewLoader interface {
	LoadView(ctx context.Context) (assets []asset.Asset, truncated bool, err error)
	LoadViewForTypes(ctx context.Context, types []string) (assets []asset.Asset, truncated bool, err error)
	LoadByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// assetStore persists derived edges and, for a rule that also implements
// AssetAnnotator, asset metadata annotations (drift signals with no live node
// to anchor an edge to). ByIDs fetches the FULL current row (every column,
// unlike the correlation view's minimal projection) so annotation writes merge
// onto real name/discovered_at/last_seen instead of upserting them blank —
// writing the partial copy would also zero last_seen, making the row
// TTL-eligible for immediate purge.
// asset.Service implements it via IngestEdges/IngestAssets/ByIDs.
type assetStore interface {
	IngestEdges(ctx context.Context, edges []asset.Edge) error
	IngestAssets(ctx context.Context, assets []asset.Asset) error
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
}

// AssetAnnotator is an optional Rule extension for signals that have no live
// node to anchor an edge to (e.g. an orphaned k8s manifest — drift:
// "declared_not_live" is a signal on the asset, not a hard finding). A rule
// implements it in addition to Rule.Correlate when it needs to write back
// asset metadata rather than (or in addition to) edges.
type AssetAnnotator interface {
	CorrelateAssets(g Graph) []asset.Asset
}

// DemotionReporter is an optional Rule extension for rules that can withhold
// an edge on positive counter-evidence. The full sweep logs what they report,
// so an exposure that disappears for a reason is visible as that reason.
type DemotionReporter interface {
	Demotions(g Graph) []Demotion
}

// ViewObserver records the size of each inventory-view load against its
// circuit-breaker limit, so the limit is alertable before it trips (the limit
// itself fails the sweep closed via ErrViewTruncated). *obs.Metrics satisfies
// it (ObserveCorrelateView) — defined here, not imported from internal/obs, so
// this domain's service.go stays free of an infra import; the concrete
// metrics type is wired in from the jobs layer via WithViewMetrics.
type ViewObserver interface {
	ObserveCorrelateView(rows, limit int)
}

// Service runs the registered correlation rules over a single inventory view and
// writes the edges they derive.
type Service struct {
	repo   viewLoader
	assets assetStore
	rules  []Rule
	// viewObserver is optional; nil disables view-size reporting.
	viewObserver ViewObserver
}

func NewService(repo viewLoader, assets assetStore, rules []Rule) *Service {
	return &Service{repo: repo, assets: assets, rules: rules}
}

// WithViewMetrics wires inventory-view size reporting. Returns the service so it
// can be chained onto NewService.
func (s *Service) WithViewMetrics(o ViewObserver) *Service {
	s.viewObserver = o
	return s
}

// observeView reports a view load. Split out so the full and partial load
// paths report identically.
func (s *Service) observeView(rows int) {
	if s.viewObserver != nil {
		s.viewObserver.ObserveCorrelateView(rows, correlationLimit)
	}
}

// Correlate loads the inventory once, runs every rule against the shared view,
// dedupes the derived edges, and writes them. Returns the number of edges
// written. A graph with no assets yet is a clean no-op.
func (s *Service) Correlate(ctx context.Context) (int, error) {
	logger := log.FromContext(ctx)

	assets, truncated, err := s.repo.LoadView(ctx)
	if err != nil {
		return 0, fmt.Errorf("Correlate: %w", err)
	}
	s.observeView(len(assets))
	// No early return on an empty view: every rule must still run once so
	// stateful rules (CIAccess) reset their per-sweep accumulator; the loop is
	// a correct no-op for every stateless rule on an empty graph.
	//
	// Fail closed, not a Warn, on truncation: a rule that never re-stamps an
	// edge lets it age out of the freshness window, so a truncated sweep
	// deletes topology rather than merely missing some. Refusing the sweep
	// keeps the last good edge set alive until the ceiling is raised.
	if truncated {
		return 0, fmt.Errorf("Correlate: %w", ErrViewTruncated)
	}

	g := NewGraph(assets)
	// Logged on the full sweep only: it sees every principal, and a partial
	// correlate re-evaluates a subset the next full sweep logs again.
	for id, policies := range notActionWidenings(g) {
		logger.Debug().Str("asset_id", id).Strs("policies", policies).
			Msg("correlate: NotAction Allow treated as Allow * (conservative over-approximation)")
	}

	var edges []asset.Edge
	var annotated []asset.Asset
	for _, r := range s.rules {
		found := r.Correlate(g)
		logger.Info().Str("rule", r.Name()).Int("edges", len(found)).Msg("correlation rule complete")
		edges = append(edges, found...)
		if a, ok := r.(AssetAnnotator); ok {
			annotated = append(annotated, a.CorrelateAssets(g)...)
		}
		if d, ok := r.(DemotionReporter); ok {
			logDemotions(logger, r.Name(), d.Demotions(g))
		}
	}

	edges = dedupe(edges)
	if err := s.assets.IngestEdges(ctx, edges); err != nil {
		return 0, fmt.Errorf("Correlate: %w", err)
	}

	if err := s.writeAnnotations(ctx, logger, dedupeAssets(annotated)); err != nil {
		return 0, fmt.Errorf("Correlate: %w", err)
	}
	return len(edges), nil
}

// demotionLogSample caps how many demoted asset ids one log line carries.
const demotionLogSample = 20

// logDemotions records a rule's demotions as one line per reason, with a
// bounded sample of asset ids.
func logDemotions(logger *zerolog.Logger, rule string, demoted []Demotion) {
	byReason := map[string][]string{}
	for _, d := range demoted {
		byReason[d.Reason] = append(byReason[d.Reason], d.AssetID)
	}
	for reason, ids := range byReason {
		sample := ids[:min(len(ids), demotionLogSample)]
		logger.Info().Str("rule", rule).Str("reason", reason).Int("demoted", len(ids)).
			Strs("sample_asset_ids", sample).Msg("correlation rule demoted exposures on counter-evidence")
	}
}

// writeAnnotations hydrates each AssetAnnotator-derived asset (built from the
// correlation view's partial projection — see assetStore) with its FULL
// current row before writing, so the upsert-via-re-insert only ever changes
// the Metadata the rule actually touched, never blanks name/discovered_at/
// last_seen. A target that vanished between the view load and this write is
// logged and skipped rather than written partial.
//
// Metadata is MERGED key-by-key onto the full row, never assigned wholesale:
// a.Metadata is only ever a partial projection of the asset's real metadata,
// never guaranteed complete. A rule signals "delete this key" with an empty
// value (see withMetadata) rather than by omitting it, since omission means
// "this code path never touched this key" and must leave the stored value
// alone.
func (s *Service) writeAnnotations(ctx context.Context, logger *zerolog.Logger, annotated []asset.Asset) error {
	if len(annotated) == 0 {
		return nil
	}
	ids := make([]string, len(annotated))
	for i, a := range annotated {
		ids[i] = a.ID
	}
	full, err := s.assets.ByIDs(ctx, ids)
	if err != nil {
		return fmt.Errorf("writeAnnotations: load full assets: %w", err)
	}
	byID := make(map[string]asset.Asset, len(full))
	for _, a := range full {
		byID[a.ID] = a
	}

	merged := make([]asset.Asset, 0, len(annotated))
	for _, a := range annotated {
		f, ok := byID[a.ID]
		if !ok {
			logger.Warn().Str("asset_id", a.ID).Msg("drift annotation target vanished before write — skipping")
			continue
		}
		// Copy rather than mutate f.Metadata in place: f came from a map keyed
		// by ID, so if the same asset were ever annotated twice in one sweep
		// (dedupeAssets prevents that today, but nothing here should rely on
		// it) two iterations must not share a backing map.
		meta := make(map[string]string, len(f.Metadata)+len(a.Metadata))
		for k, v := range f.Metadata {
			meta[k] = v
		}
		for k, v := range a.Metadata {
			if v == "" {
				delete(meta, k)
				continue
			}
			meta[k] = v
		}
		f.Metadata = meta
		merged = append(merged, f)
	}
	if len(merged) == 0 {
		return nil
	}
	return s.assets.IngestAssets(ctx, merged)
}

// PartialCorrelate runs only the rules relevant to changedIDs, loading only the
// asset types those rules need. Used by the sync worker to update edges
// immediately after a change without waiting for the full graph rebuild.
// The 30-min full correlate remains the ground-truth sweep.
func (s *Service) PartialCorrelate(ctx context.Context, changedIDs []string) (int, error) {
	if len(changedIDs) == 0 {
		return 0, nil
	}
	changed, err := s.repo.LoadByIDs(ctx, changedIDs)
	if err != nil {
		return 0, fmt.Errorf("PartialCorrelate: load changed: %w", err)
	}
	if len(changed) == 0 {
		return 0, nil
	}

	changedTypes := typesOf(changed)
	activeRules := rulesFor(s.rules, changedTypes)
	if len(activeRules) == 0 {
		return 0, nil
	}

	neededTypes := neededTypesFor(activeRules)
	view, truncated, err := s.repo.LoadViewForTypes(ctx, neededTypes)
	if err != nil {
		return 0, fmt.Errorf("PartialCorrelate: load view: %w", err)
	}
	s.observeView(len(view))
	// Same fail-closed reasoning as Correlate above — this path runs on every
	// connector sync, so silently discarding the truncation flag here would be
	// worse, not better.
	if truncated {
		return 0, fmt.Errorf("PartialCorrelate: %w", ErrViewTruncated)
	}

	g := NewGraph(mergeChangedIntoView(view, changed))
	g.changedIDs = make(map[string]bool, len(changed))
	g.changedSCPAccounts = make(map[string]bool)
	g.changedTypes = changedTypes
	for _, a := range changed {
		g.changedIDs[a.ID] = true
		if a.Type == "aws_scp_set" && a.AccountID != "" {
			g.changedSCPAccounts[a.AccountID] = true
		}
	}

	var edges []asset.Edge
	for _, r := range activeRules {
		// Rules take Graph only, not ctx, so nothing preempts a rule already
		// running past the job's Timeout. Checking here at least stops a job
		// already past deadline from starting ANOTHER rule and compounding
		// the overrun.
		if ctx.Err() != nil {
			return 0, fmt.Errorf("PartialCorrelate: %w", ctx.Err())
		}
		edges = append(edges, r.Correlate(g)...)
	}
	edges = dedupe(edges)
	if err := s.assets.IngestEdges(ctx, edges); err != nil {
		return 0, fmt.Errorf("PartialCorrelate: ingest: %w", err)
	}
	return len(edges), nil
}

// mergeChangedIntoView combines the type-scoped view with the freshly changed
// assets, keeping ONE copy of each ID — the changed one, which is the newer
// read. Appending both lists blindly would double-enter any changed asset
// whose type is also in neededTypes, running every rule on it twice.
func mergeChangedIntoView(view, changed []asset.Asset) []asset.Asset {
	isChanged := make(map[string]bool, len(changed))
	for _, a := range changed {
		isChanged[a.ID] = true
	}
	merged := make([]asset.Asset, 0, len(view)+len(changed))
	for _, a := range view {
		if !isChanged[a.ID] {
			merged = append(merged, a)
		}
	}
	return append(merged, changed...)
}

func typesOf(assets []asset.Asset) map[string]bool {
	types := make(map[string]bool, len(assets))
	for _, a := range assets {
		types[a.Type] = true
	}
	return types
}

func rulesFor(rules []Rule, changedTypes map[string]bool) []Rule {
	var active []Rule
	for _, r := range rules {
		for _, t := range r.InterestedIn() {
			if changedTypes[t] {
				active = append(active, r)
				break
			}
		}
	}
	return active
}

func neededTypesFor(rules []Rule) []string {
	seen := make(map[string]bool)
	for _, r := range rules {
		for _, t := range r.InterestedIn() {
			seen[t] = true
		}
	}
	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	return types
}

// confidenceRank orders the "confidence" property rules stamp on an edge, so
// dedupe can pick the best evidence for a link instead of the first. An edge
// with no confidence property (most rules) ranks 0 and never displaces one that
// has it.
var confidenceRank = map[string]int{
	confidenceLow:    1,
	confidenceMedium: 2,
	confidenceHigh:   3,
}

// dedupe collapses edges with the same (SrcID, EdgeType, DstID) — two rules or
// two record values can derive the same link; the graph needs it once.
//
// The winner is the HIGHEST-confidence candidate, not the first one seen:
// picking first-writer-wins would make the surviving evidence a function of
// rule registration order rather than the quality of the evidence itself.
// Ties (equal or absent confidence) keep the first, so the result stays
// deterministic for rules that stamp no confidence at all.
func dedupe(edges []asset.Edge) []asset.Edge {
	at := make(map[string]int, len(edges))
	out := edges[:0]
	for _, e := range edges {
		key := e.SrcID + "|" + e.EdgeType + "|" + e.DstID
		i, ok := at[key]
		if !ok {
			at[key] = len(out)
			out = append(out, e)
			continue
		}
		if confidenceRank[e.Properties["confidence"]] > confidenceRank[out[i].Properties["confidence"]] {
			out[i] = e
		}
	}
	return out
}

// dedupeAssets collapses asset annotations with the same ID — two rules
// (or, in principle, the same rule twice) annotating the same asset only
// need writing once.
func dedupeAssets(assets []asset.Asset) []asset.Asset {
	seen := make(map[string]bool, len(assets))
	out := assets[:0]
	for _, a := range assets {
		if seen[a.ID] {
			continue
		}
		seen[a.ID] = true
		out = append(out, a)
	}
	return out
}
