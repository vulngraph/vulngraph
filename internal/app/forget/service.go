package forget

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// PopulationReader reads what storage holds for the audited types of one connector.
// Implemented by asset.CHRepo; declared here as the narrow slice this service
// needs (CLAUDE.md: services hold interfaces they define themselves).
type PopulationReader interface {
	ScopeStaleness(ctx context.Context, connectorID string, types []string, absentBefore, confirmedBefore time.Time) ([]StoredCount, error)
	ScopeCandidateIDs(ctx context.Context, connectorID, assetType, region string, confirmedBefore time.Time, limit int) ([]Candidate, error)
}

// StoredCount mirrors asset.ScopeStaleness. Duplicated rather than imported so
// this domain does not depend on the asset domain's storage types.
type StoredCount struct {
	Region    string
	Type      string
	Stored    int
	Absent    int
	Confirmed int
}

// Candidate mirrors asset.ForgetCandidate for the same reason.
type Candidate struct {
	ID       string
	LastSeen time.Time
}

// Store persists the decision record and the tombstones.
type Store interface {
	ScopeStates(ctx context.Context, connectorID string) (map[ScopeKey]ScopeState, error)
	SaveRecords(ctx context.Context, connectorID string, recs []Record) error
	SaveTombstones(ctx context.Context, connectorID string, ts []Tombstone) (int, error)
}

// EdgeHealth reports the graph's last edge-fetch health. Implemented by
// graphstore.Service.EdgeSyncHealth.
//
// A nil EdgeHealth is not treated as healthy: every scope then refuses with
// RefusalEdgeHealthUnknown. Edges are re-stamped rather than deleted and every
// reader filters on freshness, so a truncated edge fetch already
// looks like mass edge deletion — taking a node decision on top of that
// compounds a known-partial topology.
type EdgeHealth interface {
	EdgeSyncHealth() (reachComplete bool, truncatedTypes []string)
}

// Metrics is the observability sink. Nil-safe by contract on the implementation
// side; a nil Metrics here disables publication and nothing else.
type Metrics interface {
	ObserveForgetVerdict(connectorID, scope, assetType, refusal string, confirmed, forgettable int, enforceScoped bool)
	ObserveForgetTombstones(connectorID string, written int)
}

// Service evaluates, records and (in ModeEnforce) tombstones.
type Service struct {
	mode Mode
	// enforceTypes is the FORGET_ENFORCE_TYPES allow-list (ParseEnforceTypes).
	// Consulted ONLY when mode == ModeEnforce — see enforceScoped. A nil/empty
	// map is the safe zero value: nothing gets tombstoned.
	enforceTypes map[string]bool
	pop          PopulationReader
	store        Store
	edges        EdgeHealth
	m            Metrics
}

func NewService(mode Mode, enforceTypes map[string]bool, pop PopulationReader, store Store, edges EdgeHealth, m Metrics) *Service {
	return &Service{mode: mode, enforceTypes: enforceTypes, pop: pop, store: store, edges: edges, m: m}
}

// Mode reports the configured mode, for startup logging.
func (s *Service) Mode() Mode { return s.mode }

// enforceScoped reports whether assetType is BOTH running under ModeEnforce
// AND on the FORGET_ENFORCE_TYPES allow-list — the single predicate that
// gates writing a tombstone. It is false unconditionally under ModeShadow,
// which is what keeps FORGET_ENFORCE_TYPES purely additive: shadow mode's
// behaviour (and the graph_forget_would_enforce metric derived from this)
// cannot change no matter what the allow-list contains. A type outside
// TombstoneEligibleTypes is never enforced, whatever map NewService was given.
func (s *Service) enforceScoped(assetType string) bool {
	return s.mode == ModeEnforce && s.enforceTypes[assetType] && tombstoneEligible[assetType]
}

// Sweep is one connector's completed enumerations as the sync worker observed
// them: the scope keys it PROVED complete this sweep, with the count each
// returned.
//
// Sweep deliberately carries no connector-wide Partial flag
// (collect.Result.Partial): see domain.go's Decide for why an unrelated
// family's failure must not refuse every audited scope.
type Sweep struct {
	ConnectorID string
	// At is the sweep's own clock — the cutoff a stored row must have been
	// re-stamped past to count as observed. Never wall-clock at evaluation
	// time: a slow sweep would otherwise read its own late-collected assets as
	// absent.
	At    time.Time
	Scope []ScopeEnumeration
}

// ScopeEnumeration mirrors collect.ScopeEnumeration, again to keep the
// dependency one-way.
type ScopeEnumeration struct {
	Scope string
	Types []string
	Count int
}

// Evaluate computes and records, for every enforceable scope in one sweep, what
// enforcement WOULD forget — and in ModeEnforce writes a tombstone per
// forgettable asset. It returns the total forgettable count for logging.
//
// Best-effort by construction: every failure returns an error the caller logs
// and discards. A sync must never fail because the deletion RECORD could not be
// written, and — more importantly — a failure here must never be recoverable by
// falling back to a less careful decision, which is why there is no partial
// path: one error and the whole connector's evaluation is abandoned.
func (s *Service) Evaluate(ctx context.Context, sw Sweep) (int, error) {
	if s == nil || sw.ConnectorID == "" || len(sw.Scope) == 0 {
		return 0, nil
	}
	scopes := enforceable(sw.Scope)
	if len(scopes) == 0 {
		return 0, nil
	}

	confirmedBefore := sw.At.Add(-ConfirmWindow)
	// absentBefore is the sweep clock less a small skew: last_seen is stamped by
	// the ingest that follows collection, so a row observed by THIS sweep can
	// carry a timestamp slightly after sw.At. Reading it as absent would be a
	// false candidate on live inventory.
	absentBefore := sw.At.Add(-observationSkew)

	counts, err := s.pop.ScopeStaleness(ctx, sw.ConnectorID, EnforceableTypes(), absentBefore, confirmedBefore)
	if err != nil {
		return 0, fmt.Errorf("Evaluate: population: %w", err)
	}
	states, err := s.store.ScopeStates(ctx, sw.ConnectorID)
	if err != nil {
		return 0, fmt.Errorf("Evaluate: scope states: %w", err)
	}

	truncated, edgeHealthKnown := s.edgeHealth()
	byRegionType := indexCounts(counts)

	recs := make([]Record, 0, len(scopes))
	var tombstones []Tombstone
	total := 0
	for _, se := range scopes {
		sc, ok := ParseScope(se.Scope)
		if !ok {
			continue
		}
		for _, t := range sc.Family.Types {
			key := ScopeKey{Scope: se.Scope, AssetType: t}
			prev := states[key]
			pop := byRegionType.lookup(sc, t)
			v := Decide(Input{
				Scope:      sc,
				AssetType:  t,
				Enumerated: se.Count,
				Population: pop,
				// prev.PrevCompleteAt, NOT prev.LastCompleteAt: the confirm-window
				// anchor is sticky (nextConfirmAnchor) and must be read back exactly
				// as it was stored, or it slides forward every sweep and the window
				// never elapses. See nextConfirmAnchor's doc comment.
				PrevCompleteAt:     prev.PrevCompleteAt,
				HighWater:          prev.HighWater,
				HighWaterAt:        prev.HighWaterAt,
				TruncatedEdgeTypes: truncated,
				EdgeHealthKnown:    edgeHealthKnown,
				Now:                sw.At,
			})
			recs = append(recs, Record{
				Scope:     se.Scope,
				AssetType: t,
				// last_complete_at is simply "the most recent successful sweep" —
				// informational, and not what confirm-window compares against.
				// prev_complete_at is v.NextConfirmAnchor: the sticky anchor Decide
				// just computed, which stays fixed across sweeps until it matures.
				LastCompleteAt: sw.At,
				PrevCompleteAt: v.NextConfirmAnchor,
				Enumerated:     se.Count,
				HighWater:      v.HighWater,
				HighWaterAt:    v.HighWaterAt,
				Stored:         pop.Stored,
				Absent:         pop.Absent,
				Confirmed:      pop.Confirmed,
				Forgettable:    v.Forgettable,
				Refusal:        v.Refusal,
				EvaluatedAt:    sw.At,
			})
			scoped := s.enforceScoped(t)
			if s.m != nil {
				s.m.ObserveForgetVerdict(sw.ConnectorID, se.Scope, t, v.Refusal, pop.Confirmed, v.Forgettable, scoped)
			}
			total += v.Forgettable
			// v.Forgettable is recorded (Record.Forgettable, above) and counted into
			// total regardless of scoping — "what every OTHER refusal permits" must
			// stay true independent of which types this deployment currently
			// enforces, or the record and the shadow metrics would start lying about
			// what Decide() actually decided. Only the WRITE below is gated by scoped:
			// that is the one and only place FORGET_ENFORCE_TYPES has any effect.
			if s.mode != ModeEnforce || v.Forgettable == 0 || !scoped {
				continue
			}
			ts, err := s.tombstonesFor(ctx, sw, sc, t, confirmedBefore, v.Forgettable)
			if err != nil {
				return 0, err
			}
			tombstones = append(tombstones, ts...)
		}
	}

	if err := s.store.SaveRecords(ctx, sw.ConnectorID, recs); err != nil {
		return 0, fmt.Errorf("Evaluate: %w", err)
	}
	if len(tombstones) > 0 {
		written, err := s.store.SaveTombstones(ctx, sw.ConnectorID, tombstones)
		if err != nil {
			return 0, fmt.Errorf("Evaluate: %w", err)
		}
		if s.m != nil {
			s.m.ObserveForgetTombstones(sw.ConnectorID, written)
		}
		log.FromContext(ctx).Warn().
			Str("connector_id", sw.ConnectorID).Int("tombstones", written).
			Msg("forget: ENFORCE mode recorded tombstones — assets believed gone (nothing deleted)")
	}
	return total, nil
}

// observationSkew is how far after a sweep's own clock a last_seen stamp may
// legitimately land: collection finishes, then ingest writes. Ten minutes is
// comfortably above the expected gap between a sweep's start and its ClickHouse
// write while staying far below ConfirmWindow, so it can only ever REMOVE
// candidates, never add one.
const observationSkew = 10 * time.Minute

// tombstonesFor fetches the ids behind a permitted forget. It is the only read
// that materialises ids at all, it runs only in ModeEnforce, and it runs only
// for a scope that already passed every refusal — so the fetch is bounded by
// MaxForgetPerSweep rather than by the population.
func (s *Service) tombstonesFor(ctx context.Context, sw Sweep, sc Scope, assetType string, confirmedBefore time.Time, want int) ([]Tombstone, error) {
	if want > MaxForgetPerSweep {
		// Unreachable while Evaluate applies the absolute cap, and asserted rather
		// than assumed: this is the one place a bound failure becomes a write.
		return nil, fmt.Errorf("tombstonesFor: %s/%s wants %d over the %d cap", sc.Key, assetType, want, MaxForgetPerSweep)
	}
	cands, err := s.pop.ScopeCandidateIDs(ctx, sw.ConnectorID, assetType, sc.Region, confirmedBefore, want)
	if err != nil {
		return nil, fmt.Errorf("tombstonesFor: %w", err)
	}
	out := make([]Tombstone, 0, len(cands))
	for _, c := range cands {
		out = append(out, Tombstone{
			AssetID:   c.ID,
			Scope:     sc.Key,
			AssetType: assetType,
			LastSeen:  c.LastSeen,
			GoneAt:    sw.At,
		})
	}
	return out, nil
}

func (s *Service) edgeHealth() (truncated []string, known bool) {
	if s.edges == nil {
		return nil, false
	}
	_, trunc := s.edges.EdgeSyncHealth()
	return trunc, true
}

// enforceable narrows a sweep's declared scopes to the audited families.
func enforceable(all []ScopeEnumeration) []ScopeEnumeration {
	out := make([]ScopeEnumeration, 0, len(all))
	for _, se := range all {
		if _, ok := ParseScope(se.Scope); ok {
			out = append(out, se)
		}
	}
	return out
}

// countIndex maps a (region, type) population read onto scopes. Two separate
// maps, not one keyed by "region+\x00+type" with an empty-region convention for
// the cross-region total: a genuinely region-less StoredCount row (c.Region == "",
// the GCP aggregatedList shape) would then share the accumulator's own key, and a
// write-then-read-then-add against the same key double-counts that row. See
// indexCounts' comment.
type countIndex struct {
	perRegion  map[string]StoredCount // keyed by region+"\x00"+type
	allRegions map[string]StoredCount // keyed by type — the cross-region total
}

func indexCounts(counts []StoredCount) countIndex {
	idx := countIndex{perRegion: map[string]StoredCount{}, allRegions: map[string]StoredCount{}}
	for _, c := range counts {
		idx.perRegion[c.Region+"\x00"+c.Type] = c
		// A non-region-scoped family needs the type total across every region,
		// because its enumeration covers all of them (GCP aggregatedList). Kept in
		// a SEPARATE map, keyed by type alone — not folded into perRegion under an
		// empty region string, because a genuinely region-less StoredCount row
		// (c.Region == "", exactly the GCP aggregatedList shape this exists for)
		// would then share perRegion's own key for that type. The per-region write
		// above would overwrite whatever this accumulator already held, and the
		// read-then-add below would then double that row's own contribution into
		// the total — it doubled every non-region-scoped family's
		// Stored/Absent/Confirmed count. Two maps make the collision impossible
		// rather than avoided by convention.
		all := idx.allRegions[c.Type]
		all.Type = c.Type
		all.Stored += c.Stored
		all.Absent += c.Absent
		all.Confirmed += c.Confirmed
		idx.allRegions[c.Type] = all
	}
	return idx
}

// lookup returns the population for one (scope, type). A region-scoped family
// reads its own region only; anything else reads the type total. A scope with
// no stored rows returns a zero Population, which refuses on
// RefusalTooSmall — the correct answer for a scope holding nothing.
func (idx countIndex) lookup(sc Scope, assetType string) Population {
	var c StoredCount
	if sc.Region == "" {
		c = idx.allRegions[assetType]
	} else {
		c = idx.perRegion[sc.Region+"\x00"+assetType]
	}
	return Population{Stored: c.Stored, Absent: c.Absent, Confirmed: c.Confirmed}
}
