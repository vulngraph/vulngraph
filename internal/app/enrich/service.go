package enrich

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// sourceTimeout bounds how long any single source may take; a slow source must
// not stall enrichment of the whole finding.
const sourceTimeout = 5 * time.Second

// FindingWriter persists enrichment outputs. finding.Service implements it.
//
// It deliberately has no findings-row writer. Enrich runs on a finding read at
// job start, possibly minutes earlier; a findings-row write built from that
// read carries its resolved_at/last_observed_at/severity over whatever a sync
// wrote since — reopening a finding resolved mid-enrich, or re-resolving one
// reopened mid-enrich. Enrich owns only the finding_enrichment columns.
type FindingWriter interface {
	// RecordEnrichment is the ONLY write of the enrich:"output" fields; every
	// finding reader LEFT JOINs finding_enrichment.
	RecordEnrichment(ctx context.Context, enrichments []finding.Enrichment) error
	// ByIDs re-reads a CVE finding just before the write, so a KnownExploited
	// flag the KEV refresh wrote after this enrich's read is carried forward
	// instead of overwritten (see knownExploitedSince).
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// SignalRepo persists and reads back the per-source score breakdown.
// SignalCHRepo implements it.
type SignalRepo interface {
	WriteFactors(ctx context.Context, findingID, assetID string, score Score) error
	Factors(ctx context.Context, findingID string) ([]Factor, error)
}

// BeliefInput is the enrich-side view of the facts a grounded true-severity
// belief needs. Kept primitive so enrich stays independent of the belief domain
// (a cmd-level adapter maps it to belief.SeverityInputs).
type BeliefInput struct {
	FindingID, ResourceID string
	Score                 uint8
	Band                  string
	MustFixClass          string
	MustFixReason         string
	TrustEntry            string
	// PageFloor: a source floored the score to the page band (KEV, a page
	// active-threat detection, CriticalFloor). The belief must not ground the
	// finding below that band, whatever the must-fix class says.
	PageFloor bool
	// HighFloor: a reach-independent threat or signal floor lifted the score
	// to at least the high band (a GuardDuty C&C/Backdoor detection, a live
	// leaked credential). Like PageFloor one band down: a contained/controlled
	// verdict — a claim about the internet path — must not ground below High
	// what the floor asserts regardless of that path.
	HighFloor bool
}

// BeliefFormer forms and persists a grounded true-severity belief from the enrich
// outputs. Optional and fail-open — a nil former or an error never fails enrich.
type BeliefFormer interface {
	FormBelief(ctx context.Context, in BeliefInput) error
}

type Service struct {
	findings FindingWriter
	signals  SignalRepo
	sources  []Source
	safety   FixSafetyProvider        // nil => structural safety left unknown (SafetyClass "")
	reach    ReachProvider            // nil => must-fix reachability unknown
	blast    BlastRadiusCounter       // nil => must-fix blast unknown
	scReach  SupplyChainReachProvider // nil => supply-chain must-fix reachability unknown
	rbac     RBACBindingResolver      // nil => k8s RBAC subject set unknown for Roles
	beliefs  BeliefFormer             // nil => no belief formed
	sso      SSOResolver              // nil => SSO grounding off (isControlled uses trust metadata only)
	owners   OwnerResolver            // nil => owner left unresolved (routes as unowned)
	runners  RunnerLineage            // nil => package findings keep the purl's own routing

	ownerTagKeys []string // owner tag keys for owners; nil => asset.DefaultOwnerTagKeys
	timeout      time.Duration
	now          func() time.Time

	// consistencyGate runs the per-finding scoring-consistency safety net
	// (consistency.go) before persist. Default on. consistencyShadow logs and
	// counts violations WITHOUT applying the repair — a one-sweep observability
	// mode to size the affected tail before enforcing. consistencyObserve, when
	// set, records each fired invariant to the obs counter (fail-open: nil = off).
	consistencyGate    bool
	consistencyShadow  bool
	consistencyObserve func(invariant string, n int)
}

// Option configures a Service.
type Option func(*Service)

// WithSafetyProvider enables the structural "safe to fix" signal, computed from
// the graph on every enrich (see safety.go). Without it, findings still score but
// carry no SafetyClass — exactly like a not-yet-enriched finding.
func WithSafetyProvider(p FixSafetyProvider) Option {
	return func(s *Service) { s.safety = p }
}

// WithMustFixProviders enables the evidence-backed must-fix tier: the
// reachability signal and the blast counter it weighs. Without them findings score
// normally but carry no MustFixClass. Fail-open — nil providers leave it unknown.
func WithMustFixProviders(reach ReachProvider, blast BlastRadiusCounter) Option {
	return func(s *Service) { s.reach, s.blast = reach, blast }
}

// WithSupplyChainReach enables must-fix classification for supply-chain package
// findings: package purl → dependent repos → deployed
// workloads → internet exposure. Without it, supply_chain/package findings score
// normally (SupplyChainExposure still runs) but carry no MustFixClass — the same
// fail-open contract as the other must-fix providers.
func WithSupplyChainReach(p SupplyChainReachProvider) Option {
	return func(s *Service) { s.scReach = p }
}

// WithRBACBindings enables must-fix classification for Kubernetes RBAC findings
// by resolving who actually holds a Role or ClusterRole (the `binds` edges).
// Without it, RoleBinding/ClusterRoleBinding findings still classify from their
// own subjects metadata; only Role/ClusterRole findings stay blank — the same
// fail-open contract as the other must-fix providers.
func WithRBACBindings(r RBACBindingResolver) Option {
	return func(s *Service) { s.rbac = r }
}

// WithBeliefFormer enables forming a grounded true-severity belief on
// every enrich, from the score + must-fix outputs. Fail-open — nil, or a form
// error, never fails enrichment.
func WithBeliefFormer(b BeliefFormer) Option {
	return func(s *Service) { s.beliefs = b }
}

// WithSSOResolver enables SSO-graph grounding of the must-fix
// compensating-control decision: an SSO permission set that grants admin is a
// real admin path, so its privesc finding is never demoted as "controlled".
// Fail-open — nil resolver, or an unresolved permission set, falls back to trust
// metadata (today's behaviour).
func WithSSOResolver(r SSOResolver) Option {
	return func(s *Service) { s.sso = r }
}

// WithConsistencyGate configures the per-finding scoring-consistency safety net
// (consistency.go). enabled toggles it (default on via NewService); shadow runs
// it in log/count-only mode without applying the repair, to size the affected
// tail before enforcing. observe (optional) records fired invariants to obs.
func WithConsistencyGate(enabled, shadow bool, observe func(invariant string, n int)) Option {
	return func(s *Service) {
		s.consistencyGate, s.consistencyShadow, s.consistencyObserve = enabled, shadow, observe
	}
}

// NewService wires the finding writer, the signal breakdown store, and the
// registered intelligence sources. The source slice is the single place new
// domains are added.
func NewService(findings FindingWriter, signals SignalRepo, sources []Source, opts ...Option) *Service {
	s := &Service{
		findings:        findings,
		signals:         signals,
		sources:         sources,
		timeout:         sourceTimeout,
		now:             time.Now,
		consistencyGate: true, // on by default; WithConsistencyGate can disable/shadow it
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Enrich scores one finding from all registered sources, writes the contextual
// score back onto the finding (replacing raw severity as the surfaced value),
// records the per-source breakdown, and returns the score so the caller can gate
// the decision pipeline on it.
func (s *Service) Enrich(ctx context.Context, f finding.Finding) (Score, error) {
	factors, unmeasured := s.gather(ctx, f)
	score := Aggregate(factors)

	f.Score = score.Value
	f.ScoreBand = string(score.Band)
	f.EnrichedAt = s.now()

	// The finding's asset, fetched once and shared by the safety and must-fix
	// assessments below — each doing its own point lookup saturated ClickHouse
	// (the assets sort key can't serve WHERE id = ?). The seed may legitimately
	// not exist yet (a resource not yet correlated into the graph) — a zero
	// asset, not an error, matching both assessors' fail-open semantics.
	var seed asset.Asset
	var sr seedRead
	if s.safety != nil && f.ResourceID != "" {
		seed, sr.err = s.safety.Get(ctx, f.ResourceID)
		sr.asset, sr.fetched = seed, true
	} else if s.safety != nil {
		sr.fetched = true // no resource: nothing to fetch, and nothing unmeasured
	}

	// Structural safety (safety.go) and evidence-backed must-fix (mustfix.go) are
	// independent computations over the same already-fetched seed — neither
	// reads the other's output — so they run concurrently instead of back-to-
	// back; each is itself a sequential round-trip-bearing step, and running them
	// serially under high enrich concurrency compounds into real per-finding
	// latency. Both goroutines only READ f here (assessSafety/assessMustFix take
	// it by value) and write into their OWN local variables — never into the
	// shared f — so the two concurrent reads of f never race with a write. f.*
	// fields are assigned only after wg.Wait(), once both goroutines have
	// finished.
	logger := log.FromContext(ctx)
	var sig fixSafety
	var mustFixClass, mustFixReason string
	var owner asset.Ownership
	var env string
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		// Routing context (routing.go): fail-soft to "unresolved", which routes
		// as unowned — a panic must not crash the pod or fail the score.
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", f.ID).
					Msg("enrich: owner resolution panicked; left unresolved")
			}
		}()
		owner, env = s.routingOf(ctx, f, sr, score.Value)
	}()
	go func() {
		defer wg.Done()
		// Advisory and fail-open — a nil provider, read error, or panic leaves it
		// unknown; a panic must fail this finding's assessment, not crash the pod.
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", f.ID).
					Msg("enrich: safety assessment panicked; left unknown")
			}
		}()
		sig = assessSafety(ctx, s.safety, f, seed, s.now())
	}()
	go func() {
		defer wg.Done()
		// Fail-open (nil providers or a panic → unknown class).
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", f.ID).
					Msg("enrich: must-fix assessment panicked; left unknown")
			}
		}()
		mustFixClass, mustFixReason = assessMustFix(ctx, f, seed, s.reach, s.blast, s.scReach, s.sso, s.rbac, s.now())
	}()
	wg.Wait()
	f.Dependents = clampU16(sig.Dependents)
	f.Unused = sig.Unused
	f.SafetyClass = sig.Class
	f.FixTarget = sig.FixTarget
	f.MustFixClass = mustFixClass
	f.MustFixReason = mustFixReason
	f.OwnerTeam, f.OwnerSource, f.OwnerConfidence = owner.Team, string(owner.Source), owner.Confidence
	f.Environment = env

	// Per-finding consistency safety net: catch a score/must-fix class that
	// contradicts a structural fact about the resource (e.g. an identity scored
	// as directly internet-exposed: reach poisoning). Fail-safe: it only
	// strips/demotes, never inflates. Runs on the already-computed outputs
	// before anything is persisted. When it demotes a reach-poisoned must_fix to
	// routine, the finding becomes adjudicatable downstream (belief.NeedsAdjudication),
	// so a poisoned must_fix is never stamped Critical and left unadjudicated —
	// closed at the source rather than by loosening the adjudication gate.
	if s.consistencyGate {
		cr := reconcileConsistency(f, score, f.MustFixClass, f.MustFixReason)
		if cr.Flagged() {
			for _, inv := range cr.Violations {
				if s.consistencyObserve != nil {
					s.consistencyObserve(inv, 1)
				}
				logger.Warn().
					Str("finding_id", f.ID).Str("resource_id", f.ResourceID).
					Str("resource_type", f.ResourceType).Str("invariant", inv).
					Bool("shadow", s.consistencyShadow).
					Msg("enrich: scoring-consistency invariant violated")
			}
			if !s.consistencyShadow {
				score = cr.Score
				f.Score = score.Value
				f.ScoreBand = string(score.Band)
				f.MustFixClass = cr.MustFixClass
				f.MustFixReason = cr.MustFixReason
				// INV-4 demotes an over-stated "safe to fix" claim (safe → caution);
				// every other invariant leaves it untouched.
				f.SafetyClass = cr.SafetyClass
			}
		}
	}

	// The KEV refresh may have flagged this finding after the job-start read.
	// Writing f as-is would overwrite that flag with false (the enrichment row
	// is one argMax version), so re-read it first and, if it is now flagged,
	// re-run with the flag: KEV changes the score floor and the must-fix class,
	// not just the stored bit.
	flagged, err := s.knownExploitedSince(ctx, f)
	if err != nil {
		return Score{}, fmt.Errorf("Enrich: %w", err)
	}
	if flagged {
		f.KnownExploited = true
		return s.Enrich(ctx, f)
	}

	// Writers extend their budget to finish valid computed rows. A cancelled
	// source/assessment is not a valid partial measurement to publish under that
	// fresh budget; leave the previous result intact so the job can retry.
	if err := ctx.Err(); err != nil {
		return Score{}, fmt.Errorf("Enrich: evaluation interrupted: %w", err)
	}

	// The three writes below touch three independent tables (finding_enrichment,
	// signals, beliefs) and none reads back what another just wrote, so they run
	// concurrently. RecordEnrichment/WriteFactors errors abort Enrich; a belief
	// error stays fail-open (logged, not propagated).
	var recordErr, factorsErr error
	wg.Add(3)
	go func() {
		defer wg.Done()
		// Critical path: a panic here must fail this enrichment (so the job
		// retries), not crash the pod — and never report success with no row written.
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", f.ID).Msg("enrich: record panicked")
				recordErr = fmt.Errorf("panic recording finding: %v", r)
			}
		}()
		recordErr = s.findings.RecordEnrichment(ctx, []finding.Enrichment{finding.EnrichmentOf(f)})
	}()
	go func() {
		defer wg.Done()
		// Critical path, same contract as RecordEnrichment above.
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", f.ID).Msg("enrich: write factors panicked")
				factorsErr = fmt.Errorf("panic writing factors: %v", r)
			}
		}()
		factorsErr = s.signals.WriteFactors(ctx, f.ID, f.ResourceID, score)
	}()
	go func() {
		defer wg.Done()
		// Grounded true-severity belief, from the score + must-fix
		// outputs. Fail-open: a belief error or panic must not fail enrichment.
		defer func() {
			if r := recover(); r != nil {
				logger.Error().Any("panic", r).Str("finding_id", f.ID).
					Msg("enrich: form belief panicked; skipped")
			}
		}()
		if s.beliefs == nil || f.ResourceID == "" {
			return
		}
		in := BeliefInput{
			FindingID: f.ID, ResourceID: f.ResourceID,
			Score: f.Score, Band: f.ScoreBand,
			MustFixClass: f.MustFixClass, MustFixReason: f.MustFixReason,
			TrustEntry: seed.Metadata["trust_entry"],
			PageFloor:  hasPageFloor(score.Factors),
			HighFloor:  hasReachIndependentHighFloor(score.Factors),
		}
		if err := s.beliefs.FormBelief(ctx, in); err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("finding_id", f.ID).Msg("enrich: form belief failed")
		}
	}()
	wg.Wait()
	if recordErr != nil {
		return Score{}, fmt.Errorf("Enrich: record finding: %w", recordErr)
	}
	if factorsErr != nil {
		return Score{}, fmt.Errorf("Enrich: write factors: %w", factorsErr)
	}
	score.Unmeasured = unmeasured
	score.Owner, score.Environment = owner, env
	score.MustFixClass = f.MustFixClass
	return score, nil
}

// knownExploitedSince reports whether the stored finding carries a
// KnownExploited flag that f (the job-start read) does not. Only a CVE finding
// can be KEV-flagged, so every other finding skips the read. A failed read is
// an error, not "not flagged": writing false over an unread flag is exactly
// the loss this guards against.
func (s *Service) knownExploitedSince(ctx context.Context, f finding.Finding) (bool, error) {
	if f.KnownExploited || findingCVE(f) == "" {
		return false, nil
	}
	stored, err := s.findings.ByIDs(ctx, []string{f.ID})
	if err != nil {
		return false, fmt.Errorf("re-read known_exploited: %w", err)
	}
	for _, st := range stored {
		if st.ID == f.ID && st.KnownExploited {
			return true, nil
		}
	}
	return false, nil
}

// Factors returns the per-source score breakdown recorded for a finding — the
// "why" behind its score, for the finding-detail view and MCP context.
func (s *Service) Factors(ctx context.Context, findingID string) ([]Factor, error) {
	return s.signals.Factors(ctx, findingID)
}

// gather runs every source for a finding with graceful degradation: each runs
// under its own timeout with a panic guard, and a source that errors or panics
// is logged and reported unmeasured — enrichment still produces a score from
// the rest. An erroring source's factor is kept only if it says it applied
// (a fail-safe ceiling; see Source.Evaluate).
func (s *Service) gather(ctx context.Context, f finding.Finding) (factors []Factor, unmeasured []string) {
	logger := log.FromContext(ctx)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, src := range s.sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					logger.Error().Any("panic", r).
						Str("source", src.Name()).Str("finding_id", f.ID).
						Msg("enrich source panicked; skipped")
					mu.Lock()
					unmeasured = append(unmeasured, src.Name())
					mu.Unlock()
				}
			}()

			sctx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()

			srcStart := time.Now()
			factor, applied, err := src.Evaluate(sctx, f)
			srcElapsed := time.Since(srcStart)
			if srcElapsed > 50*time.Millisecond {
				logger.Info().
					Str("source", src.Name()).
					Str("finding_id", f.ID).
					Dur("elapsed", srcElapsed).
					Msg("enrich source slow")
			}
			if err != nil {
				ev := logger.Warn()
				if errors.Is(err, ErrSourceNotReady) {
					ev = logger.Debug()
				}
				ev.Err(err).Str("source", src.Name()).Str("finding_id", f.ID).
					Msg("enrich source unmeasured; degrading")
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				unmeasured = append(unmeasured, src.Name())
			}
			if applied {
				factors = append(factors, factor)
			}
		}()
	}
	wg.Wait()
	sort.Strings(unmeasured)
	return factors, unmeasured
}
