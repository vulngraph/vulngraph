package respond

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/internal/policy"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// blastDepth is how deep the blast-radius walk goes when sizing an action.
// Aliases graphschema.BlastDepth (the single source of truth shared with
// enrich's must-fix/scoring walk) rather than redeclaring the literal — see
// that constant's doc for why the two must never drift independently.
const blastDepth = graphschema.BlastDepth

// maxCacheAge re-reasons a finding regardless of fingerprint once its cached
// decision is older than this — a belt-and-suspenders against a fingerprint that
// fails to capture some drift.
const maxCacheAge = 7 * 24 * time.Hour

// Reasoner proposes a Plan for a finding given its connected-graph context.
// internal/reason implements it with Anthropic; tests use a fake.
type Reasoner interface {
	Reason(ctx context.Context, pack ContextPack) (Plan, error)
}

// Gate is the policy decision. internal/policy.Gate implements it.
type Gate interface {
	Evaluate(ctx context.Context, in policy.Input) (policy.Decision, error)
}

// ConfidenceProvider scores autonomy confidence. memory.Service implements it.
type ConfidenceProvider interface {
	Confidence(ctx context.Context, actionClass, assetType string) (memory.Confidence, error)
}

// BlastRadiusProvider sizes an action's reach. asset.Service implements it.
// ResolveID canonicalizes finding.ResourceID to an asset ID before the walk:
// aws_guardduty iam_user findings carry the role NAME, not the ARN the graph is
// keyed by, and an unresolved seed walks from a non-existent node — reporting a
// zero blast radius for a live compromise.
type BlastRadiusProvider interface {
	BlastRadius(ctx context.Context, seedID string, maxDepth int) (asset.BlastRadius, error)
	ResolveID(ctx context.Context, identifier string) (string, error)
}

// AuditRecorder persists the decision trail. CHRepo implements it.
type AuditRecorder interface {
	Record(ctx context.Context, e AuditEvent) error
}

// ReasoningCache gates the LLM call: the last plan + context fingerprint per
// finding. Optional — a nil cache disables the gate (every Decide
// reasons).
type ReasoningCache interface {
	Get(ctx context.Context, findingID string) (reasoncache.Entry, error)
	Put(ctx context.Context, e reasoncache.Entry) error
}

// ActionApplicability answers whether an executable remediation action exists
// for a resource type. internal/app/executor's action registry is the single
// source of truth for what can actually run — respond never imports executor
// directly (layering: domains talk through service interfaces, never each
// other's internals), so this capability is wired in at construction via
// WithExecutorCapability. Nil disables the check: every remediate/modify plan
// is left as-is.
type ActionApplicability interface {
	HasExecutableAction(resourceType string) bool
}

// ActionApplicabilityFunc adapts a plain func to ActionApplicability, so the
// caller wiring respond up (cmd/graph) can pass executor.HasExecutableAction
// directly without a named adapter type on either side.
type ActionApplicabilityFunc func(resourceType string) bool

// HasExecutableAction implements ActionApplicability.
func (f ActionApplicabilityFunc) HasExecutableAction(resourceType string) bool {
	return f(resourceType)
}

type Service struct {
	reasoner   Reasoner
	gate       Gate
	confidence ConfidenceProvider
	blast      BlastRadiusProvider
	audit      AuditRecorder
	cache      ReasoningCache
	peers      Peers
	lineage    Lineage
	now        func() time.Time

	// execCap answers whether a plan's action class has any wired executor
	// action for the finding's resource type. Nil = disabled (no
	// annotation). Set via WithExecutorCapability.
	execCap ActionApplicability

	// patternVerdicts answers whether a human governor already ruled on this
	// finding's (check_id, action_class) pattern. Nil = disabled (no lookup,
	// no suppression, no annotation). Set via WithPatternVerdicts.
	patternVerdicts PatternVerdicts

	// repeatTracker records cache-hit skip-path repeats onto the reasoning
	// cache's repeat counter. Nil = disabled (no counting, the
	// escalation-hotspot panel falls back to the audit-trail count). Set via
	// WithRepeatTracker.
	repeatTracker RepeatTracker

	// Optional enrichment seams — nil = skip that section of the context pack.
	factors  FactorsReader // per-source score breakdown from signals table
	epss     EPSSScorer    // live EPSS probability from in-memory cache
	outEdger OutEdger      // outgoing edge lookups for identity chain + supply-chain path

	// notifier receives each audited decision; the receivers filter (webhook and
	// Slack take Notifiable decisions, email only parked ones). Nil = disabled.
	// Set via WithDecisionWebhook.
	notifier DecisionNotifier

	// reasonCacheObserver records each planFor cache hit/miss. Nil = disabled.
	// Set via WithReasonCacheMetrics.
	reasonCacheObserver ReasonCacheObserver
}

// ReasonCacheObserver records planFor's cache hit/miss outcome. *obs.Metrics
// satisfies it (ObserveReasonCacheLookup) — defined here, not imported from
// internal/obs, so this domain's service.go stays free of an infra import;
// the concrete metrics type is wired in from the jobs layer via
// WithReasonCacheMetrics.
type ReasonCacheObserver interface {
	ObserveReasonCacheLookup(hit bool)
}

// NewService builds the decision engine. It takes no outcome recorder on
// purpose: a decision is a proposal, not a result, so nothing Decide concludes
// may feed decaying memory — only a human verdict does (govern.Resolve).
func NewService(r Reasoner, g Gate, c ConfidenceProvider, b BlastRadiusProvider, a AuditRecorder, cache ReasoningCache, peers Peers, lineage Lineage) *Service {
	return &Service{reasoner: r, gate: g, confidence: c, blast: b, audit: a, cache: cache, peers: peers, lineage: lineage, now: time.Now}
}

// NewReadService builds a Service for the read-only Context path only (the
// finding-detail view / MCP). It wires just the graph seams buildContextPack
// needs — Decide and the LLM/gate are not available on it. The serve process
// uses this so it doesn't have to construct the full decision engine.
func NewReadService(b BlastRadiusProvider, peers Peers, lineage Lineage) *Service {
	return &Service{blast: b, peers: peers, lineage: lineage, now: time.Now}
}

// WithFactors wires the per-source score breakdown reader. Enables the "Score
// breakdown" section in the reason prompt. Call before Decide/Context.
func (s *Service) WithFactors(f FactorsReader) *Service { s.factors = f; return s }

// WithEPSS wires the live EPSS exploit-probability cache. Enables the "CVE
// context" block for CVE-keyed findings. Call before Decide/Context.
func (s *Service) WithEPSS(e EPSSScorer) *Service { s.epss = e; return s }

// WithOutEdger wires the outgoing-edge resolver used for identity-chain and
// supply-chain blast-path enrichment. Call before Decide/Context.
func (s *Service) WithOutEdger(o OutEdger) *Service { s.outEdger = o; return s }

// WithDecisionWebhook wires the decision notification. When set, every
// decision Decision.Notifiable accepts (a non-observe plan, or an observe plan
// a guardrail escalated: a proposal awaiting a human, never an authorisation
// to act) is sent to the notifier after the audit event is recorded. Errors are logged and swallowed — a webhook failure
// must never fail an audited decision.
func (s *Service) WithDecisionWebhook(n DecisionNotifier) *Service { s.notifier = n; return s }

// WithReasonCacheMetrics wires the planFor cache hit/miss counter. Call
// before Decide.
func (s *Service) WithReasonCacheMetrics(o ReasonCacheObserver) *Service {
	s.reasonCacheObserver = o
	return s
}

// WithExecutorCapability wires the executor's action registry so Decide can
// annotate a remediate/modify plan when no executor action can execute it.
// Call before Decide.
func (s *Service) WithExecutorCapability(c ActionApplicability) *Service {
	s.execCap = c
	return s
}

// blastRadiusFor walks the blast radius for a finding's resource. The raw
// ResourceID is tried first: every source that keys findings by asset ID hits
// on that attempt and pays nothing extra. Only a seed miss falls back to
// ResolveID, because a miss is the signature of a name-keyed source
// (aws_guardduty iam_user carries the role NAME, not the ARN the graph is
// keyed by). This keeps ResolveID's substring search off the hot path: it
// runs once per genuinely unresolvable finding, not once per Decide.
//
// The second return is whether the walk MEASURED anything, and it is the
// whole point of this signature. A failed walk produces asset.BlastRadius{},
// which would otherwise reach the approver, the reasoner and the reasoning
// cache indistinguishable from a real zero — "touches nothing" is the reading
// most likely to get a risky change approved, so a measurement failure must
// never read as evidence there was nothing to see. The caller cannot reach the
// count without also being handed the known-ness.
func (s *Service) blastRadiusFor(ctx context.Context, resourceID string) (radius asset.BlastRadius, known bool) {
	if br, err := s.blast.BlastRadius(ctx, resourceID, blastDepth); err == nil {
		return br, true
	}
	resolved, err := s.blast.ResolveID(ctx, resourceID)
	if err != nil || resolved == resourceID {
		// Not fatal, but not a measurement either: the action is sized by a human.
		return asset.BlastRadius{}, false
	}
	br, err := s.blast.BlastRadius(ctx, resolved, blastDepth)
	if err != nil {
		return asset.BlastRadius{}, false
	}
	log.FromContext(ctx).Debug().
		Str("resource_id", resourceID).Str("resolved_asset_id", resolved).
		Int("blast_count", len(br.Assets)).
		Msg("respond: seeded blast radius from resolved asset id")
	return br, true
}

// Decide handles one finding end-to-end: reason -> confidence -> blast radius ->
// policy gate -> outcome, recording an audit event. It proposes and never
// executes: a state-changing plan is parked for a human or escalated, and runs
// only after a human approves it through the executor (ADR 087).
func (s *Service) Decide(ctx context.Context, f finding.Finding) (Decision, error) {
	// Blast radius first — it both sizes the action and feeds the change
	// fingerprint that gates the (expensive) LLM call.
	// blastKnown stays false when there is no resource to walk from, which is the
	// same answer as a failed walk and for the same reason: nothing measured the
	// radius. It travels with the count to the decision, the cache and the
	// approver, never inferred downstream from blastCount == 0.
	var br asset.BlastRadius
	var blastKnown bool
	if f.ResourceID != "" {
		blastStart := time.Now()
		br, blastKnown = s.blastRadiusFor(ctx, f.ResourceID)
		if elapsed := time.Since(blastStart); elapsed > 100*time.Millisecond {
			log.FromContext(ctx).Info().
				Str("finding_id", f.ID).
				Dur("blast_elapsed", elapsed).
				Int("blast_count", len(br.Assets)).
				Msg("respond: slow blast radius walk")
		}
	}
	// Excludes the seed asset — see reachableAssets' doc: this count is what
	// the approver reads as the action's reach (Decision, reasoncache.Entry).
	blastCount := len(reachableAssets(br.Assets))
	if !blastKnown {
		log.FromContext(ctx).Warn().
			Str("finding_id", f.ID).Str("resource_id", f.ResourceID).
			Msg("respond: blast radius unmeasured — the approver sees it as unmeasured, not zero")
	}

	// Assemble the connected-graph context once — it feeds both the reasoner
	// (so it judges over the graph) and the change fingerprint that gates it.
	pack := s.buildContextPack(ctx, f, br, blastKnown, nil, false) // prefetchedPeersKnown unused: nil peers means "fetch it yourself"
	// Factors load before the fingerprint: FactorsKnown is one of its inputs,
	// so a plan reasoned while the breakdown was unreadable is not reused once
	// it is readable.
	s.loadFactors(ctx, &pack)

	// Reason only when the finding's context changed since last time. On a
	// fingerprint hit we reuse the cached plan and skip the LLM, but still run
	// confidence/gate/CoVe below — a policy change must never be masked. Only
	// the RECORDING (audit + notify) of an unchanged
	// conclusion is skipped, further down, once the freshly recomputed
	// outcome is compared against the cached one — every step through the
	// gate still runs on every Decide.
	fp := reasoncache.Fingerprint(reasoncache.FingerprintInput{
		FindingID: f.ID, CheckID: f.CheckID, Type: f.Type,
		ScoreBand: f.ScoreBand, KnownExploited: f.KnownExploited,
		BlastAssetIDs: assetIDs(br.Assets), BlastTruncated: br.Truncated, SeedID: f.ResourceID,
		Extra: pack.fingerprintExtra(),
	})
	plan, reused, cachedEntry, err := s.planFor(ctx, &pack, fp)
	if err != nil {
		return Decision{}, err
	}

	// Note when a remediate/modify plan targets a resource type the
	// in-cluster executor has no wired action for — useful triage context on
	// the decision ("a human or the webhook consumer has to carry this one").
	//
	// This ANNOTATES and nothing else — it must never downgrade the plan to
	// observe. The executor registry covers only a handful of resource
	// types, far fewer than findings target; downgrading on that gap would
	// relabel most actionable findings as observe, which needs no approval and
	// so drops them out of the human governor queue.
	// A public RDS instance or a privileged pod still needs a human even
	// though no in-cluster action can execute it — the real handoff is the
	// webhook to the external remediation service, whose capability set this
	// registry does not describe.
	var planNotes []string
	if s.execCap != nil && (plan.ActionClass == ClassRemediate || plan.ActionClass == ClassModify) &&
		!s.execCap.HasExecutableAction(f.ResourceType) {
		planNotes = append(planNotes, fmt.Sprintf(
			"no in-cluster executor action for %s — execution needs the webhook consumer or a human", f.ResourceType))
	}

	// Pattern verdict: has a human governor already ruled on this whole
	// (check_id, action_class, resource_type) pattern, independent of this
	// specific finding? Checked BEFORE the confidence/gate/CoVe pipeline
	// below, so a denied pattern short-circuits cleanly without paying for
	// any of it. Scoped by f.ResourceType: a denial recorded for s3_bucket
	// must never suppress the same (check, action) pair on rds_instance.
	//
	// A verdict is evidence that a human already ruled — never standing
	// consent to act. APPROVED only annotates (each change still needs its
	// own human yes, ADR 087). DENIED suppresses only when it holds for every
	// class (see patternRulingFor): the class is the reasoner's choice, so a
	// denial of that class alone is annotated and the finding still reaches a
	// person. Nothing wired, no verdict, an expired one or a lookup error all
	// fail open: the decision proceeds as if no verdict existed.
	var deniedUrgent string
	if s.patternVerdicts != nil {
		switch s.patternRulingFor(ctx, f, plan.ActionClass) {
		case rulingDeniedAll:
			if UrgentEvidence(f) == "" {
				return s.decideSuppressedByVerdict(ctx, f, plan, planNotes, blastCount, pack, fp, reused, cachedEntry)
			}
			// A denial must not silence a finding the evidence calls urgent
			// for 90 days. It goes to a person, with the denial on record.
			deniedUrgent = UrgentEvidence(f)
		case rulingDeniedOne:
			planNotes = append(planNotes,
				"pattern previously denied by a human governor for this check and action class — not suppressed, "+
					"because the action class is the reasoner's choice and other classes for this check are not denied")
		case rulingApproved:
			planNotes = append(planNotes,
				"pattern previously approved by a human governor for this check and action class")
		}
	}

	conf, err := s.confidence.Confidence(ctx, string(plan.ActionClass), f.ResourceType)
	if err != nil {
		return Decision{}, fmt.Errorf("Decide: confidence: %w", err)
	}

	gateDecision, err := s.gate.Evaluate(ctx, policy.Input{
		ActionClass:    string(plan.ActionClass),
		ConfidenceBand: string(conf.Band),
	})
	if err != nil {
		return Decision{}, fmt.Errorf("Decide: gate: %w", err)
	}

	// CoVe: structural guardrails over the plan. A concern forces human
	// escalation regardless of what the gate would allow — fail-closed.
	cove := verify(plan, f, br, conf)
	// Grounding: a rationale that cites an asset the reasoner was never
	// shown is a possible hallucination — escalate rather than park it as routine.
	if gc := groundingConcerns(plan, pack); len(gc) > 0 {
		cove.concerns = append(cove.concerns, gc...)
		cove.escalate = true
	}
	if deniedUrgent != "" {
		cove.concerns = append(cove.concerns, "pattern previously denied by a human governor, but this is a "+
			deniedUrgent+" finding — a human must confirm the denial still applies")
		cove.escalate = true
	}
	outcome := outcomeFor(gateDecision)
	if cove.escalate {
		outcome = OutcomeEscalated
	}

	// An escalated decision says WHY, so a human triaging the trail doesn't
	// have to reconstruct it from the other fields.
	//
	// The reason names what actually CAUSED the escalation, which is why it
	// keys off the gate's own verdict rather than the class alone. For
	// destroy/isolate at high confidence the gate returns needs_approval, not
	// escalate — a CoVe concern is what turned "park for approval" into
	// "escalate", and labelling that policy_blocked would
	// point the triager at the wrong cause. So: policy_blocked only when the
	// gate itself escalated a destructive class; verification_concern when
	// CoVe flipped a non-escalating gate verdict.
	var escalationReason string
	if outcome == OutcomeEscalated {
		gateEscalated := outcomeFor(gateDecision) == OutcomeEscalated
		switch {
		case gateEscalated && (plan.ActionClass == ClassDestroy || plan.ActionClass == ClassIsolate):
			escalationReason = "policy_blocked"
		case gateEscalated:
			escalationReason = "insufficient_confidence"
		default:
			escalationReason = "verification_concern"
		}
	}

	// Safety band folds the chosen action into the structural impact — advisory
	// only for now (surfaced for triage / quick-wins). Feeding it into the policy
	// gate above is a deliberate future step, not wired here.
	safety := safetyBand(plan.ActionClass, pack.Impact, pack.Exposure, pack.Provenance)

	d := Decision{
		FindingID:        f.ID,
		Plan:             plan,
		ConfidenceBand:   string(conf.Band),
		ConfidenceScore:  conf.Score,
		EffectiveN:       conf.EffectiveN,
		SampleCount:      conf.SampleCount,
		BlastRadius:      blastCount,
		BlastRadiusKnown: blastKnown,
		CoVeConcerns:     cove.concerns,
		PlanNotes:        planNotes,
		EscalationReason: escalationReason,
		SafetyBand:       safety,
		FixLocation:      pack.Impact.FixLocation,
		Outcome:          outcome,
		DecidedAt:        s.now(),
		Fingerprint:      fp,
	}

	// A cache hit that reaches every one of the same conclusions as the
	// cached entry is a no-op repeat — the periodic sweep re-confirming
	// something nothing challenged — and is not re-recorded, to avoid
	// audit-row inflation. Anything that DIVERGED is never masked: it is
	// recorded and the cache entry refreshed, so the next sweep compares
	// against the new state instead of re-recording forever.
	//
	// The comparison covers outcome, action class, confidence band AND the
	// CoVe concern set, because outcome alone is too coarse: neither raw
	// score nor blast edge types are in the reason fingerprint, so a finding
	// can newly trip the CoVe circuit breaker — or flip insufficient→high
	// confidence while CoVe keeps it escalated — with outcome and class
	// unchanged. Those are the guardrail events an audit trail exists for,
	// and the skip would have hidden them permanently. EscalationReason
	// derives from exactly these inputs (gate outcome, class, CoVe), so it is
	// covered transitively.
	skipRecord := reused &&
		cachedEntry.Outcome == string(d.Outcome) &&
		cachedEntry.ActionClass == string(plan.ActionClass) &&
		cachedEntry.ConfidenceBand == d.ConfidenceBand &&
		concernDigest(cachedEntry.CoVeConcerns) == concernDigest(cove.concerns)

	if !skipRecord {
		// No memory outcome is written here, by design: a decision is a
		// proposal, and nothing ran. Decaying memory learns only from a human
		// verdict (govern.Resolve), so the pipeline can never vouch for itself.
		if err := s.audit.Record(ctx, auditFor(d)); err != nil {
			return Decision{}, fmt.Errorf("Decide: audit: %w", err)
		}

		// Decision notification: hand the audited decision to the configured
		// receivers, which decide whether to send it. It carries no authority to
		// act. Best-effort — a receiver failure must not fail an audited decision.
		if s.notifier != nil {
			if err := s.notifier.Notify(ctx, f, d, pack); err != nil {
				_ = err // the injected notifier (cmd/graph multiDecisionNotifier) logs failures
			}
		}
	} else if s.repeatTracker != nil {
		// This IS the repeat — a byte-identical conclusion that is
		// deliberately not audited above. Register it on the reasoning cache's
		// counter so the escalation-hotspot panel can still see it. Best-effort:
		// a counter miss must never fail an already-decided outcome.
		if err := s.repeatTracker.IncrementRepeat(ctx, f.ID); err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("finding_id", f.ID).
				Msg("respond: increment repeat counter failed")
		}
	}

	// Cache this reasoning so the next sweep skips the LLM until context
	// changes. Written on every fresh reason, and also on a reuse whose
	// conclusions diverged (skipRecord false) so the cache reflects the state
	// just recorded, not the stale one it was compared against. A reuse that
	// matched already has a current-enough entry — best-effort, a cache write
	// failure must not fail an audited decision.
	//
	// DecidedAt is the REASONING timestamp, so a reuse keeps the cached one:
	// maxCacheAge is measured against it (the forced re-reason), and
	// refreshing it on every divergence would let a finding whose outcome
	// flips frequently keep its original LLM plan text forever. Only a fresh
	// reason moves it.
	if s.cache != nil && (!reused || !skipRecord) {
		decidedAt := d.DecidedAt
		if reused {
			decidedAt = cachedEntry.DecidedAt
		}
		_ = s.cache.Put(ctx, reasoncache.Entry{
			FindingID:        f.ID,
			Fingerprint:      fp,
			ActionClass:      string(plan.ActionClass),
			Summary:          plan.Summary,
			Rationale:        plan.Rationale,
			Outcome:          string(outcome),
			ConfidenceBand:   string(conf.Band),
			ConfidenceScore:  conf.Score,
			EffectiveN:       conf.EffectiveN,
			SampleCount:      conf.SampleCount,
			BlastRadius:      blastCount,
			BlastRadiusKnown: blastKnown,
			CoVeConcerns:     cove.concerns,
			EscalationReason: escalationReason,
			SafetyBand:       safety,
			DecidedAt:        decidedAt,
		})
	}

	return d, nil
}

// Context assembles the connected-graph context for a finding without deciding
// — the read path for the finding-detail view and MCP (reuses the same blast
// walk + pack assembly Decide uses, so there is one source of context).
// Unlike Decide (sequential pipeline), Context pre-fetches peers concurrently
// with the blast walk — the expensive full-table peer scan does not add to
// wall-clock time; it overlaps with the BFS.
func (s *Service) Context(ctx context.Context, f finding.Finding) (ContextPack, error) {
	var (
		br         asset.BlastRadius
		blastKnown bool
		peers      []finding.Finding
		// peersKnown mirrors blastKnown for the peer-findings query below.
		// Without it, a failed peer query would be normalized into an
		// empty-but-not-nil slice at the end of this method and read by
		// buildContextPack as "successfully queried, found nothing". Starts
		// true: if
		// s.peers is nil (feature not wired) or there's no ResourceID, the
		// peers goroutine below never even runs, and "nothing to know" is
		// correctly known, not unknown.
		peersKnown = true
		wg         sync.WaitGroup
	)
	logger := log.FromContext(ctx)

	if f.ResourceID != "" {
		wg.Go(func() {
			// Best-effort: a panic in the blast walk must not crash the serve pod.
			defer func() {
				if r := recover(); r != nil {
					logger.Error().Any("panic", r).Str("resource_id", f.ResourceID).Msg("respond: blast radius panicked; skipped")
				}
			}()
			// Context is the read path: nothing gates on the radius here, so an
			// unmeasured walk is reported rather than refused. It is still not
			// dropped — "0 reachable assets" rendered into an LLM-facing pack is
			// the same lie here as at the gate, just without the mutation — and
			// blastKnown is carried into the pack (BlastSummary.Known) so the
			// finding-detail UI can render "unmeasured" instead of a bare 0.
			if br, blastKnown = s.blastRadiusFor(ctx, f.ResourceID); !blastKnown {
				logger.Warn().Str("resource_id", f.ResourceID).
					Msg("respond: blast radius unmeasured — context pack reports an unwalked radius")
			}
		})
		if s.peers != nil {
			wg.Go(func() {
				// peersKnown starts true (see its doc above) for the "goroutine
				// never runs" case — a panic here is a THIRD state (ran, but
				// produced nothing usable) and must land on the same unsafe-value
				// side as a query error, not fall through to the true default
				// meant for "nothing to know". Without this, a panic in
				// s.peers.List (a nil map, a driver panic) silently reported
				// "successfully queried, found nothing" — the exact known-ness
				// gap this goroutine's error branch exists to close, missed on
				// its recover path.
				defer func() {
					if r := recover(); r != nil {
						peersKnown = false
						logger.Error().Any("panic", r).Str("resource_id", f.ResourceID).Msg("respond: peer fetch panicked; skipped")
					}
				}()
				if p, err := s.peers.List(ctx, finding.Filter{ResourceID: f.ResourceID, Limit: 200}); err == nil {
					peers = p
				} else {
					// A failed query must not read the same as "queried,
					// found nothing" — carried into ExposureFlags.PeersKnown
					// via buildContextPack below, then into
					// GroundingFacts.ExposurePeersLookupFailed for the
					// belief adjudicator's corroboration gate, exactly the
					// same treatment the blast-radius walk already gets.
					peersKnown = false
					logger.Warn().Err(err).Str("resource_id", f.ResourceID).
						Msg("respond: peer findings query failed — context pack reports an unqueried peer set")
				}
			})
		}
	}
	wg.Wait()

	// Non-nil peers tells buildContextPack to skip its own fetch.
	if peers == nil {
		peers = []finding.Finding{}
	}
	return s.buildContextPack(ctx, f, br, blastKnown, peers, peersKnown), nil
}

// planFor reuses the cached plan when the context fingerprint is unchanged
// and fresh (skipping the LLM), otherwise calls the reasoner. Cache read
// errors fail open — we reason rather than block a decision. It returns the
// plan, whether it was reused, and the PRIOR cache entry — populated
// whenever one exists, even on a miss (stale fingerprint, or past
// maxCacheAge), not only on a hit. Decide compares the prior entry's
// Outcome/ActionClass against the freshly recomputed decision to tell a
// byte-identical repeat from a genuine change; callers that carry
// measurements forward across a skip (decideSuppressedByVerdict) need it on
// a miss too, since the entry existing is what tells them this finding had
// real measurements a moment ago, independent of whether this call reasons
// fresh.
func (s *Service) planFor(ctx context.Context, pack *ContextPack, fp string) (Plan, bool, reasoncache.Entry, error) {
	var prior reasoncache.Entry
	if s.cache != nil {
		if cached, err := s.cache.Get(ctx, pack.Finding.ID); err == nil {
			prior = cached
			if cached.Fingerprint == fp && s.now().Sub(cached.DecidedAt) < maxCacheAge {
				s.observeReasonCacheLookup(true)
				return Plan{
					ActionClass: ActionClass(cached.ActionClass),
					Summary:     cached.Summary,
					Rationale:   cached.Rationale,
				}, true, cached, nil
			}
		}
	}
	s.observeReasonCacheLookup(false)
	plan, err := s.reasoner.Reason(ctx, *pack)
	if err != nil {
		return Plan{}, false, reasoncache.Entry{}, fmt.Errorf("Decide: reason: %w", err)
	}
	return plan, false, prior, nil
}

// loadFactors fills pack.Factors and pack.FactorsKnown. A failed read, or no
// reader wired, leaves FactorsKnown false so the reasoner is told the score
// breakdown is unknown rather than shown a score with no explanation as if
// nothing contributed to it.
func (s *Service) loadFactors(ctx context.Context, pack *ContextPack) {
	if s.factors == nil {
		return
	}
	factors, err := s.factors.Factors(ctx, pack.Finding.ID)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("finding_id", pack.Finding.ID).
			Msg("respond: score factors read failed — the reasoner sees the breakdown as unknown")
		return
	}
	pack.Factors, pack.FactorsKnown = factors, true
}

func (s *Service) observeReasonCacheLookup(hit bool) {
	if s.reasonCacheObserver != nil {
		s.reasonCacheObserver.ObserveReasonCacheLookup(hit)
	}
}

func assetIDs(assets []asset.Asset) []string {
	ids := make([]string, 0, len(assets))
	for _, a := range assets {
		ids = append(ids, a.ID)
	}
	return ids
}

// outcomeFor maps the gate's verdict to an outcome. AllowAuto is granted only
// to read-only observe plans, so it maps to OutcomeObserved: there is nothing
// to change, and nothing is executed.
func outcomeFor(d policy.Decision) Outcome {
	switch {
	case d.AllowAuto:
		return OutcomeObserved
	case d.NeedsApproval:
		return OutcomeParked
	default:
		return OutcomeEscalated
	}
}

// concernDigestNumber matches the volatile numeric fragments cove.go's
// concern strings embed (e.g. "weighted blast radius 10.4 ≥ 10.0", "68
// reachable assets with enriched score 80") — the exact GUARDRAIL that
// tripped, not the exact number that tripped it, is the identity
// concernDigest exists to compare.
var concernDigestNumber = regexp.MustCompile(`\d+(\.\d+)?`)

// concernDigest is an order-independent identity for a CoVe concern set, used
// to tell "the same guardrails as last sweep" from "a guardrail just
// tripped". Sorted before joining: verify() builds the slice from
// independent checks and their order is not a contract, so an order flip
// must not read as a change.
//
// Numbers are stripped from each concern string before hashing — cove.go's
// checks interpolate the exact score/blast-radius/threshold values that
// tripped them, and those wiggle sweep to sweep (score 81 -> 80, blast 68 ->
// 67) without the guardrail's IDENTITY changing at all. Hashing the raw
// prose made a same-band score drift look like "a new decision", producing
// a duplicate audit row and a duplicate re-notify to the decision webhook
// for a repeat that skipRecord was specifically built to suppress. This is
// the same "key on fact identity, not rendered prose" principle as
// belief.dedupeEvidence's (Source, Fact) fix, applied here since these
// concern strings have no separate stable-kind field to key on instead.
//
// Side effect worth stating plainly rather than leaving implicit: \d+ also
// erases the numeric octets of an IP address, so Check 3's "%s action on an
// internet-facing asset (%s)" (cove.go, seedPublicIP) hashes identically for
// EVERY public IP once normalized — the digest cannot distinguish
// "still 203.0.113.5" from "now 198.51.100.9, a different public IP" as a
// changed decision. Defensible for the same reason the number-stripping
// exists at all: the guardrail's identity is "this action class trips the
// internet-facing check", not which address it happened to see this sweep —
// re-notifying on every DNS/IP churn of an already-flagged resource would be
// exactly the audit-row/re-notify duplication this function exists to
// suppress, just on a different axis. Stated here because it is easy to
// rediscover as a surprise rather than a design decision.
func concernDigest(concerns []string) string {
	if len(concerns) == 0 {
		return ""
	}
	normalized := make([]string, len(concerns))
	for i, c := range concerns {
		normalized[i] = concernDigestNumber.ReplaceAllString(c, "#")
	}
	sort.Strings(normalized)
	return strings.Join(normalized, "\x1f")
}

func auditFor(d Decision) AuditEvent {
	details, _ := json.Marshal(map[string]any{
		"action_class":       string(d.Plan.ActionClass),
		"summary":            d.Plan.Summary,
		"rationale":          d.Plan.Rationale,
		"confidence_band":    d.ConfidenceBand,
		"confidence_score":   d.ConfidenceScore,
		"effective_n":        d.EffectiveN,
		"sample_count":       d.SampleCount,
		"blast_radius":       d.BlastRadius,
		"blast_radius_known": d.BlastRadiusKnown,
		"cove_concerns":      d.CoVeConcerns,
		"plan_notes":         d.PlanNotes,
		"escalation_reason":  d.EscalationReason,
		"safety_band":        d.SafetyBand,
		"fix_location":       d.FixLocation.fixLocationJSON(),
		"outcome":            string(d.Outcome),
	})
	return AuditEvent{
		TS:         d.DecidedAt,
		Actor:      "agent",
		Action:     "decision",
		TargetType: "finding",
		TargetID:   d.FindingID,
		Details:    string(details),
	}
}
