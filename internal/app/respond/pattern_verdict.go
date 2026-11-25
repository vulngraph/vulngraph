package respond

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// RepeatTracker records that Decide's cache-hit skip path took a
// byte-identical repeat — the escalation-hotspot panel
// (respond.Handler.DecisionsSummary) reads reasoncache's repeat counters
// instead of the audit trail precisely because the skip path never writes
// its own audit row, so something has to register the repeat or the panel
// goes blind. reasoncache.Service implements it.
//
// Deliberately its OWN interface rather than a third method bolted onto
// ReasoningCache: Get/Put are the stable read/write contract every existing
// cache test double already satisfies, while this is a narrow, additive
// telemetry side effect that only the skip path needs. Nil disables it (no
// counting), matching every other optional seam on this Service.
type RepeatTracker interface {
	IncrementRepeat(ctx context.Context, findingID string) error
}

// patternVerdictApproved and patternVerdictDenied are the only verdict
// strings Decide acts on. A third value ("risk_accepted") exists in
// govern.Verdict but govern.PGRepo never writes it to pattern_verdicts (it
// needs expiry/scope semantics that don't exist yet), so it is deliberately
// not given a case here: an unrecognized string behaves exactly like "no
// verdict found" (fail open), never like a ruling.
const (
	patternVerdictApproved = "approved"
	patternVerdictDenied   = "denied"
)

// PatternVerdicts answers whether a human governor already ruled on a whole
// (check_id, action_class, resource_type) pattern, independent of any one
// finding. internal/app/govern.Service.PatternVerdict is the source of
// truth, but govern already imports respond (for respond.AuditEvent), so
// respond importing govern back would cycle. cmd/graph wires this with a
// closure over govern.Service.PatternVerdict that converts govern.Verdict to
// a plain string, so this interface (and this package) stays free of a
// govern import. Nil disables the lookup: no decision consults a pattern
// verdict. resourceType scopes the lookup — a
// ruling on s3_bucket must never suppress rds_instance under the same
// (check, action) pair.
type PatternVerdicts interface {
	// PatternVerdict returns the verdict string for (checkID, actionClass,
	// resourceType), when it was decided, and whether one was found. A
	// sentinel-error-free "not found" contract, matching
	// govern.Service.PatternVerdict. decidedAt lets Decide refuse to act on
	// a verdict older than PatternVerdictMaxAge.
	PatternVerdict(ctx context.Context, checkID, actionClass, resourceType string) (verdict string, decidedAt time.Time, found bool, err error)
}

// PatternVerdictsFunc adapts a plain func to PatternVerdicts, so cmd/graph
// can pass a closure directly without a named adapter type on either side.
type PatternVerdictsFunc func(ctx context.Context, checkID, actionClass, resourceType string) (string, time.Time, bool, error)

// PatternVerdict implements PatternVerdicts.
func (f PatternVerdictsFunc) PatternVerdict(ctx context.Context, checkID, actionClass, resourceType string) (string, time.Time, bool, error) {
	return f(ctx, checkID, actionClass, resourceType)
}

// patternRuling is what Decide does with the pattern verdicts for a finding.
type patternRuling int

const (
	rulingNone      patternRuling = iota // no live verdict for the chosen class: decide as usual
	rulingApproved                       // annotate only — an approval is never standing consent
	rulingDeniedOne                      // the chosen class is denied, but not every class: annotate, a human still sees it
	rulingDeniedAll                      // every class for (check_id, resource_type) is denied: suppress
)

// patternClasses is every action class a human can rule on for a pattern.
// observe is included because an escalated observe plan reaches the queue too.
var patternClasses = []ActionClass{ClassObserve, ClassRemediate, ClassModify, ClassIsolate, ClassDestroy}

// patternRulingFor consults the pattern verdicts for f. Only check_id and
// resource_type are deterministic finding attributes; the action class is the
// reasoner's choice, which injected scan text can steer. So a denial of the
// chosen class alone must never suppress — that would let the model pick a
// denied class and silence the finding for PatternVerdictMaxAge. Suppression
// needs a live denial for EVERY class under (check_id, resource_type), which
// makes the outcome independent of which class the model picked. A lookup
// error or an expired verdict counts as no verdict (fail open: decide as usual).
func (s *Service) patternRulingFor(ctx context.Context, f finding.Finding, chosen ActionClass) patternRuling {
	verdict, live := s.livePatternVerdict(ctx, f, chosen)
	switch {
	case !live:
		return rulingNone
	case verdict == patternVerdictApproved:
		return rulingApproved
	case verdict != patternVerdictDenied:
		return rulingNone
	}
	for _, c := range patternClasses {
		if c == chosen {
			continue
		}
		if v, ok := s.livePatternVerdict(ctx, f, c); !ok || v != patternVerdictDenied {
			return rulingDeniedOne
		}
	}
	return rulingDeniedAll
}

// livePatternVerdict returns the verdict for one (check_id, class,
// resource_type) pattern and whether it is live: found, not expired, no error.
func (s *Service) livePatternVerdict(ctx context.Context, f finding.Finding, class ActionClass) (string, bool) {
	verdict, decidedAt, found, err := s.patternVerdicts.PatternVerdict(ctx, f.CheckID, string(class), f.ResourceType)
	switch {
	case err != nil:
		log.FromContext(ctx).Warn().Err(err).Str("finding_id", f.ID).Str("action_class", string(class)).
			Msg("respond: pattern verdict lookup failed; deciding as if none was recorded")
		return "", false
	case !found:
		return "", false
	case s.now().Sub(decidedAt) > PatternVerdictMaxAge:
		// A human ruling is evidence about the world AS IT WAS; once old
		// enough it is treated as though it were never found.
		log.FromContext(ctx).Debug().Str("finding_id", f.ID).Str("check_id", f.CheckID).
			Str("action_class", string(class)).Time("decided_at", decidedAt).
			Msg("respond: pattern verdict expired; deciding as if none was recorded")
		return "", false
	}
	return verdict, true
}

// WithPatternVerdicts wires the governor's pattern-verdict lookup so Decide
// can consult a prior human ruling on the finding's whole (check_id,
// action_class) pattern. Call before Decide.
func (s *Service) WithPatternVerdicts(p PatternVerdicts) *Service {
	s.patternVerdicts = p
	return s
}

// WithRepeatTracker wires the reasoning-cache repeat counter so Decide's
// cache-hit skip path registers each byte-identical repeat. Call before
// Decide.
func (s *Service) WithRepeatTracker(r RepeatTracker) *Service {
	s.repeatTracker = r
	return s
}

// decideSuppressedByVerdict finalizes a decision short-circuited by a DENIED
// pattern verdict (see the pattern-verdict check in Decide). It is terminal:
// no gate, no CoVe, no confidence lookup — a human already ruled on the whole
// pattern, so none of those inputs could change the outcome. It still skips
// re-recording a byte-identical suppressed repeat and still caches the
// reasoning so the next sweep skips the LLM, but it must NEVER notify the
// webhook or record a memory outcome: those are the exact
// re-asking/re-evidencing channels a pattern denial exists to close, and the
// human's ruling already lives once in pattern_verdicts, not per finding.
func (s *Service) decideSuppressedByVerdict(ctx context.Context, f finding.Finding, plan Plan, planNotes []string,
	blastCount int, pack ContextPack, fp string, reused bool, cachedEntry reasoncache.Entry) (Decision, error) {
	d := Decision{
		FindingID:        f.ID,
		Plan:             plan,
		PlanNotes:        planNotes,
		BlastRadius:      blastCount,
		SafetyBand:       safetyBand(plan.ActionClass, pack.Impact, pack.Exposure, pack.Provenance),
		FixLocation:      pack.Impact.FixLocation,
		Outcome:          OutcomeSuppressedByVerdict,
		EscalationReason: "pattern_denied",
		DecidedAt:        s.now(),
		Fingerprint:      fp,
	}

	// The same repeat-dedup applies here, narrowed to what this branch's
	// Decision actually depends on: there is no gate/CoVe/confidence in this
	// path to compare, so outcome + action class is the whole signal.
	skipRecord := reused && cachedEntry.Outcome == string(d.Outcome) && cachedEntry.ActionClass == string(plan.ActionClass)
	if !skipRecord {
		if err := s.audit.Record(ctx, auditFor(d)); err != nil {
			return Decision{}, fmt.Errorf("Decide: audit: %w", err)
		}
		// Deliberately no s.notifier.Notify call here: a suppressed decision
		// is a closed question, not a handoff to execute or approve.
	}

	if s.cache != nil && (!reused || !skipRecord) {
		// hadPrior is "a cache entry existed for this finding", independent of
		// `reused`: planFor returns the PRIOR entry even on a miss (stale
		// fingerprint, or the maxCacheAge forced re-reason) — see its doc
		// comment. Gating the carry-forward on `reused` alone would let a
		// suppressed finding's real measurements survive only until the next
		// cache miss, then get zeroed.
		hadPrior := cachedEntry.FindingID != ""
		decidedAt := d.DecidedAt
		if hadPrior {
			decidedAt = cachedEntry.DecidedAt
		}
		// A suppressed decision does not MEASURE confidence, blast
		// composition or CoVe concerns as low/none — it declined to measure
		// any of them, because the whole point of suppression is skipping
		// that pipeline. Writing hard zeros over a cache entry that held real
		// measurements is a degraded-input trap: the next read (findingctx's
		// finding-detail panel) cannot tell "measured zero" from "never
		// measured". Whenever a prior entry exists, carry its measurements
		// forward instead. blastCount IS measured here — it's a Decide
		// parameter already written into d.BlastRadius and the audit row —
		// so it is never zeroed regardless.
		var (
			confidenceBand        string
			confidenceScore, effN float64
			sampleCount           int
			coveConcerns          []string
		)
		if hadPrior {
			confidenceBand = cachedEntry.ConfidenceBand
			confidenceScore = cachedEntry.ConfidenceScore
			effN = cachedEntry.EffectiveN
			sampleCount = cachedEntry.SampleCount
			coveConcerns = cachedEntry.CoVeConcerns
		}
		_ = s.cache.Put(ctx, reasoncache.Entry{
			FindingID:        f.ID,
			Fingerprint:      fp,
			ActionClass:      string(plan.ActionClass),
			Summary:          plan.Summary,
			Rationale:        plan.Rationale,
			Outcome:          string(d.Outcome),
			ConfidenceBand:   confidenceBand,
			ConfidenceScore:  confidenceScore,
			EffectiveN:       effN,
			SampleCount:      sampleCount,
			BlastRadius:      blastCount,
			CoVeConcerns:     coveConcerns,
			EscalationReason: d.EscalationReason,
			SafetyBand:       d.SafetyBand,
			DecidedAt:        decidedAt,
		})
	}

	// No memory evidence is generated here: the human's ruling is recorded
	// once, in pattern_verdicts (and in the ledger by govern.Resolve), not
	// re-fed into the decaying confidence ledger per finding.
	return d, nil
}
