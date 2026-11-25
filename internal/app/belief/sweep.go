package belief

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// SweepConfig bounds the adjudicator's cost per sweep. The gate
// (NeedsAdjudication) and change-driven enrichment already limit the candidate
// set to changed, high-band, unresolved findings; these caps bound what's left.
type SweepConfig struct {
	MaxPerSweep int // hard ceiling on findings adjudicated per sweep (0 = unlimited)
	EscalateN   int // sample count for the full adjudication when the cheap check disagrees
	// RevalidateAfter re-adjudicates a cached belief once it is older than this,
	// even if its inputs are unchanged — a periodic re-check that guards against
	// silent drift the fingerprint can't see (model updates, world changes not in
	// the context). Zero uses the default (7 days).
	RevalidateAfter time.Duration
}

// DefaultSweepConfig is the "moderate" posture: cap 40 findings adjudicated per
// sweep, each costing one cheap sample plus 3 more on disagreement (so up to 4
// LLM calls per finding, 160 per sweep), re-validate a standing belief weekly.
// The cap is sized so a sweep of sequential LLM calls finishes inside the
// job's time budget (see adjudicateJobTimeout); the backlog drains across
// sweeps via the backlog cursor (AdjudicationCandidates), and once a finding
// is judged, change-driven caching skips it for free thereafter. Beliefs
// persist incrementally, so a sweep that times out mid-batch resumes next
// tick.
func DefaultSweepConfig() SweepConfig {
	return SweepConfig{MaxPerSweep: 40, EscalateN: 3, RevalidateAfter: 7 * 24 * time.Hour}
}

const defaultRevalidateAfter = 7 * 24 * time.Hour

// Candidate is a finding eligible for adjudication plus the deterministic
// severity the cheap check compares against and the independent grounding facts
// the corroboration gate cross-checks the verdict against.
type Candidate struct {
	Input                 AdjudicationInput
	DeterministicSeverity finding.Severity
	Facts                 GroundingFacts
}

// SweepResult reports what the sweep did — for metrics and the no-silent-cap log.
type SweepResult struct {
	Considered  int // candidates handed in
	Cached      int // fresh belief for unchanged inputs — skipped, zero LLM spend
	Agreed      int // cheap 1-sample confirmed the deterministic severity
	Adjudicated int // adjudicator belief written (confirmed, disagreement resolved)
	Escalated   int // low-confidence proposed belief (human review)
	Downgraded  int // a demotion contradicted by an independent witness → forced to proposed (corroboration gate)
	// Deferred counts candidates NOT processed this sweep — either over the
	// per-sweep cost cap (MaxPerSweep) or cut short by a context cancellation
	// (deploy/shutdown) mid-batch. Both are picked up again next sweep, so one
	// counter covers "not silently dropped"; it does not currently distinguish
	// which of the two causes applied.
	Deferred int
	// SampleErrors counts candidates whose LLM sample failed (API error, bad model,
	// ungrounded/unparseable verdict). A high count with zero agreed/adjudicated
	// means the sampler is broken — surfaced so it never hides as "0 adjudicated"
	// again. FirstSampleErr is the first such error's message, for the log.
	SampleErrors   int
	FirstSampleErr string
}

// Adjudicator orchestrates cost-bounded adjudication over the candidate set: it
// prioritizes by raw score, honors the per-sweep cap, and runs an N-cascade — one
// cheap adversarial sample first, escalating to the full EscalateN-sample
// convergence ONLY when that sample disagrees with the deterministic severity.
// So an already-correct high finding costs one call; only genuine conflicts pay
// the multi-sample rigor.
type Adjudicator struct {
	store   Store
	sampler Sampler
	cfg     SweepConfig
	now     func() time.Time
}

// NewAdjudicator wires the store, the reasoning sampler, and the cost caps.
func NewAdjudicator(store Store, sampler Sampler, cfg SweepConfig) *Adjudicator {
	if cfg.EscalateN < 1 {
		cfg.EscalateN = 3
	}
	if cfg.RevalidateAfter <= 0 {
		cfg.RevalidateAfter = defaultRevalidateAfter
	}
	return &Adjudicator{store: store, sampler: sampler, cfg: cfg, now: time.Now}
}

// Run adjudicates the candidates within the sweep budget and persists the beliefs
// it forms. Change-driven: a finding whose fresh belief already covers its current
// inputs is skipped for free (no LLM), so a stable finding is adjudicated once and
// remembered — cost only recurs when its evidence changes or the belief ages out.
// Of the rest, highest raw score first; overflow beyond MaxPerSweep is deferred
// (reported, never silently dropped). Both agreement and disagreement write a
// belief, so the next sweep finds them cached.
//
// Known limitation: a persist (store.Upsert) failure for any one candidate
// aborts the whole sweep via an early return, discarding every remaining
// lower-priority candidate for this tick (and the belief just computed for
// it) rather than skipping just that candidate. Left as-is deliberately —
// changing it to "log and continue" is a separate behavior decision.
func (a *Adjudicator) Run(ctx context.Context, cands []Candidate) (SweepResult, error) {
	res := SweepResult{Considered: len(cands)}
	sorted := append([]Candidate(nil), cands...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Input.RawScore > sorted[j].Input.RawScore })

	processed := 0
	for i, c := range sorted {
		// The sweep is being torn down (deploy, shutdown) mid-batch — every
		// remaining candidate is genuinely deferred to the next tick, not a
		// sampler failure. Without this check, a.sampler.Sample's context
		// cancellation would surface as an ordinary error indistinguishable
		// from a broken sampler and inflate SampleErrors on every deploy.
		if isContextCancellation(ctx) {
			res.Deferred += len(sorted) - i
			break
		}
		fp := c.fingerprint()
		// Change-driven skip: a fresh adjudicator verdict for these exact inputs
		// stands — spend nothing. This is what makes it "adjudicate once, remember".
		// Stamp checked_at so the backlog cursor stops offering this finding
		// until it is re-enriched, and so the verdict keeps superseding the
		// deterministic belief enrich re-forms (see Effective).
		if prior, ok := a.cachedFresh(ctx, c.Input.FindingID, fp); ok {
			prior.CheckedAt = a.now()
			if err := a.store.Upsert(ctx, []Belief{prior}); err != nil {
				return res, fmt.Errorf("Run: stamp checked %s: %w", c.Input.FindingID, err)
			}
			res.Cached++
			continue
		}
		// Cost cap applies only to LLM-spending work; cached skips above are free,
		// so a swept-but-cached finding never consumes budget.
		if a.cfg.MaxPerSweep > 0 && processed >= a.cfg.MaxPerSweep {
			res.Deferred++
			continue
		}
		processed++

		// Cheap check: one adversarial sample.
		v, err := a.sampler.Sample(ctx, c.Input)
		if err != nil {
			if isContextCancellation(ctx) {
				// This call was already in flight when the context was cancelled —
				// the top-of-loop check above only catches cancellation BETWEEN
				// candidates, not one already in progress. Defer this candidate and
				// everything after it (the context will not recover) rather than
				// count a shutdown as a sample failure.
				res.Deferred += len(sorted) - i
				break
			}
			// A failed cheap check leaves the standing belief in place — but record
			// it so a wholesale sampler failure is visible, not hidden as "0 agreed".
			res.SampleErrors++
			if res.FirstSampleErr == "" {
				res.FirstSampleErr = err.Error()
			}
			continue
		}
		if v.Severity == c.DeterministicSeverity {
			// Agreement: the high score holds up. Record a single-sample
			// confirmation so the next sweep finds it cached instead of re-checking.
			if err := a.store.Upsert(ctx, []Belief{confirmationBelief(c, v, fp, a.now())}); err != nil {
				return res, fmt.Errorf("Run: persist confirmation %s: %w", c.Input.FindingID, err)
			}
			res.Agreed++
			continue
		}
		// Disagreement → full N-sample convergence for a confident, grounded verdict.
		b, escFails, err := Adjudicate(ctx, a.sampler, c.Input, a.cfg.EscalateN, a.now())
		// Surface escalation-cascade sample failures (and a fatal Adjudicate
		// error), including the message, so a sampler that breaks only during
		// escalation can't hide as "0" (see SampleFailures' doc comment).
		res.SampleErrors += escFails.Count
		if escFails.First != nil && res.FirstSampleErr == "" {
			res.FirstSampleErr = escFails.First.Error()
		}
		if escFails.Truncated {
			// The escalation cascade was cut short by our own context
			// cancellation, not genuine sample disagreement — do not persist
			// this as a resolved belief: caching it would stamp it fresh for
			// the full revalidation window, making a deploy-timing hiccup wait
			// out the window instead of retrying next sweep. Defer this
			// candidate and everything after it — the context will not
			// recover mid-sweep.
			res.Deferred += len(sorted) - i
			break
		}
		if err != nil {
			res.SampleErrors++
			if res.FirstSampleErr == "" {
				res.FirstSampleErr = err.Error()
			}
			continue
		}
		b.Fingerprint = fp
		// Corroboration gate: a demotion contradicted by an independent
		// exposure witness is not trusted — flag it for review instead of silently
		// accepting it. Only a genuine downgrade counts (escalate() already set
		// proposed on divergence).
		downgraded := false
		if b.Status != StatusProposed {
			if conflict, ev := corroborationConflict(b.Severity, c.Facts); conflict {
				b = downgradeForConflict(b, ev)
				downgraded = true
			}
		}
		if err := a.store.Upsert(ctx, []Belief{b}); err != nil {
			return res, fmt.Errorf("Run: persist belief %s: %w", b.FindingID, err)
		}
		switch {
		case downgraded:
			res.Downgraded++
		case b.Status == StatusProposed:
			res.Escalated++
		default:
			res.Adjudicated++
		}
	}
	return res, nil
}

// Backlog returns the finding ids to adjudicate this sweep — the eligible
// high-band findings not freshly adjudicated, least-recently-adjudicated first.
// staleBefore is derived from the sweep's RevalidateAfter so the cursor's
// re-inclusion horizon matches cachedFresh's revalidation window: a belief the
// cache would re-check is one the cursor lets back in, and vice versa.
func (a *Adjudicator) Backlog(ctx context.Context, minScore uint8, limit int) ([]string, error) {
	staleBefore := a.now().Add(-a.cfg.RevalidateAfter)
	ids, err := a.store.AdjudicationCandidates(ctx, minScore, staleBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("Backlog: %w", err)
	}
	return ids, nil
}

// MineCrystallization surfaces the stable, corroboration-surviving belief patterns
// that are candidates to crystallize into cheap deterministic rules. It
// only IDENTIFIES them (report-only) — promotion/auto-application is a separate
// eval-gated step, because auto-trusting the model's own patterns is the collapse
// risk anti-collapse forbids.
func (a *Adjudicator) MineCrystallization(ctx context.Context) ([]CrystallizationCandidate, error) {
	in, err := a.store.CrystallizationInputs(ctx)
	if err != nil {
		return nil, fmt.Errorf("MineCrystallization: %w", err)
	}
	return MineCandidates(in, MinCrystallizeInstances), nil
}

// cachedFresh reports whether a finding already has a standing adjudicator belief
// for the same grounded inputs that is not yet due for re-validation, and
// returns it. The revalidation window runs from CreatedAt, not CheckedAt: a
// cache hit must not extend it, or a stable finding would never be re-judged.
func (a *Adjudicator) cachedFresh(ctx context.Context, findingID, fp string) (Belief, bool) {
	prior, err := a.store.GetByProvenance(ctx, findingID, ProvenanceAdjudicator)
	if err != nil {
		return Belief{}, false // no verdict (or a read error) → adjudicate
	}
	fresh := prior.Fingerprint == fp && a.now().Sub(prior.CreatedAt) < a.cfg.RevalidateAfter
	return prior, fresh
}

// fingerprint hashes the grounding inputs that define this finding's world. A
// change in the score, band, deterministic severity, the assembled context, OR the
// independent corroboration witnesses yields a new fingerprint and re-adjudication;
// anything else stays cached. The witnesses (Facts) MUST be in the key: the
// public-access signal is deliberately kept out of the LLM Context, so without it
// here a resource going public after a cached demotion would never re-run the
// corroboration gate until the 7-day revalidation.
//
// The *Known bits are hashed too, not just the *Confirmed/*Present/
// *Evidenced values they pair with: a
// witness flipping from known to unknown (or back) between sweeps — a
// provider becoming unreachable, or recovering — changes what
// corroborationConflict actually does with this candidate (fidelity.go's
// !f.XKnown branches) without changing any of the OTHER hashed values, so
// omitting them left exactly that transition invisible to the cache for up
// to RevalidateAfter.
func (c Candidate) fingerprint() string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d\x00%s\x00%s\x00%t\x00%t\x00%t\x00%t\x00%t\x00%t\x00%t\x00%t\x00%s\x00%s",
		c.Input.RawScore, c.Input.RawBand, c.DeterministicSeverity,
		c.Facts.PublicAccessConfirmed, c.Facts.ExposedEdgePresent,
		c.Facts.ExposureConfirmed, c.Facts.ReachabilityEvidenced,
		c.Facts.PublicAccessKnown, c.Facts.ExposedEdgeKnown, c.Facts.ExposurePeersKnown, c.Facts.BlastKnown,
		c.Facts.ReachabilityReason, c.Input.Context))
	return hex.EncodeToString(sum[:8])
}

// confirmationBelief records that a cheap adversarial sample confirmed the
// deterministic severity. Grounded (the sample's evidence plus the raw-score
// citation) and fingerprinted so the sweep caches it.
func confirmationBelief(c Candidate, v Verdict, fp string, now time.Time) Belief {
	ev := dedupeEvidence(v.Evidence)
	ev = append(ev, Evidence{
		Clause: fmt.Sprintf("raw enriched score %d (band %q) held up under adversarial review", c.Input.RawScore, c.Input.RawBand),
		Source: "enrich_score", Fact: fmt.Sprintf("%d/%s", c.Input.RawScore, c.Input.RawBand),
	})
	return Belief{
		FindingID:   c.Input.FindingID,
		ResourceID:  c.Input.ResourceID,
		Claim:       fmt.Sprintf("adversarial check confirms %s — the raw severity holds up", v.Severity),
		Severity:    v.Severity,
		Confidence:  ConfidenceMedium,
		Status:      StatusConfirmed,
		Evidence:    ev,
		Provenance:  ProvenanceAdjudicator,
		Fingerprint: fp,
		CreatedAt:   now,
	}
}
