package belief

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// AdjudicationInput carries a finding plus its full grounded context for the
// adversarial reasoning samples (the graph/live/CSPM context pack).
type AdjudicationInput struct {
	FindingID, ResourceID string
	Title                 string
	RawScore              uint8
	RawBand               string
	Context               string // assembled connected-graph + live + CSPM context
}

// Verdict is one adversarial sample's output: its judged true severity and the
// grounded clauses backing it. The sample is prompted to try to REFUTE the raw
// high severity, so a lower Severity here means it found the high score unjustified.
type Verdict struct {
	Severity finding.Severity
	Evidence []Evidence
}

// Sampler runs one adversarial reasoning pass over the finding's full context.
// The reason-seam adapter implements it (real LLM); tests inject deterministic
// samples. Kept in the belief package so the convergence logic depends only on
// this narrow interface, not the LLM.
type Sampler interface {
	Sample(ctx context.Context, in AdjudicationInput) (Verdict, error)
}

// isContextCancellation reports whether ctx has already been cancelled or its
// deadline exceeded — the single check for "was this Sample() failure (or the
// about-to-be-made call) caused by our own shutdown, not a broken sampler."
// Centralized so every call site (this file's cascade loop, sweep.go's cheap
// check) applies the same check before AND after calling Sample — see
// TestIsContextCancellation and TestNoInlineCtxErrCancellationChecks.
func isContextCancellation(ctx context.Context) bool {
	return ctx.Err() != nil
}

// SampleFailures reports how many samples failed in one Adjudicate cascade and
// the first failure's actual error, mirroring SweepResult's
// SampleErrors/FirstSampleErr split so an escalation-cascade failure is as
// diagnosable as a cheap-check failure — a bare count with no message hides a
// broken sampler as "0 adjudicated".
//
// Truncated reports whether the cascade was cut short by isContextCancellation
// rather than completing (with agreement, divergence, or plain sample
// failures). The caller (sweep.go's Run) uses it to skip caching the resulting
// low-confidence belief for the full revalidation window — a cascade cut short
// by a deploy is not evidence the finding is ambiguous, so it should retry on
// the next sweep instead of waiting out the window.
type SampleFailures struct {
	Count     int
	First     error
	Truncated bool
}

// Adjudicate runs n independent adversarial samples and forms a belief ONLY on
// convergence ("undeniable truth"): unanimous → high confidence, a clear
// majority → medium — both confirmed; a split (no majority) or too few successful
// samples → a low-confidence proposed belief flagged for human escalation.
// Divergence is a signal, never averaged away. Every emitted belief is grounded:
// only cited evidence from the winning samples is carried, and the result is
// Validate-checked before return.
// Returns the belief, the sample failures in the cascade (so the caller can
// surface a broken sampler, with its actual message, instead of it hiding as
// "0 adjudicated"), and a fatal error only when a converged verdict fails the
// grounding contract.
func Adjudicate(ctx context.Context, sampler Sampler, in AdjudicationInput, n int, now time.Time) (Belief, SampleFailures, error) {
	if n < 1 {
		n = 1
	}
	var verdicts []Verdict
	var fails SampleFailures
	truncated := false
	for i := 0; i < n; i++ {
		if isContextCancellation(ctx) {
			// Torn down mid-cascade (deploy, shutdown), no sample in flight —
			// stop rather than let every remaining attempt surface as an
			// ordinary Sample() error indistinguishable from a broken sampler.
			truncated = true
			break
		}
		v, err := sampler.Sample(ctx, in)
		if err != nil {
			if isContextCancellation(ctx) {
				// This call was already in flight when the context was
				// cancelled, so it failed because of the shutdown, not because
				// the sampler is broken — the pre-call check above can't catch
				// this since the context was still live at that moment.
				truncated = true
				break
			}
			// A failed sample is dropped, not fatal — but counted AND its message
			// kept, not just counted (see SampleFailures' doc comment).
			fails.Count++
			if fails.First == nil {
				fails.First = err
			}
			continue
		}
		verdicts = append(verdicts, v)
	}

	base := Belief{
		FindingID: in.FindingID, ResourceID: in.ResourceID,
		Provenance: ProvenanceAdjudicator, CreatedAt: now,
	}

	// Too few opinions to trust — escalate. truncated is checked here, before
	// majoritySeverity, on purpose: 2 agreeing verdicts out of a cascade cut
	// short at n=3 look identical to a cascade only ever configured for n=2,
	// and would otherwise report ConfidenceHigh/StatusConfirmed with no trace
	// that a third sample was ever supposed to run. A cancelled cascade never
	// got the rigor it was asked for, regardless of how many partial verdicts
	// happen to agree, so it escalates exactly like "too few samples" does.
	if truncated || len(verdicts) < 2 {
		fails.Truncated = truncated
		return escalate(base, in, verdicts, "insufficient reasoning samples converged"), fails, nil
	}

	winner, count := majoritySeverity(verdicts)
	if count*2 <= len(verdicts) { // no strict majority → divergence → escalate
		return escalate(base, in, verdicts, "adversarial samples diverged on severity"), fails, nil
	}

	base.Severity = winner
	base.Evidence = dedupeEvidence(winningEvidence(verdicts, winner))
	if len(base.Evidence) == 0 {
		// A converged verdict with no cited evidence violates the grounding
		// contract — treat as inconclusive rather than assert ungrounded.
		return escalate(base, in, verdicts, "converged verdict lacked cited evidence"), fails, nil
	}
	if count == len(verdicts) {
		base.Confidence, base.Status, base.Claim = ConfidenceHigh, StatusConfirmed,
			fmt.Sprintf("adjudicated %s — all %d samples agreed", winner, count)
	} else {
		base.Confidence, base.Status, base.Claim = ConfidenceMedium, StatusConfirmed,
			fmt.Sprintf("adjudicated %s — %d of %d samples agreed", winner, count, len(verdicts))
	}
	if err := base.Validate(); err != nil {
		return Belief{}, fails, fmt.Errorf("Adjudicate: %w", err)
	}
	return base, fails, nil
}

// escalate builds a low-confidence, human-escalation belief, still grounded on
// whatever evidence the samples cited (plus the raw score as a floor citation).
//
// A truncated cascade escalates through this same path as a genuinely
// content-ambiguous one — low confidence is warranted either way. What
// differs is caching: SampleFailures.Truncated tells sweep.go's Run not to
// cache this belief for the full revalidation window, since a candidate whose
// only problem was a deploy-timing cancellation should retry next sweep, not
// wait out the window.
func escalate(b Belief, in AdjudicationInput, verdicts []Verdict, why string) Belief {
	var ev []Evidence
	for _, v := range verdicts {
		ev = append(ev, v.Evidence...)
	}
	ev = dedupeEvidence(ev)
	ev = append(ev, Evidence{
		Clause: fmt.Sprintf("raw enriched score %d (band %q); adjudication inconclusive", in.RawScore, in.RawBand),
		Source: "enrich_score", Fact: fmt.Sprintf("%d/%s", in.RawScore, in.RawBand),
	})
	b.Severity = finding.Severity(in.RawBand) // keep the raw signal pending review
	if !isSeverity(b.Severity) {
		b.Severity = bandToSeverity(in.RawBand)
	}
	b.Confidence, b.Status = ConfidenceLow, StatusProposed
	b.Claim = "needs human review — " + why
	b.Evidence = ev
	return b
}

// severityRank orders bands for deterministic tie-breaking (higher = more severe).
func severityRank(s string) int {
	switch finding.Severity(s) {
	case finding.SeverityCritical:
		return 4
	case finding.SeverityHigh:
		return 3
	case finding.SeverityMedium:
		return 2
	case finding.SeverityLow:
		return 1
	default:
		return 0
	}
}

func isSeverity(s finding.Severity) bool {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo:
		return true
	}
	return false
}

// majoritySeverity returns the most-cited severity and its count.
func majoritySeverity(vs []Verdict) (finding.Severity, int) {
	counts := map[finding.Severity]int{}
	for _, v := range vs {
		counts[v.Severity]++
	}
	// Deterministic pick on ties by ranking severity desc, then count.
	sevs := make([]finding.Severity, 0, len(counts))
	for s := range counts {
		sevs = append(sevs, s)
	}
	sort.Slice(sevs, func(i, j int) bool { return severityRank(string(sevs[i])) > severityRank(string(sevs[j])) })
	best, bestN := finding.Severity(""), 0
	for _, s := range sevs {
		if counts[s] > bestN {
			best, bestN = s, counts[s]
		}
	}
	return best, bestN
}

func winningEvidence(vs []Verdict, winner finding.Severity) []Evidence {
	var out []Evidence
	for _, v := range vs {
		if v.Severity == winner {
			out = append(out, v.Evidence...)
		}
	}
	return out
}

// dedupeEvidence collapses evidence to one entry per distinct grounding
// fact — (Source, Fact) — not per distinct Clause. Fact must be the
// OBSERVED VALUE (see the Evidence doc comment) — a genuinely distinct
// instance-specific detail, never a coarse category label like "must_fix"
// or "elevated". Clause is only its prose rendering, and the multi-sample
// adjudicator's independent LLM samples routinely paraphrase the SAME fact
// into slightly different clauses ("blast radius is real but moderate" vs
// "blast radius is moderate — real but not sprawling"). Keying on Clause too
// would let those paraphrases survive dedup as near-duplicate bullets.
//
// reconcile.go must honour this contract too: its must_fix/controlled
// branches emit the instance-specific reason string (already sitting right
// there in Clause) as Fact, never the coarse class name — a coarse Fact would
// silently DROP (not merge) two genuinely different findings' evidence if
// they were ever combined, since dropping (not merging) is what this function
// does on a key collision. The contract is upheld at the call sites, not here.
//
// First-seen clause wins for a given (Source, Fact); nothing here merges
// genuinely distinct facts, PROVIDED callers uphold the Fact-is-observed-
// value contract.
func dedupeEvidence(in []Evidence) []Evidence {
	seen := map[string]bool{}
	var out []Evidence
	for _, e := range in {
		if e.Source == "" || e.Fact == "" {
			continue // drop ungrounded clauses
		}
		k := normalizeEvidenceKey(e.Source) + "|" + normalizeEvidenceKey(e.Fact)
		if !seen[k] {
			seen[k] = true
			out = append(out, e)
		}
	}
	return out
}

// normalizeEvidenceKey folds case and collapses whitespace so two samples'
// facts that differ only in casing or incidental spacing still dedupe.
func normalizeEvidenceKey(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}
