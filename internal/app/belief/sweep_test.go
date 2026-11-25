package belief

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// severitySampler always returns a fixed severity (deterministic mock).
type severitySampler struct{ sev finding.Severity }

func (s severitySampler) Sample(context.Context, AdjudicationInput) (Verdict, error) {
	return Verdict{Severity: s.sev, Evidence: []Evidence{{Clause: "review", Source: "reasoner", Fact: string(s.sev)}}}, nil
}

// panicSampler fails the test if Sample is ever called — used to prove a cached
// finding spends no LLM.
type panicSampler struct{ t *testing.T }

func (s panicSampler) Sample(context.Context, AdjudicationInput) (Verdict, error) {
	s.t.Fatal("Sample called for a cached finding — should have been skipped")
	return Verdict{}, nil
}

// cand defaults Facts to allKnown() (fidelity_test.go): these tests are
// about adjudication sweep mechanics (backlog, caps, drift, disagreement),
// not the corroboration gate's known-ness — leaving Facts at its bare zero
// value would (after the Known-polarity fix) mean "every witness unknown",
// spuriously triggering the corroboration gate's !Known conflict cases on
// every demotion these tests produce. Tests that specifically exercise the
// gate set c.Facts explicitly (see e.g.
// TestAdjudicator_DemotionContradictedByPublicAccessDowngraded).
func cand(id string, score uint8, det finding.Severity) Candidate {
	return Candidate{
		Input:                 AdjudicationInput{FindingID: id, ResourceID: "r-" + id, RawScore: score, RawBand: "page", Context: "ctx"},
		DeterministicSeverity: det,
		Facts:                 allKnown(),
	}
}

// recordingCandidateStore captures the arguments AdjudicationCandidates is called
// with, to prove Backlog derives the revalidation horizon from RevalidateAfter.
type recordingCandidateStore struct {
	memStore
	gotMinScore uint8
	gotStale    time.Time
	gotLimit    int
	ret         []string
}

func (s *recordingCandidateStore) AdjudicationCandidates(_ context.Context, minScore uint8, staleBefore time.Time, limit int) ([]string, error) {
	s.gotMinScore, s.gotStale, s.gotLimit = minScore, staleBefore, limit
	return s.ret, nil
}

func TestAdjudicator_Backlog_DerivesStaleHorizon(t *testing.T) {
	st := &recordingCandidateStore{ret: []string{"f1", "f2"}}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityLow}, SweepConfig{MaxPerSweep: 40, EscalateN: 3, RevalidateAfter: 7 * 24 * time.Hour})
	a.now = func() time.Time { return now }

	ids, err := a.Backlog(context.Background(), 61, 60)
	require.NoError(t, err)
	require.Equal(t, []string{"f1", "f2"}, ids)
	require.Equal(t, uint8(61), st.gotMinScore)
	require.Equal(t, 60, st.gotLimit)
	require.Equal(t, now.Add(-7*24*time.Hour), st.gotStale, "revalidation horizon = now - RevalidateAfter")
}

func TestAdjudicator_MineCrystallization(t *testing.T) {
	identity := PatternSignature{ResourceType: "iam_user", Band: "page", MustFixClass: "elevated"}
	// 20 corroboration-survivor beliefs all mapping identity/page/elevated → medium.
	st := &memStore{crystIn: inputs(identity, finding.SeverityMedium, 20)}
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityLow}, DefaultSweepConfig())

	cands, err := a.MineCrystallization(context.Background())
	require.NoError(t, err)
	require.Len(t, cands, 1)
	require.Equal(t, identity, cands[0].Sig)
	require.Equal(t, finding.SeverityMedium, cands[0].Severity)
	require.Equal(t, 20, cands[0].Instances)
}

func TestAdjudicator_DemotionContradictedByPublicAccessDowngraded(t *testing.T) {
	st := &memStore{}
	// Sample demotes to Low, deterministic guessed Critical → full adjudication →
	// confirmed Low. But an independent public-access witness contradicts the
	// demotion → the corroboration gate forces it to proposed/low for review.
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityLow}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	c := cand("f1", 95, finding.SeverityCritical)
	c.Facts = GroundingFacts{PublicAccessConfirmed: true}

	res, err := a.Run(context.Background(), []Candidate{c})
	require.NoError(t, err)
	require.Equal(t, 1, res.Downgraded)
	require.Equal(t, 0, res.Adjudicated, "the demotion was not accepted as-is")
	require.Len(t, st.saved, 1)
	require.Equal(t, StatusProposed, st.saved[0].Status)
	require.Equal(t, ConfidenceLow, st.saved[0].Confidence)
	require.NoError(t, st.saved[0].Validate())
}

// mustFixSampler mimics the real reason-seam adjudicator: every sample cites
// its own "must_fix" evidence, exactly the source the corroboration gate used
// to reuse for its own bolted-on conflict clause (the bug: adjudicator beliefs
// carried a gate clause that read as the model contradicting its own verdict,
// because both clauses shared the "must_fix" source tag).
type mustFixSampler struct{ sev finding.Severity }

func (s mustFixSampler) Sample(context.Context, AdjudicationInput) (Verdict, error) {
	return Verdict{Severity: s.sev, Evidence: []Evidence{
		{Clause: "must-fix class is elevated but the reachability claim lacks a named source asset", Source: "must_fix", Fact: "elevated"},
	}}, nil
}

func TestAdjudicator_ReachabilityConflict_EvidenceProvenanceUnambiguous(t *testing.T) {
	st := &memStore{}
	a := NewAdjudicator(st, mustFixSampler{sev: finding.SeverityMedium}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	c := cand("f1", 100, finding.SeverityHigh)
	// The gate fires only with an INDEPENDENT witness (a fresh exposed-edge
	// re-query) — reachability evidence alone no longer vetoes. This case keeps
	// both so it still exercises the evidence-provenance separation it guards.
	c.Facts = GroundingFacts{ExposedEdgePresent: true, ReachabilityEvidenced: true, ReachabilityReason: "internet-exposed"}

	res, err := a.Run(context.Background(), []Candidate{c})
	require.NoError(t, err)
	require.Equal(t, 1, res.Downgraded)
	require.Len(t, st.saved, 1)
	belief := st.saved[0]
	require.Equal(t, StatusProposed, belief.Status)

	// The model's own must_fix-sourced clauses must never contain the gate's
	// contradiction language — that would mean the LLM itself is inconsistent.
	var gateClauses, modelClauses int
	for _, e := range belief.Evidence {
		if e.Source == corroborationGateSource {
			gateClauses++
			require.Contains(t, e.Clause, "CORROBORATION GATE")
		} else {
			modelClauses++
			require.NotContains(t, e.Clause, "contradicted",
				"a model-sourced clause must never carry the gate's contradiction language")
		}
	}
	require.Equal(t, 1, gateClauses, "exactly one gate-authored conflict clause")
	require.Equal(t, 1, modelClauses, "the model's own clause is untouched")
}

func TestAdjudicator_DemotionWithNoWitnessAccepted(t *testing.T) {
	st := &memStore{}
	// Same demotion, but no public witness (e.g. an IAM identity) → accepted as a
	// normal adjudicated belief, NOT downgraded.
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityLow}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(context.Background(), []Candidate{cand("f1", 95, finding.SeverityCritical)})
	require.NoError(t, err)
	require.Equal(t, 0, res.Downgraded)
	require.Equal(t, 1, res.Adjudicated)
	require.Equal(t, finding.SeverityLow, st.saved[0].Severity)
	require.Equal(t, StatusConfirmed, st.saved[0].Status)
}

func TestAdjudicator_CheapAgreementRecordsConfirmation(t *testing.T) {
	st := &memStore{}
	// The sample agrees with the deterministic severity (Critical) → a single-sample
	// confirmation belief is written so the finding is remembered (cached) next sweep.
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityCritical}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(context.Background(), []Candidate{cand("f1", 90, finding.SeverityCritical)})
	require.NoError(t, err)
	require.Equal(t, 1, res.Agreed)
	require.Equal(t, 0, res.Adjudicated)
	require.Len(t, st.saved, 1, "agreement writes a confirmation so it's cached next sweep")
	require.Equal(t, finding.SeverityCritical, st.saved[0].Severity)
	require.Equal(t, ProvenanceAdjudicator, st.saved[0].Provenance)
	require.NotEmpty(t, st.saved[0].Fingerprint)
	require.NoError(t, st.saved[0].Validate(), "confirmation belief is grounded")
}

// errSampler always fails — models a broken model id / API error.
type errSampler struct{}

func (errSampler) Sample(context.Context, AdjudicationInput) (Verdict, error) {
	return Verdict{}, errStub
}

var errStub = fmt.Errorf("Sample: do: model not found")

func TestAdjudicator_SampleErrorsSurfaced(t *testing.T) {
	st := &memStore{}
	a := NewAdjudicator(st, errSampler{}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(context.Background(), []Candidate{
		cand("f1", 90, finding.SeverityCritical),
		cand("f2", 80, finding.SeverityCritical),
	})
	require.NoError(t, err, "a broken sampler is not a sweep-fatal error")
	require.Equal(t, 2, res.SampleErrors, "every failed sample is counted, not hidden")
	require.Equal(t, 0, res.Agreed+res.Adjudicated+res.Escalated)
	require.Contains(t, res.FirstSampleErr, "model not found")
	require.Empty(t, st.saved, "no belief written when the sampler fails")
}

// Regression: unlike the cheap-check failure above, an escalation-cascade
// failure used to reach res.SampleErrors as a bare count with
// res.FirstSampleErr left "" — Adjudicate's signature had no way to carry the
// message out (see SampleFailures' doc comment, adjudicate.go). Forces
// escalation (sample 0 disagrees with the deterministic severity) and fails
// every escalation sample so the only way this test can pass is if the message
// actually made the trip from Adjudicate through Run.
func TestAdjudicator_EscalationSampleErrorMessageSurfaced(t *testing.T) {
	st := &memStore{}
	escFail := fmt.Errorf("Sample: do: rate limited")
	s := &scriptedSampler{
		verdicts: []Verdict{ev(finding.SeverityLow), {}, {}, {}},
		errs:     []error{nil, escFail, escFail, escFail},
	}
	a := NewAdjudicator(st, s, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(context.Background(), []Candidate{cand("f1", 90, finding.SeverityCritical)})
	require.NoError(t, err)
	require.Equal(t, 3, res.SampleErrors, "all 3 escalation samples failed")
	require.Contains(t, res.FirstSampleErr, "rate limited",
		"the escalation cascade's failure message must reach the sweep result, not just its count")
}

// Regression: a context cancelled mid-sweep (a deploy tearing the pod down)
// used to surface through Sample() as an ordinary error, indistinguishable
// from a broken sampler ("Sample: do: context canceled" errors clustered at a
// pod-replacement boundary). panicSampler
// proves Sample is never even called once the context is already done: if the
// ctx.Err() check in Run's loop were missing or wrong, this test would fail via
// t.Fatal inside panicSampler.Sample, not via a require assertion.
func TestAdjudicator_ContextCanceledDefersRatherThanCountsAsSampleError(t *testing.T) {
	st := &memStore{}
	a := NewAdjudicator(st, panicSampler{t}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate the sweep's context already being torn down

	res, err := a.Run(ctx, []Candidate{
		cand("f1", 90, finding.SeverityCritical),
		cand("f2", 80, finding.SeverityCritical),
	})
	require.NoError(t, err, "a torn-down sweep is not itself a fatal error")
	require.Equal(t, 2, res.Deferred, "every candidate left unprocessed when the context is already done is deferred, not a sampler failure")
	require.Zero(t, res.SampleErrors, "cancellation must never be miscounted as a broken sampler")
}

// Regression, found by a later review: the test above
// only cancels ctx BEFORE Run starts, which the top-of-loop ctx.Err() check
// catches. It does not exercise a candidate whose cheap-check Sample() call is
// already in flight when cancellation happens — that call still returns an
// ordinary-looking error, indistinguishable from a broken sampler, unless Run
// ALSO checks ctx.Err() after a failed Sample call. cancelDuringSampleSampler
// (adjudicate_test.go) cancels its own context from inside Sample to
// reproduce exactly that.
func TestAdjudicator_ContextCanceledMidFlightDefersRatherThanCountsAsSampleError(t *testing.T) {
	st := &memStore{}
	ctx, cancel := context.WithCancel(context.Background())
	a := NewAdjudicator(st, cancelDuringSampleSampler{cancel: cancel}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(ctx, []Candidate{
		cand("f1", 90, finding.SeverityCritical),
		cand("f2", 80, finding.SeverityCritical),
	})
	require.NoError(t, err)
	require.Equal(t, 2, res.Deferred, "the in-flight-cancelled candidate and everything after it are deferred, not sample errors")
	require.Zero(t, res.SampleErrors)
}

func TestAdjudicator_SkipsCachedFreshBelief(t *testing.T) {
	c := cand("f1", 90, finding.SeverityCritical)
	// Pre-seed a fresh adjudicator belief whose fingerprint matches the candidate.
	st := &memStore{saved: []Belief{{
		FindingID: "f1", Provenance: ProvenanceAdjudicator, Fingerprint: c.fingerprint(),
		Severity: finding.SeverityLow, CreatedAt: time.Unix(100, 0),
	}}}
	// A sampler that fails if ever called — proving the sweep spent no LLM.
	a := NewAdjudicator(st, panicSampler{t}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(200, 0) } // 100s later, well within TTL

	res, err := a.Run(context.Background(), []Candidate{c})
	require.NoError(t, err)
	require.Equal(t, 1, res.Cached, "fresh belief for unchanged inputs → skipped")
	require.Equal(t, 0, res.Agreed)
	require.Equal(t, 0, res.Adjudicated)
	require.Len(t, st.saved, 2, "only the checked_at stamp is written")
	stamp := st.saved[1]
	require.Equal(t, st.saved[0].CreatedAt, stamp.CreatedAt,
		"the stamp keeps created_at, so it never extends the revalidation window")
	require.Equal(t, time.Unix(200, 0), stamp.CheckedAt)
	require.Equal(t, st.saved[0].Severity, stamp.Severity, "the verdict itself is unchanged")
	require.Equal(t, st.saved[0].Fingerprint, stamp.Fingerprint)
}

// The daily re-enrich re-forms the deterministic belief, making it newer than
// the standing verdict. The cache must still find its own verdict (not the
// deterministic one) and, by stamping checked_at, make it effective again.
func TestAdjudicator_CacheHitReaffirmsVerdictOverNewerDeterministic(t *testing.T) {
	c := cand("f1", 90, finding.SeverityCritical)
	st := &memStore{saved: []Belief{
		{FindingID: "f1", Provenance: ProvenanceAdjudicator, Fingerprint: c.fingerprint(),
			Severity: finding.SeverityLow, CreatedAt: time.Unix(100, 0)},
		{FindingID: "f1", Provenance: ProvenanceDeterministic,
			Severity: finding.SeverityCritical, CreatedAt: time.Unix(150, 0)},
	}}
	before, err := st.GetByFinding(context.Background(), "f1")
	require.NoError(t, err)
	require.Equal(t, ProvenanceDeterministic, before.Provenance, "re-formed deterministic belief is newer")

	a := NewAdjudicator(st, panicSampler{t}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(200, 0) }
	res, err := a.Run(context.Background(), []Candidate{c})
	require.NoError(t, err)
	require.Equal(t, 1, res.Cached)

	after, err := st.GetByFinding(context.Background(), "f1")
	require.NoError(t, err)
	require.Equal(t, ProvenanceAdjudicator, after.Provenance, "a re-affirmed verdict is effective again")
	require.Equal(t, finding.SeverityLow, after.Severity)
}

func TestAdjudicator_ReadjudicatesOnInputDrift(t *testing.T) {
	// Seed a belief with a stale fingerprint (inputs changed since) → not cached.
	st := &memStore{saved: []Belief{{
		FindingID: "f1", Provenance: ProvenanceAdjudicator, Fingerprint: "stale-fp",
		Severity: finding.SeverityLow, CreatedAt: time.Unix(100, 0),
	}}}
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityLow}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(200, 0) }

	res, err := a.Run(context.Background(), []Candidate{cand("f1", 90, finding.SeverityCritical)})
	require.NoError(t, err)
	require.Equal(t, 0, res.Cached, "fingerprint mismatch → the world changed → re-adjudicate")
	require.Equal(t, 1, res.Adjudicated)
}

func TestAdjudicator_RevalidatesStaleBelief(t *testing.T) {
	c := cand("f1", 90, finding.SeverityCritical)
	// Same fingerprint, but the belief is older than RevalidateAfter → re-checked.
	st := &memStore{saved: []Belief{{
		FindingID: "f1", Provenance: ProvenanceAdjudicator, Fingerprint: c.fingerprint(),
		Severity: finding.SeverityCritical, CreatedAt: time.Unix(0, 0),
	}}}
	cfg := SweepConfig{MaxPerSweep: 100, EscalateN: 3, RevalidateAfter: time.Hour}
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityCritical}, cfg)
	a.now = func() time.Time { return time.Unix(7200, 0) } // 2h later > 1h TTL

	res, err := a.Run(context.Background(), []Candidate{c})
	require.NoError(t, err)
	require.Equal(t, 0, res.Cached, "belief past its re-validation window is re-checked")
	require.Equal(t, 1, res.Agreed)
}

func TestAdjudicator_DisagreementAdjudicatesAndPersists(t *testing.T) {
	st := &memStore{}
	// Sample says Low, deterministic guessed Critical → disagreement → full N-sample
	// (all Low here) → confirmed Low belief written.
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityLow}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(context.Background(), []Candidate{cand("f1", 90, finding.SeverityCritical)})
	require.NoError(t, err)
	require.Equal(t, 1, res.Adjudicated)
	require.Len(t, st.saved, 1)
	require.Equal(t, finding.SeverityLow, st.saved[0].Severity)
	require.Equal(t, "adjudicator", st.saved[0].Provenance)
}

// diverge3Sampler always disagrees with the deterministic severity on the
// cheap check, then diverges across the 3 escalation samples (no majority) —
// a genuinely ambiguous cascade that runs to completion, no cancellation
// anywhere in the picture.
type diverge3Sampler struct{ i int }

func (s *diverge3Sampler) Sample(context.Context, AdjudicationInput) (Verdict, error) {
	sevs := []finding.Severity{finding.SeverityLow, finding.SeverityLow, finding.SeverityHigh, finding.SeverityMedium}
	sev := sevs[s.i]
	s.i++
	return Verdict{Severity: sev, Evidence: []Evidence{{Clause: "review", Source: "reasoner", Fact: string(sev)}}}, nil
}

// TestAdjudicator_GenuineEscalationIsCachedFresh pins the CONTRAST case for
// TestAdjudicator_TruncatedEscalationNotCachedFresh below: an escalation
// cascade that runs to completion and genuinely diverges (no cancellation
// anywhere) is still cached as a resolved, fresh belief — only a cancellation-
// truncated cascade should skip the freshness stamp.
func TestAdjudicator_GenuineEscalationIsCachedFresh(t *testing.T) {
	st := &memStore{}
	a := NewAdjudicator(st, &diverge3Sampler{}, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(context.Background(), []Candidate{cand("f1", 90, finding.SeverityCritical)})
	require.NoError(t, err)
	require.Equal(t, 1, res.Escalated, "genuine divergence escalates")
	require.Zero(t, res.Deferred)
	require.Len(t, st.saved, 1, "a genuinely ambiguous cascade IS cached — it isn't a false one")
	require.Equal(t, StatusProposed, st.saved[0].Status)
	require.NotEmpty(t, st.saved[0].Fingerprint, "cached with a fingerprint, so cachedFresh will honor the full RevalidateAfter window next sweep")
}

// disagreeThenCancelSampler disagrees on the cheap check (forcing escalation),
// then cancels its OWN context from inside the FIRST escalation sample and
// returns the resulting cancellation error — reproducing a deploy/shutdown
// landing mid-escalation-cascade, exactly like cancelDuringSampleSampler
// (adjudicate_test.go) but wired so the cheap check happens first.
type disagreeThenCancelSampler struct {
	cancel context.CancelFunc
	calls  int
}

func (s *disagreeThenCancelSampler) Sample(ctx context.Context, _ AdjudicationInput) (Verdict, error) {
	s.calls++
	if s.calls == 1 {
		// Cheap check: disagree with the deterministic severity so Run escalates.
		return ev(finding.SeverityLow), nil
	}
	s.cancel()
	return Verdict{}, fmt.Errorf("Sample: do: %w", ctx.Err())
}

// Regression for the cascade-truncated-by-cancellation caching defect: an
// escalation cascade cut short by OUR OWN context cancellation (deploy,
// shutdown) must NOT be persisted as a resolved belief stamped fresh for the
// full defaultRevalidateAfter (7 days) — that would make a candidate whose
// only problem was deploy timing wait up to a week for human review instead
// of being retried on the very next routine sweep (30min later). Contrast
// with TestAdjudicator_GenuineEscalationIsCachedFresh above, which completes
// with no cancellation and IS cached.
func TestAdjudicator_TruncatedEscalationNotCachedFresh(t *testing.T) {
	st := &memStore{}
	ctx, cancel := context.WithCancel(context.Background())
	s := &disagreeThenCancelSampler{cancel: cancel}
	a := NewAdjudicator(st, s, DefaultSweepConfig())
	a.now = func() time.Time { return time.Unix(0, 0) }

	res, err := a.Run(ctx, []Candidate{cand("f1", 90, finding.SeverityCritical)})
	require.NoError(t, err)
	require.Equal(t, 0, res.Escalated, "a cancellation-truncated cascade must not be reported as a resolved escalation")
	require.Equal(t, 0, res.Adjudicated)
	require.Equal(t, 1, res.Deferred, "deferred so the next routine sweep retries it, not cached out for a week")
	require.Empty(t, st.saved, "must not be cached fresh for the full RevalidateAfter window — the cascade never actually ran")
}

func TestAdjudicator_PerSweepCapDefers(t *testing.T) {
	st := &memStore{}
	a := NewAdjudicator(st, severitySampler{sev: finding.SeverityLow}, SweepConfig{MaxPerSweep: 2, EscalateN: 3})
	a.now = func() time.Time { return time.Unix(0, 0) }

	cands := []Candidate{
		cand("f1", 70, finding.SeverityCritical),
		cand("f2", 95, finding.SeverityCritical),
		cand("f3", 85, finding.SeverityCritical),
	}
	res, err := a.Run(context.Background(), cands)
	require.NoError(t, err)
	require.Equal(t, 1, res.Deferred, "3 candidates, cap 2 → 1 deferred")
	require.Equal(t, 2, res.Adjudicated)
	// Highest-score first: f2 (95) and f3 (85) processed, f1 (70) deferred.
	ids := map[string]bool{}
	for _, b := range st.saved {
		ids[b.FindingID] = true
	}
	require.True(t, ids["f2"] && ids["f3"], "highest scores prioritized")
	require.False(t, ids["f1"], "lowest score deferred")
}
