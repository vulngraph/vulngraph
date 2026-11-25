package respond

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/policy"
)

type fakeReasoner struct {
	plan Plan
	err  error
}

func (f fakeReasoner) Reason(context.Context, ContextPack) (Plan, error) {
	return f.plan, f.err
}

type fakeGate struct{ decision policy.Decision }

func (f fakeGate) Evaluate(context.Context, policy.Input) (policy.Decision, error) {
	return f.decision, nil
}

type fakeConfidence struct {
	band       memory.Band
	score      float64
	effectiveN float64
	samples    int
}

func (f fakeConfidence) Confidence(context.Context, string, string) (memory.Confidence, error) {
	return memory.Confidence{Band: f.band, Score: f.score, EffectiveN: f.effectiveN, SampleCount: f.samples}, nil
}

// fakeBlast.n is the REACHABLE count every caller in this file means it to
// be — asset.BlastRadius.Assets always carries the seed at index 0 in
// production (asset.Service.BlastRadiusDir), and reachableAssets drops it, so
// this fake reproduces that shape (n+1 total) rather than making every
// existing fakeBlast{n: X} call site's X mean something different than it did
// before the seed-exclusion change: the seed itself is never part of the blast radius.
type fakeBlast struct{ n int }

func (f fakeBlast) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	return asset.BlastRadius{Assets: make([]asset.Asset, f.n+1)}, nil
}

func (f fakeBlast) ResolveID(_ context.Context, identifier string) (string, error) {
	return identifier, nil
}

type fakeAudit struct{ events []AuditEvent }

func (f *fakeAudit) Record(_ context.Context, e AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

type fakeNotifier struct{ calls int }

func (f *fakeNotifier) Notify(context.Context, finding.Finding, Decision, ContextPack) error {
	f.calls++
	return nil
}

// fakePatternVerdicts is the respond-side test double for PatternVerdicts —
// respond's own narrow interface, not govern's (layering).
type fakePatternVerdicts struct {
	verdict string
	found   bool
	err     error
	// decidedAt is the verdict's timestamp. Zero (the default) resolves to
	// the real wall clock at call time — always far AFTER any of the fixed
	// svc.now() values these tests use (near the Unix epoch), so it never
	// reads as expired unless a test sets it explicitly (the max-age tests).
	decidedAt time.Time
	// byClass, when non-nil, overrides verdict/found per action class: a
	// class present in the map has that verdict, an absent one has none.
	byClass map[string]string
	// gotCheckID/gotActionClass/gotResourceType record the FIRST call's
	// arguments (the plan's own class is always looked up first) so a test
	// can assert respond actually passes the finding's own check_id/
	// action_class/resource_type — a fake that silently discarded them would
	// leave the resource-type scoping unguarded: every test would stay green
	// even if Decide passed the wrong argument, or the empty string, and
	// re-opened the estate-wide suppression the scoping exists to close.
	gotCheckID, gotActionClass, gotResourceType string
	calls                                       int
}

func (f *fakePatternVerdicts) PatternVerdict(_ context.Context, checkID, actionClass, resourceType string) (string, time.Time, bool, error) {
	if f.calls == 0 {
		f.gotCheckID, f.gotActionClass, f.gotResourceType = checkID, actionClass, resourceType
	}
	f.calls++
	decidedAt := f.decidedAt
	if decidedAt.IsZero() {
		decidedAt = time.Now()
	}
	if f.byClass != nil {
		v, ok := f.byClass[actionClass]
		return v, decidedAt, ok, f.err
	}
	return f.verdict, decidedAt, f.found, f.err
}

// countingGate records how many times Evaluate was called — used to prove a
// denied pattern verdict short-circuits BEFORE the gate, not merely overrides
// its result afterward.
type countingGate struct {
	calls    int
	decision policy.Decision
}

func (g *countingGate) Evaluate(context.Context, policy.Input) (policy.Decision, error) {
	g.calls++
	return g.decision, nil
}

func newSvc(gate policy.Decision, band memory.Band, blast int) (*Service, *fakeAudit) {
	audit := &fakeAudit{}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "fix it"}},
		fakeGate{decision: gate},
		fakeConfidence{band: band},
		fakeBlast{n: blast},
		audit, nil, nil, nil, // nil cache + nil peers + nil lineage: always reason, finding-only pack
	)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }
	return svc, audit
}

var aFinding = finding.Finding{ID: "f1", ResourceID: "i-1", ResourceType: "ec2_instance"}

func TestDecide_Parks_AndAudits(t *testing.T) {
	svc, audit := newSvc(policy.Decision{NeedsApproval: true}, memory.BandHigh, 3)

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeParked, d.Outcome)
	require.Equal(t, 3, d.BlastRadius)
	require.Len(t, audit.events, 1)
	require.Equal(t, "decision", audit.events[0].Action)
	require.Equal(t, "f1", audit.events[0].TargetID)

	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(audit.events[0].Details), &details))
	require.Equal(t, string(OutcomeParked), details["outcome"])
	require.NotContains(t, details, "simulated", "nothing is ever executed, so nothing is ever simulated")
}

func TestDecide_Escalates(t *testing.T) {
	svc, audit := newSvc(policy.Decision{Escalate: true}, memory.BandInsufficient, 0)

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeEscalated, d.Outcome)
	require.Len(t, audit.events, 1)
}

func TestDecide_ReasonerError(t *testing.T) {
	svc := NewService(fakeReasoner{err: errors.New("llm down")}, fakeGate{}, fakeConfidence{}, fakeBlast{}, &fakeAudit{}, nil, nil, nil)
	_, err := svc.Decide(context.Background(), aFinding)
	require.ErrorContains(t, err, "llm down")
}

func TestDecide_NoResourceSkipsBlastRadius(t *testing.T) {
	svc, _ := newSvc(policy.Decision{NeedsApproval: true}, memory.BandHigh, 5)
	d, err := svc.Decide(context.Background(), finding.Finding{ID: "f2"}) // no ResourceID
	require.NoError(t, err)
	require.Equal(t, 0, d.BlastRadius, "no resource => zero blast, blast provider not consulted")
	require.False(t, d.BlastRadiusKnown, "nothing was walked, so nothing was measured")
}

// fakeErrBlast always fails both the walk and the resolve fallback — the
// "ladybug/CH both down" shape blastRadiusFor's known=false branch guards.
type fakeErrBlast struct{ err error }

func (f fakeErrBlast) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	return asset.BlastRadius{}, f.err
}
func (f fakeErrBlast) ResolveID(_ context.Context, identifier string) (string, error) {
	return identifier, f.err
}

// TestDecide_BlastRadiusUnknown_PropagatesToDecisionAndAudit is the
// display-layer half of the known-ness fix: blastRadiusFor already computes
// the known bit correctly for the GATE, but it must also reach
// Decision.BlastRadiusKnown and the persisted audit JSON — otherwise the
// finding-detail UI and the decisions list can never tell "0 reachable
// assets" apart from "the walk failed".
func TestDecide_BlastRadiusUnknown_PropagatesToDecisionAndAudit(t *testing.T) {
	audit := &fakeAudit{}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "fix it"}},
		fakeGate{decision: policy.Decision{Escalate: true}},
		fakeConfidence{band: memory.BandInsufficient},
		fakeErrBlast{err: errors.New("ladybug and ch both down")},
		audit, nil, nil, nil,
	)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 0, d.BlastRadius)
	require.False(t, d.BlastRadiusKnown, "a failed walk must never read as a measured zero")

	require.Len(t, audit.events, 1)
	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(audit.events[0].Details), &details))
	require.Equal(t, false, details["blast_radius_known"],
		"the audit trail must carry the same known-ness the Decision struct does")
}

// TestDecide_BlastRadiusKnown_PropagatesToDecisionAndAudit is the mirror
// case: a successful zero-asset walk (genuinely isolated resource) must
// read as known=true, distinct from the failure case above.
func TestDecide_BlastRadiusKnown_PropagatesToDecisionAndAudit(t *testing.T) {
	audit := &fakeAudit{}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "fix it"}},
		fakeGate{decision: policy.Decision{Escalate: true}},
		fakeConfidence{band: memory.BandInsufficient},
		fakeBlast{n: 0},
		audit, nil, nil, nil,
	)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 0, d.BlastRadius)
	require.True(t, d.BlastRadiusKnown, "a walk that completed and found nothing IS a measurement")

	require.Len(t, audit.events, 1)
	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(audit.events[0].Details), &details))
	require.Equal(t, true, details["blast_radius_known"])
}

type countingReasoner struct{ n int }

func (r *countingReasoner) Reason(context.Context, ContextPack) (Plan, error) {
	r.n++
	return Plan{ActionClass: ClassRemediate, Summary: "fix it"}, nil
}

type fakeCache struct{ entries map[string]reasoncache.Entry }

func newFakeCache() *fakeCache { return &fakeCache{entries: map[string]reasoncache.Entry{}} }
func (c *fakeCache) Get(_ context.Context, id string) (reasoncache.Entry, error) {
	if e, ok := c.entries[id]; ok {
		return e, nil
	}
	return reasoncache.Entry{}, reasoncache.ErrNotFound
}
func (c *fakeCache) Put(_ context.Context, e reasoncache.Entry) error {
	c.entries[e.FindingID] = e
	return nil
}

func cacheSvc(rsn Reasoner, cache ReasoningCache, blast int) *Service {
	svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandMedium}, fakeBlast{n: blast}, &fakeAudit{}, cache, nil, nil)
	svc.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	return svc
}

func TestDecide_CacheHit_SkipsReasoner(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}

	_, err := cacheSvc(rsn, cache, 2).Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 1, rsn.n, "first decide reasons (cache miss) and caches")

	_, err = cacheSvc(rsn, cache, 2).Decide(context.Background(), aFinding) // unchanged context
	require.NoError(t, err)
	require.Equal(t, 1, rsn.n, "unchanged context reuses the cached plan — no LLM call")
}

type fakeReasonCacheObserver struct{ hits, misses int }

func (f *fakeReasonCacheObserver) ObserveReasonCacheLookup(hit bool) {
	if hit {
		f.hits++
	} else {
		f.misses++
	}
}

// A nil observer (the default, no WithReasonCacheMetrics call) must not panic —
// metrics are optional, mirroring every other Optional seam on Service.
func TestDecide_NilReasonCacheObserver_DoesNotPanic(t *testing.T) {
	cache := newFakeCache()
	_, err := cacheSvc(&countingReasoner{}, cache, 1).Decide(context.Background(), aFinding)
	require.NoError(t, err)
}

// The reason-cache hit/miss counter records exactly what planFor decided: a
// miss on first reason (and cache write), a hit on the unchanged repeat.
func TestDecide_RecordsReasonCacheHitAndMiss(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	obs := &fakeReasonCacheObserver{}

	svc := cacheSvc(rsn, cache, 2).WithReasonCacheMetrics(obs)
	_, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 0, obs.hits)
	require.Equal(t, 1, obs.misses)

	svc2 := cacheSvc(rsn, cache, 2).WithReasonCacheMetrics(obs) // unchanged context
	_, err = svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 1, obs.hits)
	require.Equal(t, 1, obs.misses)
}

func TestDecide_ContextChange_Reasons(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}

	_, err := cacheSvc(rsn, cache, 1).Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 1, rsn.n)

	_, err = cacheSvc(rsn, cache, 2).Decide(context.Background(), aFinding) // blast radius widened
	require.NoError(t, err)
	require.Equal(t, 2, rsn.n, "changed blast radius changes the fingerprint — re-reason")
}

func TestDecide_CachesFullTrace(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh, score: 0.9, effectiveN: 4.5, samples: 6},
		fakeBlast{n: 3}, &fakeAudit{}, cache, nil, nil)
	svc.now = func() time.Time { return time.Unix(1000, 0).UTC() }

	_, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	e, ok := cache.entries[aFinding.ID]
	require.True(t, ok, "the decision is cached")
	// The cache holds the whole 7-step trace, not just the plan.
	require.Equal(t, string(memory.BandHigh), e.ConfidenceBand)
	require.InDelta(t, 0.9, e.ConfidenceScore, 0.001)
	require.InDelta(t, 4.5, e.EffectiveN, 0.001)
	require.Equal(t, 6, e.SampleCount)
	require.Equal(t, 3, e.BlastRadius)
}

// cacheSvcGate builds a Service sharing the given cache/audit/notifier
// across calls, with a configurable gate decision — the seam the repeat-decision skip tests use
// to model "the same finding decided twice" (same cache) and "the gate outcome
// changed between sweeps" (different gate decision, same fingerprint inputs).
func cacheSvcGate(rsn Reasoner, cache ReasoningCache, gate policy.Decision, blast int,
	audit *fakeAudit, notifier *fakeNotifier) *Service {
	svc := NewService(rsn, fakeGate{decision: gate}, fakeConfidence{band: memory.BandMedium},
		fakeBlast{n: blast}, audit, cache, nil, nil)
	svc.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	if notifier != nil {
		svc.WithDecisionWebhook(notifier)
	}
	return svc
}

// Repeat-decision skip: a cache hit whose recomputed outcome is byte-identical to the
// cached entry's is a no-op repeat — the audit row, the webhook, and the memory
// outcome must all fire exactly once, not once per sweep.
func TestDecide_CacheHit_UnchangedOutcome_SkipsRecording(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}
	gate := policy.Decision{NeedsApproval: true}

	svc1 := cacheSvcGate(rsn, cache, gate, 2, audit, notifier)
	_, err := svc1.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	svc2 := cacheSvcGate(rsn, cache, gate, 2, audit, notifier) // unchanged context, unchanged gate
	d2, err := svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	require.Equal(t, 1, rsn.n, "second decide is a cache hit — no LLM call")
	require.Equal(t, OutcomeParked, d2.Outcome, "the reused decision still returns normally")
	require.Len(t, audit.events, 1, "byte-identical repeat is not re-recorded")
	require.Equal(t, 1, notifier.calls, "byte-identical repeat does not re-fire the webhook")
}

// Repeat-decision skip, guardrail case: a NEWLY TRIPPED CoVe concern must be recorded even
// though outcome and action class are unchanged. Neither the raw score nor the
// blast edge types are in the reason fingerprint, so a finding can cross the
// CoVe circuit-breaker threshold on a later sweep with everything the old
// two-field skip key compared still identical — and the skip would then have
// hidden the tripped guardrail permanently, since the cache entry is only
// refreshed on divergence.
func TestDecide_CacheHit_NewCoVeConcern_StillRecords(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	audit := &fakeAudit{}
	gate := policy.Decision{Escalate: true}

	// The reason fingerprint hashes ScoreBand, never the raw score — so a score
	// climbing within its band leaves the cache hitting while CoVe check 2
	// (>=5 reachable assets AND score >= 80) newly fires. Same blast set, same
	// band, same outcome, same class: only the guardrail changed.
	low := finding.Finding{ID: "f1", ResourceID: "i-1", ResourceType: "ec2_instance", Score: 10}
	high := low
	high.Score = 85

	_, err := cacheSvcGate(rsn, cache, gate, 5, audit, nil).Decide(context.Background(), low)
	require.NoError(t, err)
	require.Len(t, audit.events, 1)

	d2, err := cacheSvcGate(rsn, cache, gate, 5, audit, nil).Decide(context.Background(), high)
	require.NoError(t, err)
	require.Equal(t, 1, rsn.n, "the fingerprint is unchanged — still a cache hit, no LLM call")
	require.Equal(t, OutcomeEscalated, d2.Outcome, "same outcome as sweep 1")
	require.NotEmpty(t, d2.CoVeConcerns, "CoVe check 2 fired on the higher score")
	require.Len(t, audit.events, 2, "a newly tripped guardrail must reach the trail")
}

// Repeat-decision skip, confidence case: a band flip (insufficient -> high) with CoVe still
// forcing escalation leaves outcome and class unchanged, and must still record.
func TestDecide_CacheHit_ConfidenceBandFlip_StillRecords(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	audit := &fakeAudit{}
	gate := policy.Decision{Escalate: true}

	svc1 := NewService(rsn, fakeGate{decision: gate}, fakeConfidence{band: memory.BandInsufficient},
		fakeBlast{n: 1}, audit, cache, nil, nil)
	svc1.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	_, err := svc1.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Len(t, audit.events, 1)

	svc2 := NewService(rsn, fakeGate{decision: gate}, fakeConfidence{band: memory.BandHigh},
		fakeBlast{n: 1}, audit, cache, nil, nil)
	svc2.now = func() time.Time { return time.Unix(2000, 0).UTC() }
	d2, err := svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeEscalated, d2.Outcome, "the gate still escalates")
	require.Len(t, audit.events, 2, "the evidence behind the decision changed — record it")
}

// Repeat-decision skip: a reuse must never extend the cached plan's life. maxCacheAge (the
// 7-day forced re-reason) is measured against DecidedAt, so refreshing it
// on a divergence would let a finding whose outcome flips weekly keep its
// original LLM plan text forever.
func TestDecide_CacheHit_DivergedPut_PreservesDecidedAt(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}

	svc1 := cacheSvcGate(rsn, cache, policy.Decision{Escalate: true}, 1, &fakeAudit{}, nil)
	_, err := svc1.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	firstDecidedAt := cache.entries[aFinding.ID].DecidedAt
	require.False(t, firstDecidedAt.IsZero())

	// Sweep 2 diverges (gate now parks) a day later — inside maxCacheAge,
	// so the plan is genuinely reused rather than re-reasoned.
	svc2 := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandMedium}, fakeBlast{n: 1}, &fakeAudit{}, cache, nil, nil)
	svc2.now = func() time.Time { return time.Unix(1000, 0).UTC().Add(24 * time.Hour) }
	_, err = svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	e := cache.entries[aFinding.ID]
	require.Equal(t, string(OutcomeParked), e.Outcome, "the diverged outcome is written")
	require.Equal(t, firstDecidedAt, e.DecidedAt,
		"DecidedAt is the REASONING timestamp — a reuse must not push out the 7-day re-reason floor")
}

// Repeat-decision skip, divergence: a cache hit whose recomputed outcome DIVERGES from the cached
// entry — a policy/gate change — must never be masked: it records like a fresh
// decision, and the cache entry is refreshed so the NEXT sweep compares against
// the new state instead of re-recording forever.
func TestDecide_CacheHit_DivergingOutcome_RecordsAndUpdatesCache(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}

	svc1 := cacheSvcGate(rsn, cache, policy.Decision{NeedsApproval: true}, 2, audit, notifier)
	_, err := svc1.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	// Same fingerprint inputs (same finding, same blast count) — the LLM is
	// still not re-consulted — but the gate now escalates.
	svc2 := cacheSvcGate(rsn, cache, policy.Decision{Escalate: true}, 2, audit, notifier)
	d2, err := svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	require.Equal(t, 1, rsn.n, "still a cache hit — only the gate's verdict changed, not the context")
	require.Equal(t, OutcomeEscalated, d2.Outcome)
	require.Len(t, audit.events, 2, "a diverging outcome is recorded, not masked")
	require.Equal(t, 2, notifier.calls)

	e, ok := cache.entries[aFinding.ID]
	require.True(t, ok)
	require.Equal(t, string(OutcomeEscalated), e.Outcome,
		"the cache entry is refreshed to the new outcome so the next sweep compares against it")
}

// Repeat-decision skip, no cache hit: decisions that never hit the cache (fresh context every time)
// always record, regardless of whether the outcome happens to repeat.
func TestDecide_FreshDecisions_AlwaysRecord(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}
	gate := policy.Decision{NeedsApproval: true}

	svc1 := cacheSvcGate(rsn, cache, gate, 1, audit, notifier)
	_, err := svc1.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	// Blast radius widened -> fingerprint changes -> always a fresh reason,
	// even though the outcome (parked) is identical both times.
	svc2 := cacheSvcGate(rsn, cache, gate, 2, audit, notifier)
	_, err = svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	require.Equal(t, 2, rsn.n, "both decides reason — neither is a cache hit")
	require.Len(t, audit.events, 2, "fresh decisions always record, identical outcome or not")
	require.Equal(t, 2, notifier.calls)
}

func TestOutcomeFor(t *testing.T) {
	require.Equal(t, OutcomeObserved, outcomeFor(policy.Decision{AllowAuto: true}))
	require.Equal(t, OutcomeParked, outcomeFor(policy.Decision{NeedsApproval: true}))
	require.Equal(t, OutcomeEscalated, outcomeFor(policy.Decision{Escalate: true}))
}

// escalation_reason is set only on escalated decisions, and is
// "policy_blocked" for destroy/isolate regardless of what else fired — those
// two classes are the ones the gate escalates as policy-blocked, so that is
// the true reason even when CoVe also raised a concern.
func TestDecide_EscalationReason_PolicyBlockedForDestructiveActions(t *testing.T) {
	rsn := fakeReasoner{plan: Plan{ActionClass: ClassDestroy, Summary: "terminate it"}}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{Escalate: true}},
		fakeConfidence{band: memory.BandInsufficient}, fakeBlast{n: 1}, &fakeAudit{}, nil, nil, nil)

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeEscalated, d.Outcome)
	require.Equal(t, "policy_blocked", d.EscalationReason)
}

// A CoVe guardrail (not a destructive action class) escalating is
// "verification_concern".
func TestDecide_EscalationReason_VerificationConcern(t *testing.T) {
	// destructive (isolate) + internet-facing seed trips CoVe check 3, and the
	// gate would otherwise have allowed it — CoVe's fail-closed override is
	// what actually produced the escalation, so the class check above must not
	// also match: use modify instead of isolate/destroy to isolate the case.
	rsn := fakeReasoner{plan: Plan{ActionClass: ClassModify, Summary: "patch it"}}
	// Assets[0] is the seed (excluded from the reachable count — see
	// reachableAssets); 5 more so 5 REACHABLE assets trips check 2.
	blast := asset.BlastRadius{Assets: []asset.Asset{{PublicIP: "1.2.3.4"}, {}, {}, {}, {}, {}}}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh}, fakeBlastRadius{br: blast}, &fakeAudit{}, nil, nil, nil)

	f := aFinding
	f.Score = 90 // check 2: >=5 reachable assets + score >= 80
	d, err := svc.Decide(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, OutcomeEscalated, d.Outcome, "CoVe forces escalation regardless of the gate")
	require.Equal(t, "verification_concern", d.EscalationReason)
}

// Absent both a destructive action class and a CoVe concern, an escalation
// (from the gate alone, e.g. insufficient confidence) reads as
// "insufficient_confidence".
func TestDecide_EscalationReason_InsufficientConfidence(t *testing.T) {
	svc, _ := newSvc(policy.Decision{Escalate: true}, memory.BandInsufficient, 0)

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeEscalated, d.Outcome)
	require.Equal(t, "insufficient_confidence", d.EscalationReason)
}

// Non-escalated outcomes carry no escalation reason.
func TestDecide_EscalationReason_EmptyWhenNotEscalated(t *testing.T) {
	svc, _ := newSvc(policy.Decision{NeedsApproval: true}, memory.BandHigh, 1)

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Empty(t, d.EscalationReason)
}

// fakeBlastRadius returns a fixed BlastRadius value regardless of seed —
// letting tests control edges/assets/public IPs precisely (fakeBlast only
// controls the asset count).
type fakeBlastRadius struct{ br asset.BlastRadius }

func (f fakeBlastRadius) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	return f.br, nil
}

func (f fakeBlastRadius) ResolveID(_ context.Context, identifier string) (string, error) {
	return identifier, nil
}

// fakeExecCap is a fixed-answer ActionApplicability for the executor-applicability tests.
type fakeExecCap map[string]bool

func (f fakeExecCap) HasExecutableAction(resourceType string) bool { return f[resourceType] }

// A remediate plan against a resource type with no wired executor action is
// ANNOTATED and otherwise untouched. Downgrading it to observe would be wrong:
// observe auto-runs unconditionally, drops out of the human governor queue
// (ListPendingReasoning filters to parked/escalated) and is dropped by the
// webhook notifier — so most finding resource types would have their
// actionable findings quietly disappear from both. This test pins the class NOT changing.
func TestDecide_UnexecutablePlan_IsAnnotatedNotDowngraded(t *testing.T) {
	rsn := fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "remediate the DNS record"}}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{Escalate: true}},
		fakeConfidence{band: memory.BandInsufficient}, fakeBlast{n: 0}, &fakeAudit{}, nil, nil, nil).
		WithExecutorCapability(fakeExecCap{"ec2_instance": true, "security_group": true})

	f := finding.Finding{ID: "f-dns", ResourceID: "sub.example.com", ResourceType: "dns_record"}
	d, err := svc.Decide(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, ClassRemediate, d.Plan.ActionClass,
		"the plan's class must survive: no executor action is not the same as nothing to do")
	require.Contains(t, d.PlanNotes[0], "no in-cluster executor action for dns_record")
	require.Equal(t, OutcomeEscalated, d.Outcome, "it still reaches a human")
}

// A resource type WITH a wired executor action is left unchanged.
func TestDecide_ExecutablePlan_Unchanged(t *testing.T) {
	rsn := fakeReasoner{plan: Plan{ActionClass: ClassModify, Summary: "modify the instance"}}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandMedium}, fakeBlast{n: 0}, &fakeAudit{}, nil, nil, nil).
		WithExecutorCapability(fakeExecCap{"ec2_instance": true})

	f := finding.Finding{ID: "f-ec2", ResourceID: "i-1", ResourceType: "ec2_instance"}
	d, err := svc.Decide(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, ClassModify, d.Plan.ActionClass, "an executable resource type is never reclassified")
	require.Empty(t, d.PlanNotes)
}

// destroy/isolate are never annotated either — the note is triage context for
// remediate/modify plans, and these classes always reach a human regardless.
func TestDecide_DestructivePlan_NeverReclassified(t *testing.T) {
	rsn := fakeReasoner{plan: Plan{ActionClass: ClassDestroy, Summary: "destroy the record"}}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{Escalate: true}},
		fakeConfidence{band: memory.BandInsufficient}, fakeBlast{n: 0}, &fakeAudit{}, nil, nil, nil).
		WithExecutorCapability(fakeExecCap{}) // nothing is executable

	f := finding.Finding{ID: "f-dns2", ResourceID: "sub.example.com", ResourceType: "dns_record"}
	d, err := svc.Decide(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, ClassDestroy, d.Plan.ActionClass, "destroy is never rewritten")
	require.Empty(t, d.PlanNotes)
	require.Equal(t, OutcomeEscalated, d.Outcome)
}

// A nil executor capability (the default — WithExecutorCapability never
// called) disables the check entirely, matching every other optional seam on
// Service.
func TestDecide_NilExecutorCapability_NeverReclassifies(t *testing.T) {
	svc, _ := newSvc(policy.Decision{NeedsApproval: true}, memory.BandMedium, 0)
	f := finding.Finding{ID: "f-dns3", ResourceID: "sub.example.com", ResourceType: "dns_record"}

	d, err := svc.Decide(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, ClassRemediate, d.Plan.ActionClass, "no executor capability wired => no annotation, no change")
	require.Empty(t, d.PlanNotes)
}

// nameKeyedBlast models the graph as it really is: nodes are keyed by ARN, and a
// walk seeded with anything else finds nothing. ResolveID maps the bare name to
// the ARN the way asset.Service does.
type nameKeyedBlast struct {
	arn      string
	name     string
	reach    int
	resolved []string // every identifier ResolveID was asked for
	seeded   []string // every seed BlastRadius was walked from
}

func (f *nameKeyedBlast) BlastRadius(_ context.Context, seedID string, _ int) (asset.BlastRadius, error) {
	f.seeded = append(f.seeded, seedID)
	if seedID != f.arn {
		return asset.BlastRadius{}, asset.ErrNotFound
	}
	return asset.BlastRadius{SeedID: seedID, Assets: make([]asset.Asset, f.reach)}, nil
}

func (f *nameKeyedBlast) ResolveID(_ context.Context, identifier string) (string, error) {
	f.resolved = append(f.resolved, identifier)
	if identifier == f.name || identifier == f.arn {
		return f.arn, nil
	}
	return "", asset.ErrNotFound
}

// A GuardDuty iam_user finding carries the role NAME (guardDutyResource →
// AccessKeyDetails.UserName) while the graph is keyed by ARN. Before ResolveID
// the walk seeded the bare name, found nothing, and reported a zero blast radius
// for a live credential compromise — which the narrative then described as
// "limited real risk".
func TestBlastRadiusFor_ResolvesNameKeyedResourceID(t *testing.T) {
	const (
		roleName = "example-app-TaskRole-ABC123EXAMPLE"
		roleARN  = "arn:aws:iam::210987654321:role/" + roleName
	)
	blast := &nameKeyedBlast{arn: roleARN, name: roleName, reach: 37}
	svc := NewReadService(blast, nil, nil)

	br, known := svc.blastRadiusFor(context.Background(), roleName)

	require.True(t, known, "a walk that resolved and completed is a measurement")
	require.Len(t, br.Assets, 37, "blast radius must be walked from the resolved ARN")
	require.Equal(t, roleARN, br.SeedID)
	require.Equal(t, []string{roleName}, blast.resolved)
	// The raw ID is attempted first (so ID-keyed sources pay no resolution cost);
	// only its miss triggers ResolveID and the second, canonical seed.
	require.Equal(t, []string{roleName, roleARN}, blast.seeded)
}

// Sources that already key findings by asset ID must be unaffected: no extra
// walk, same seed, same result.
func TestBlastRadiusFor_IDKeyedResourceIDUnchanged(t *testing.T) {
	const arn = "arn:aws:iam::210987654321:role/already-canonical"
	blast := &nameKeyedBlast{arn: arn, name: "already-canonical", reach: 4}
	svc := NewReadService(blast, nil, nil)

	br, known := svc.blastRadiusFor(context.Background(), arn)

	require.True(t, known)
	require.Len(t, br.Assets, 4)
	require.Equal(t, []string{arn}, blast.seeded)
	require.Empty(t, blast.resolved, "an ID-keyed resource must not pay for the substring search")
}

// An identifier that resolves to nothing must fall back to the raw ID and return
// zero blast rather than erroring — a missing asset was never fatal. It must NOT
// report that zero as a measurement, though: "touches nothing" is what the
// approver would read, the most reassuring thing an unwalkable resource could
// claim.
func TestBlastRadiusFor_UnresolvableIsUnmeasuredNotZero(t *testing.T) {
	blast := &nameKeyedBlast{arn: "arn:aws:iam::1:role/known", name: "known", reach: 9}
	svc := NewReadService(blast, nil, nil)

	br, known := svc.blastRadiusFor(context.Background(), "no-such-resource")

	require.False(t, known, "nothing was walked, so nothing was measured")
	require.Empty(t, br.Assets)
	require.Equal(t, []string{"no-such-resource"}, blast.seeded, "no second walk when nothing resolves")
}

// ── Pattern verdict tests ────────────────────────────────────────────────────

// DENIED: a human already ruled on this whole (check_id, action_class)
// pattern. Decide must suppress rather than re-escalate — no gate call and no
// webhook — but must still audit the decision.
func TestDecide_PatternDenied_Suppresses(t *testing.T) {
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}
	gate := &countingGate{decision: policy.Decision{NeedsApproval: true}}
	pv := &fakePatternVerdicts{verdict: patternVerdictDenied, found: true}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "fix it"}},
		gate, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1},
		audit, nil, nil, nil,
	).WithDecisionWebhook(notifier).WithPatternVerdicts(pv)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	f := finding.Finding{ID: "f1", CheckID: "aws-s3-public-bucket", ResourceID: "i-1", ResourceType: "s3_bucket"}
	d, err := svc.Decide(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, OutcomeSuppressedByVerdict, d.Outcome)
	require.Equal(t, "pattern_denied", d.EscalationReason)
	require.Zero(t, gate.calls, "a denied pattern short-circuits before the gate is ever consulted")
	require.Zero(t, notifier.calls, "a suppressed decision must never notify the webhook")
	require.Len(t, audit.events, 1, "still auditable — a human can see it was suppressed and why")
	// Scoping guard: the lookup must be scoped by the finding's OWN check_id,
	// action class and resource type — a fake that silently discarded any of
	// these would leave the resource-type scoping unguarded and every test
	// here would stay green even if Decide re-opened the estate-wide
	// suppression the scoping exists to close.
	require.Equal(t, "aws-s3-public-bucket", pv.gotCheckID)
	require.Equal(t, string(ClassRemediate), pv.gotActionClass)
	require.Equal(t, "s3_bucket", pv.gotResourceType)
}

// A denied pattern on a destroy-class plan must still suppress, never let the
// gate verdict the fake would otherwise return turn it back into a proposal.
func TestDecide_PatternDenied_DestroyClass_StaysSuppressed(t *testing.T) {
	gate := &countingGate{decision: policy.Decision{NeedsApproval: true}} // would park if ever consulted
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassDestroy, Summary: "delete it"}},
		gate, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 0},
		&fakeAudit{}, nil, nil, nil,
	).WithPatternVerdicts(&fakePatternVerdicts{verdict: patternVerdictDenied, found: true})
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeSuppressedByVerdict, d.Outcome)
	require.NotEqual(t, OutcomeParked, d.Outcome)
	require.Zero(t, gate.calls)
}

// APPROVED is not standing consent: outcome and gate behave exactly as
// without a pattern verdict — the only difference is an annotation.
func TestDecide_PatternApproved_AnnotatesOnly(t *testing.T) {
	svc, audit := newSvc(policy.Decision{NeedsApproval: true}, memory.BandHigh, 3)
	svc.WithPatternVerdicts(&fakePatternVerdicts{verdict: patternVerdictApproved, found: true})

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeParked, d.Outcome,
		"an approved pattern never bypasses the gate/confidence ledger — it only annotates")
	require.Len(t, audit.events, 1)
	require.Len(t, d.PlanNotes, 1)
	require.Contains(t, d.PlanNotes[0], "previously approved")
}

// No verdict recorded for this pattern: behave exactly as before this
// feature existed.
func TestDecide_NoPatternVerdictFound_Unchanged(t *testing.T) {
	svc, _ := newSvc(policy.Decision{NeedsApproval: true}, memory.BandHigh, 3)
	svc.WithPatternVerdicts(&fakePatternVerdicts{found: false})

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeParked, d.Outcome)
	require.Empty(t, d.PlanNotes)
}

// A lookup error must fail open — never fail the decision, never suppress it.
func TestDecide_PatternVerdictLookupError_FailsOpen(t *testing.T) {
	svc, _ := newSvc(policy.Decision{NeedsApproval: true}, memory.BandHigh, 3)
	svc.WithPatternVerdicts(&fakePatternVerdicts{err: errors.New("pg down")})

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err, "a pattern-verdict lookup failure must never fail a decision")
	require.Equal(t, OutcomeParked, d.Outcome)
	require.Empty(t, d.PlanNotes)
}

// The repeat-decision skip applies to the suppressed path too: a byte-identical suppressed
// repeat is not re-recorded.
func TestDecide_PatternDenied_RepeatSkipsRecording(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	audit := &fakeAudit{}
	notifier := &fakeNotifier{}
	pv := &fakePatternVerdicts{verdict: patternVerdictDenied, found: true}

	build := func() *Service {
		svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
			fakeConfidence{band: memory.BandMedium}, fakeBlast{n: 2}, audit, cache, nil, nil).
			WithDecisionWebhook(notifier).WithPatternVerdicts(pv)
		svc.now = func() time.Time { return time.Unix(1000, 0).UTC() }
		return svc
	}

	d1, err := build().Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeSuppressedByVerdict, d1.Outcome)

	d2, err := build().Decide(context.Background(), aFinding) // unchanged context
	require.NoError(t, err)
	require.Equal(t, OutcomeSuppressedByVerdict, d2.Outcome)

	require.Equal(t, 1, rsn.n, "unchanged context reuses the cached plan — no second LLM call")
	require.Len(t, audit.events, 1, "a byte-identical suppressed repeat is not re-recorded")
	require.Zero(t, notifier.calls, "a suppressed decision never notifies, repeat or not")
}

// A pattern verdict older than PatternVerdictMaxAge must be treated as
// though it were never found — the estate changes underneath a human's
// ruling, so a stale DENIED must fall through to the normal gate path rather
// than suppress forever.
func TestDecide_PatternVerdict_ExpiredIsTreatedAsNotFound(t *testing.T) {
	svc, _ := newSvc(policy.Decision{NeedsApproval: true}, memory.BandHigh, 3)
	decidedAt := svc.now().Add(-PatternVerdictMaxAge - time.Second) // one second past the boundary
	svc.WithPatternVerdicts(&fakePatternVerdicts{verdict: patternVerdictDenied, found: true, decidedAt: decidedAt})

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeParked, d.Outcome,
		"an expired verdict must never suppress — decide exactly as if none was recorded")
	require.NotEqual(t, OutcomeSuppressedByVerdict, d.Outcome)
}

// The other side of the same boundary: a verdict decided exactly
// PatternVerdictMaxAge ago (not older) is still trusted and suppresses.
func TestDecide_PatternVerdict_AtMaxAgeStillSuppresses(t *testing.T) {
	audit := &fakeAudit{}
	gate := &countingGate{decision: policy.Decision{NeedsApproval: true}}
	svc := NewService(
		fakeReasoner{plan: Plan{ActionClass: ClassRemediate, Summary: "fix it"}},
		gate, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1},
		audit, nil, nil, nil,
	)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }
	decidedAt := svc.now().Add(-PatternVerdictMaxAge) // exactly at the boundary, not past it
	svc.WithPatternVerdicts(&fakePatternVerdicts{verdict: patternVerdictDenied, found: true, decidedAt: decidedAt})

	d, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeSuppressedByVerdict, d.Outcome, "exactly at the max age, the verdict is still trusted")
	require.Zero(t, gate.calls)
}

// A suppressed decision that reuses an already-rich cache
// entry must carry the prior MEASURED confidence/blast forward into the
// refreshed cache entry — it declined to measure them, it did not measure
// zero. A regression here would make the finding-detail panel render
// "confidence 0.00 / blast 0" over what a moment ago read real numbers.
func TestDecide_PatternDenied_ReusedEntry_PreservesMeasurements(t *testing.T) {
	cache := newFakeCache()

	// Pass 1: no pattern verdict wired — parks and populates a rich
	// cache entry (real confidence band/score/effectiveN/sampleCount).
	svc1 := NewService(&countingReasoner{}, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh, score: 0.92, effectiveN: 11, samples: 4},
		fakeBlast{n: 11}, &fakeAudit{}, cache, nil, nil)
	svc1.now = func() time.Time { return time.Unix(1000, 0).UTC() }

	d1, err := svc1.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeParked, d1.Outcome)

	cached, err := cache.Get(context.Background(), aFinding.ID)
	require.NoError(t, err)
	require.Equal(t, "high", cached.ConfidenceBand)
	require.InDelta(t, 0.92, cached.ConfidenceScore, 0.0001)
	require.Equal(t, 11, cached.BlastRadius)

	// Pass 2: identical finding/context (same fingerprint => reused), but now
	// a pattern verdict denies the pattern, so Decide suppresses.
	svc2 := NewService(&countingReasoner{}, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh, score: 0.92, effectiveN: 11, samples: 4},
		fakeBlast{n: 11}, &fakeAudit{}, cache, nil, nil).
		WithPatternVerdicts(&fakePatternVerdicts{verdict: patternVerdictDenied, found: true})
	svc2.now = func() time.Time { return time.Unix(1000, 0).UTC() }

	d2, err := svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, OutcomeSuppressedByVerdict, d2.Outcome)

	refreshed, err := cache.Get(context.Background(), aFinding.ID)
	require.NoError(t, err)
	require.Equal(t, string(OutcomeSuppressedByVerdict), refreshed.Outcome)
	require.Equal(t, "high", refreshed.ConfidenceBand,
		"a suppressed decision declined to measure confidence — it must not overwrite the prior real measurement with zero")
	require.InDelta(t, 0.92, refreshed.ConfidenceScore, 0.0001)
	require.InDelta(t, 11, refreshed.EffectiveN, 0.0001)
	require.Equal(t, 4, refreshed.SampleCount)
	require.Equal(t, 11, refreshed.BlastRadius, "blast radius IS measured on the suppressed path too, reused or not")
}

// The reasoning cache's repeat counter has no other caller — this is the
// wiring test proving it actually fires on the repeat-decision skip path,
// and only there.
type fakeRepeatTracker struct {
	counts map[string]int
}

func newFakeRepeatTracker() *fakeRepeatTracker { return &fakeRepeatTracker{counts: map[string]int{}} }

func (f *fakeRepeatTracker) IncrementRepeat(_ context.Context, findingID string) error {
	f.counts[findingID]++
	return nil
}

func TestDecide_RepeatTracker_IncrementsOnlyOnMatchedRepeat(t *testing.T) {
	cache := newFakeCache()
	tracker := newFakeRepeatTracker()
	rsn := &countingReasoner{}
	gate := policy.Decision{NeedsApproval: true}

	build := func() *Service {
		svc := NewService(rsn, fakeGate{decision: gate}, fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 2},
			&fakeAudit{}, cache, nil, nil).
			WithRepeatTracker(tracker)
		svc.now = func() time.Time { return time.Unix(1000, 0).UTC() }
		return svc
	}

	// Fresh decision: not a repeat, counter must not move.
	_, err := build().Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Zero(t, tracker.counts[aFinding.ID], "a fresh (first-ever) decision is not a repeat")

	// Byte-identical repeat: same finding, same context, same conclusion —
	// the repeat-decision skip path fires, and the tracker must register it.
	_, err = build().Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 1, tracker.counts[aFinding.ID], "a matched repeat increments the tracker exactly once")

	// A second byte-identical repeat increments again.
	_, err = build().Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 2, tracker.counts[aFinding.ID])
}

// A diverging repeat (same fingerprint, different conclusion) is recorded
// normally, not routed through the skip path — the tracker must not move.
func TestDecide_RepeatTracker_NotIncrementedOnDivergingDecision(t *testing.T) {
	cache := newFakeCache()
	tracker := newFakeRepeatTracker()
	rsn := &countingReasoner{}

	svc1 := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 2}, &fakeAudit{}, cache, nil, nil).
		WithRepeatTracker(tracker)
	svc1.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	_, err := svc1.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	// Same fingerprint (unchanged finding), but the gate verdict now differs
	// -> outcome diverges from the cached entry -> recorded fresh, not a skip.
	svc2 := NewService(rsn, fakeGate{decision: policy.Decision{Escalate: true}},
		fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 2}, &fakeAudit{}, cache, nil, nil).
		WithRepeatTracker(tracker)
	svc2.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	_, err = svc2.Decide(context.Background(), aFinding)
	require.NoError(t, err)

	require.Zero(t, tracker.counts[aFinding.ID], "a diverging decision is recorded, not skipped — the tracker must not fire")
}

// TestConcernDigest_IgnoresVolatileNumbers: cove.go's concern strings
// interpolate the exact score/blast/threshold values that tripped them, and
// those wiggle sweep to sweep without the guardrail's identity changing.
// Digesting them raw would make a same-band score drift look like "a new
// decision" to skipRecord, causing a
// duplicate audit row and a duplicate re-notify to the decision webhook.
func TestConcernDigest_IgnoresVolatileNumbers(t *testing.T) {
	a := []string{"weighted blast radius 10.4 ≥ 10.0 — human review mandatory"}
	b := []string{"weighted blast radius 12.9 ≥ 10.0 — human review mandatory"}
	require.Equal(t, concernDigest(a), concernDigest(b),
		"the same guardrail tripping with different exact numbers must digest identically")

	c := []string{"68 reachable assets with enriched score 80"}
	d := []string{"67 reachable assets with enriched score 81"}
	require.Equal(t, concernDigest(c), concernDigest(d))
}

// A genuinely different guardrail (not just a different number on the same
// one) must still digest differently — the fix strips numbers, not meaning.
func TestConcernDigest_DifferentGuardrailsStillDiffer(t *testing.T) {
	blast := []string{"weighted blast radius 10.4 ≥ 10.0 — human review mandatory"}
	wideReach := []string{"68 reachable assets with enriched score 80"}
	require.NotEqual(t, concernDigest(blast), concernDigest(wideReach))
}

// Order-independence survives the number-stripping change.
func TestConcernDigest_StillOrderIndependent(t *testing.T) {
	require.Equal(t,
		concernDigest([]string{"a 1", "b 2"}),
		concernDigest([]string{"b 2", "a 1"}))
}

// packReasoner records the pack it was asked to reason over.
type packReasoner struct {
	got ContextPack
	n   int
}

func (r *packReasoner) Reason(_ context.Context, p ContextPack) (Plan, error) {
	r.got = p
	r.n++
	return Plan{ActionClass: ClassRemediate, Summary: "fix it"}, nil
}

type fakeFactors struct {
	factors []enrich.Factor
	err     error
	calls   int
}

func (f *fakeFactors) Factors(context.Context, string) ([]enrich.Factor, error) {
	f.calls++
	return f.factors, f.err
}

// The score factors exist only for the reasoner, so they must be in the pack
// it reasons over — loading them after the call (as before) meant the model
// never saw the "Score breakdown" block.
func TestDecide_ReasonerSeesScoreFactors(t *testing.T) {
	rsn := &packReasoner{}
	factors := &fakeFactors{factors: []enrich.Factor{{Source: "kev", Points: 30, Floor: 81}}}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1}, &fakeAudit{}, nil, nil, nil).WithFactors(factors)
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	_, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 1, rsn.n)
	require.True(t, rsn.got.FactorsKnown)
	require.Equal(t, factors.factors, rsn.got.Factors)
}

// A failed factors read reaches the reasoner as unknown, never as a
// successful read that found nothing.
func TestDecide_FactorsReadError_ReasonerSeesUnknown(t *testing.T) {
	rsn := &packReasoner{}
	svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1}, &fakeAudit{}, nil, nil, nil).
		WithFactors(&fakeFactors{err: errors.New("clickhouse: timeout")})
	svc.now = func() time.Time { return time.Unix(0, 0).UTC() }

	_, err := svc.Decide(context.Background(), aFinding)
	require.NoError(t, err, "a factors read failure degrades the context, it does not fail the decision")
	require.False(t, rsn.got.FactorsKnown)
	require.Nil(t, rsn.got.Factors)
}

func factorsCacheSvc(rsn Reasoner, cache ReasoningCache, factors *fakeFactors) *Service {
	svc := NewService(rsn, fakeGate{decision: policy.Decision{NeedsApproval: true}},
		fakeConfidence{band: memory.BandHigh}, fakeBlast{n: 1}, &fakeAudit{}, cache, nil, nil).WithFactors(factors)
	svc.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	return svc
}

// A plan reasoned while the score breakdown was unreadable must not be
// reused once it is readable: FactorsKnown is in the fingerprint, so the
// factors have to be loaded before it is computed.
func TestDecide_FactorsUnknownThenKnown_Rereasons(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	factors := &fakeFactors{err: errors.New("clickhouse: timeout")}

	_, err := factorsCacheSvc(rsn, cache, factors).Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 1, rsn.n)

	factors.err = nil
	factors.factors = []enrich.Factor{{Source: "kev", Points: 30}}
	_, err = factorsCacheSvc(rsn, cache, factors).Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 2, rsn.n, "the factors becoming readable is a new context, not a cache hit")
}

// Readable factors on both runs leave the fingerprint unchanged, so the
// cached plan is reused.
func TestDecide_FactorsKnownTwice_ReusesPlan(t *testing.T) {
	cache := newFakeCache()
	rsn := &countingReasoner{}
	factors := &fakeFactors{factors: []enrich.Factor{{Source: "kev", Points: 30}}}

	_, err := factorsCacheSvc(rsn, cache, factors).Decide(context.Background(), aFinding)
	require.NoError(t, err)
	_, err = factorsCacheSvc(rsn, cache, factors).Decide(context.Background(), aFinding)
	require.NoError(t, err)
	require.Equal(t, 1, rsn.n, "an unchanged, measured context reuses the cached plan")
	require.Equal(t, 2, factors.calls, "the fingerprint needs FactorsKnown, so every Decide reads the factors")
}
