package jobs

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// pastEnrich is a fixed enriched_at in the past: a never-adjudicated finding
// (adj_at = zero time) is < pastEnrich, so the cursor includes it; a belief
// written during a sweep (created ≈ now) is > pastEnrich, so the finding is then
// excluded until re-enriched — the mechanism the cursor tests exercise.
var pastEnrich = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// cursorStore is a faithful in-memory model of the belief store's coverage cursor
// (belief.CHRepo.AdjudicationCandidates): it returns the eligible findings that
// have NOT been freshly adjudicated, least-recently-adjudicated first, mirroring
// the SQL anti-join. The real SQL is exercised in belief/repo_integration_test.go;
// this lets the worker's advance/skip behavior be proven without ClickHouse.
type cursorStore struct {
	eligible    []finding.Finding // the eligible backlog rows (EnrichedAt set)
	saved       []belief.Belief
	reqMinScore uint8     // records the minScore the worker asked for
	reqStale    time.Time // records the revalidation horizon the worker asked for
}

func (m *cursorStore) Upsert(_ context.Context, bs []belief.Belief) error {
	m.saved = append(m.saved, bs...)
	return nil
}

func (m *cursorStore) GetByFinding(_ context.Context, id string) (belief.Belief, error) {
	found := false
	var latest belief.Belief
	for _, b := range m.saved {
		if b.FindingID == id {
			latest, found = b, true
		}
	}
	if !found {
		return belief.Belief{}, belief.ErrNotFound
	}
	return latest, nil
}

func (m *cursorStore) GetByProvenance(_ context.Context, id, provenance string) (belief.Belief, error) {
	found := false
	var latest belief.Belief
	for _, b := range m.saved {
		if b.FindingID == id && b.Provenance == provenance {
			latest, found = b, true
		}
	}
	if !found {
		return belief.Belief{}, belief.ErrNotFound
	}
	return latest, nil
}

func (m *cursorStore) CrystallizationInputs(context.Context) ([]belief.CrystallizationInput, error) {
	return nil, nil
}

// AdjudicationCandidates mirrors selectAdjudicationBacklog: eligible findings
// re-enter when never/stale-by-enrich (checked_at < enriched_at) or past the
// revalidation horizon (adj_at < staleBefore), least-recently-checked first.
func (m *cursorStore) AdjudicationCandidates(_ context.Context, minScore uint8, staleBefore time.Time, limit int) ([]string, error) {
	m.reqMinScore = minScore
	m.reqStale = staleBefore
	type row struct {
		id        string
		checkedAt time.Time
	}
	var rows []row
	for _, f := range m.eligible {
		if f.Score < minScore {
			continue
		}
		adjAt, checkedAt := m.latestAdj(f.ID)
		if checkedAt.Before(f.EnrichedAt) || adjAt.Before(staleBefore) {
			rows = append(rows, row{f.ID, checkedAt})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].checkedAt.Before(rows[j].checkedAt) })
	var out []string
	for _, r := range rows {
		if len(out) >= limit {
			break
		}
		out = append(out, r.id)
	}
	return out, nil
}

// latestAdj returns max(created_at) and max(checked_at) over the finding's
// adjudicator rows, as the SQL's adj CTE does.
func (m *cursorStore) latestAdj(id string) (adjAt, checkedAt time.Time) {
	for _, b := range m.saved {
		if b.FindingID != id || b.Provenance != belief.ProvenanceAdjudicator {
			continue
		}
		if b.CreatedAt.After(adjAt) {
			adjAt = b.CreatedAt
		}
		if c := b.LastChecked(); c.After(checkedAt) {
			checkedAt = c
		}
	}
	return adjAt, checkedAt
}

// mapFindingSource hydrates candidate findings by id. Order is not preserved (the
// adjudicator re-sorts by score); gotIDs records the last hydration request so a
// test can assert which findings the cursor selected.
type mapFindingSource struct {
	byID   map[string]finding.Finding
	gotIDs []string
}

func (s *mapFindingSource) ByIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	s.gotIDs = append([]string(nil), ids...)
	var out []finding.Finding
	for _, id := range ids {
		if f, ok := s.byID[id]; ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// fakeAssembler returns an empty pack (finding-only context path). PeersKnown:
// true because this simulates a SUCCESSFUL assembly that simply found no
// peers/exposure signal — real buildContextPack always sets this bit one way
// or the other on success; only a failed assembly (or a failed peer query
// within an otherwise-successful one) leaves it false.
type fakeAssembler struct{ calls int }

func (a *fakeAssembler) Context(context.Context, finding.Finding) (respond.ContextPack, error) {
	a.calls++
	return respond.ContextPack{Exposure: respond.ExposureFlags{PeersKnown: true}, Blast: respond.BlastSummary{Known: true}}, nil
}

// recordingSampler records every input it is asked to sample and returns Low
// (disagreeing with a Critical deterministic guess → drives full adjudication).
type recordingSampler struct{ seen []string }

func (s *recordingSampler) Sample(_ context.Context, in belief.AdjudicationInput) (belief.Verdict, error) {
	s.seen = append(s.seen, in.FindingID)
	return belief.Verdict{
		Severity: finding.SeverityLow,
		Evidence: []belief.Evidence{{Clause: "unreachable", Source: "reachability", Fact: "no path"}},
	}, nil
}

// eligibleFindings builds a source + store seeded with the given findings as the
// eligible backlog (all enriched in the past so the cursor includes them).
func eligibleFindings(fs ...finding.Finding) (*mapFindingSource, *cursorStore) {
	byID := map[string]finding.Finding{}
	elig := make([]finding.Finding, len(fs))
	for i, f := range fs {
		f.EnrichedAt = pastEnrich
		fs[i] = f
		byID[f.ID] = f
		elig[i] = f
	}
	return &mapFindingSource{byID: byID}, &cursorStore{eligible: elig}
}

func TestAdjudicateWorker_OnlyGatedFindingsAdjudicated(t *testing.T) {
	src, store := eligibleFindings(
		// Gated: high band, no resolving must-fix class → needs adjudication.
		finding.Finding{ID: "f1", ResourceID: "r1", Title: "open", Score: 90, ScoreBand: "page"},
		// Not gated: deterministically resolved as controlled → skipped.
		finding.Finding{ID: "f2", ResourceID: "r2", Title: "controlled", Score: 90, ScoreBand: "page", MustFixClass: "controlled"},
		// Not gated: already evidence-backed must-fix → skipped.
		finding.Finding{ID: "f3", ResourceID: "r3", Title: "must", Score: 95, ScoreBand: "page", MustFixClass: "must_fix"},
	)
	assembler := &fakeAssembler{}
	sampler := &recordingSampler{}
	w := &AdjudicateWorker{
		findings:    src,
		assembler:   assembler,
		adjudicator: belief.NewAdjudicator(store, sampler, belief.DefaultSweepConfig()),
	}

	err := w.Work(context.Background(), &river.Job[AdjudicateArgs]{})
	require.NoError(t, err)

	// Only f1 passed the attention gate → only it was sampled and its context assembled.
	require.Equal(t, []string{"f1"}, uniq(sampler.seen), "only the gated finding is adjudicated")
	require.Equal(t, 1, assembler.calls, "context assembled once, for the gated finding only")
	require.Len(t, store.saved, 1)
	require.Equal(t, "f1", store.saved[0].FindingID)
	require.Equal(t, finding.SeverityLow, store.saved[0].Severity)

	// The backlog cursor is queried at the high-band floor.
	require.Equal(t, uint8(61), store.reqMinScore)
	require.WithinDuration(t, time.Now().Add(-7*24*time.Hour), store.reqStale, time.Minute,
		"revalidation horizon matches the sweep's RevalidateAfter")
}

// The cursor advances: consecutive sweeps over the SAME eligible set adjudicate
// DIFFERENT findings, because each processed finding gets a belief that moves it
// out of the candidate set. A per-sweep cap of 2 forces the backlog to drain
// across sweeps rather than in one shot.
func TestAdjudicateWorker_CursorAdvancesAcrossSweeps(t *testing.T) {
	// Distinct scores so the per-sweep cap picks a deterministic, highest-first pair.
	src, store := eligibleFindings(
		finding.Finding{ID: "f1", ResourceID: "r1", Score: 99, ScoreBand: "page"},
		finding.Finding{ID: "f2", ResourceID: "r2", Score: 98, ScoreBand: "page"},
		finding.Finding{ID: "f3", ResourceID: "r3", Score: 97, ScoreBand: "page"},
		finding.Finding{ID: "f4", ResourceID: "r4", Score: 96, ScoreBand: "page"},
		finding.Finding{ID: "f5", ResourceID: "r5", Score: 95, ScoreBand: "page"},
	)
	cfg := belief.SweepConfig{MaxPerSweep: 2, EscalateN: 3, RevalidateAfter: 7 * 24 * time.Hour}
	w := &AdjudicateWorker{
		findings:    src,
		assembler:   &fakeAssembler{},
		adjudicator: belief.NewAdjudicator(store, &recordingSampler{}, cfg),
	}
	run := func() []string {
		before := len(store.saved)
		require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
		var ids []string
		for _, b := range store.saved[before:] {
			ids = append(ids, b.FindingID)
		}
		ids = uniq(ids)
		sort.Strings(ids)
		return ids
	}

	sweep1 := run()
	require.Equal(t, []string{"f1", "f2"}, sweep1, "highest-score pair adjudicated first")

	sweep2 := run()
	require.Equal(t, []string{"f3", "f4"}, sweep2, "sweep advances past the already-adjudicated head")
	require.NotContains(t, src.gotIDs, "f1", "a freshly-adjudicated finding is not re-listed")
	require.NotContains(t, src.gotIDs, "f2")

	sweep3 := run()
	require.Equal(t, []string{"f5"}, sweep3, "the tail of the backlog is finally reached")

	// Every eligible finding was adjudicated exactly once across the three sweeps.
	all := append(append(append([]string{}, sweep1...), sweep2...), sweep3...)
	sort.Strings(all)
	require.Equal(t, []string{"f1", "f2", "f3", "f4", "f5"}, all)
}

// A finding whose belief is fresh (adjudicated this window, inputs unchanged) is
// skipped; re-enrichment that changes its evidence makes it eligible again.
func TestAdjudicateWorker_ReEnrichedBecomesEligibleAgain(t *testing.T) {
	src, store := eligibleFindings(
		finding.Finding{ID: "f1", ResourceID: "r1", Score: 90, ScoreBand: "page"},
	)
	w := &AdjudicateWorker{
		findings:    src,
		assembler:   &fakeAssembler{},
		adjudicator: belief.NewAdjudicator(store, &recordingSampler{}, belief.DefaultSweepConfig()),
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
	require.Len(t, store.saved, 1)
	require.Equal(t, "f1", store.saved[0].FindingID)

	// Second sweep: f1 is freshly adjudicated → the cursor excludes it, nothing hydrated.
	src.gotIDs = nil
	require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
	require.Empty(t, src.gotIDs, "a freshly-adjudicated finding is not re-listed")

	// Re-enrich f1 with changed evidence (later enriched_at + new score): the cursor
	// re-includes it and its new fingerprint forces a fresh adjudication.
	reenriched := src.byID["f1"]
	reenriched.EnrichedAt = time.Now().Add(time.Hour)
	reenriched.Score = 88
	src.byID["f1"] = reenriched
	store.eligible[0] = reenriched
	before := len(store.saved)

	require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
	require.Contains(t, src.gotIDs, "f1", "re-enriched finding is eligible again")
	require.Greater(t, len(store.saved), before, "re-enriched finding is re-adjudicated (new belief written)")
}

// fakePublicAccess reports a fixed public-access verdict for every resource.
type fakePublicAccess struct{ confirmed bool }

func (f fakePublicAccess) PublicAccessConfirmed(context.Context, string) (bool, error) {
	return f.confirmed, nil
}

// The corroboration gate: a demotion of a resource an independent witness says is
// publicly accessible is flagged for review (proposed), not silently accepted.
func TestAdjudicateWorker_DemotionOfPublicResourceDowngraded(t *testing.T) {
	run := func(publicConfirmed bool) belief.Belief {
		src, store := eligibleFindings(
			finding.Finding{ID: "f1", ResourceID: "arn:s3:bucket", Title: "public bucket", Score: 95, ScoreBand: "page"},
		)
		w := &AdjudicateWorker{
			findings:     src,
			assembler:    &fakeAssembler{},
			publicAccess: fakePublicAccess{confirmed: publicConfirmed},
			adjudicator:  belief.NewAdjudicator(store, &recordingSampler{}, belief.DefaultSweepConfig()),
		}
		require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
		require.Len(t, store.saved, 1)
		return store.saved[0]
	}

	// Public-access confirmed → the Low verdict is downgraded to proposed for review.
	flagged := run(true)
	require.Equal(t, belief.StatusProposed, flagged.Status)
	require.Equal(t, belief.ConfidenceLow, flagged.Confidence)

	// No public witness → the same demotion is accepted as a confirmed belief.
	accepted := run(false)
	require.Equal(t, belief.StatusConfirmed, accepted.Status)
	require.Equal(t, finding.SeverityLow, accepted.Severity)
}

// TestAdjudicateWorker_UnwiredWitnessProviderDoesNotFlagForReview is the
// polarity design decision made explicit: a witness provider that is simply NOT
// WIRED in this deployment (publicAccess: nil, exposedEdge: nil) must NOT
// be treated the same as a wired provider whose call failed. Both leave the
// corresponding GroundingFacts.*Known field at its zero value if handled
// naively, but the correct behavior differs: "no witness available at all"
// is the documented common case a demotion is accepted on; "witness
// available but this call errored" is what must flag for review (see
// TestAdjudicateWorker_FailedWitnessLookupFlagsForReview). Conflating them
// would flag EVERY demotion for review in any deployment lacking full
// witness coverage, defeating the adjudicator's purpose.
func TestAdjudicateWorker_UnwiredWitnessProviderDoesNotFlagForReview(t *testing.T) {
	src, store := eligibleFindings(
		finding.Finding{ID: "f1", ResourceID: "arn:s3:bucket", Title: "public bucket", Score: 95, ScoreBand: "page"},
	)
	w := &AdjudicateWorker{
		findings:  src,
		assembler: &fakeAssembler{},
		// publicAccess and exposedEdge deliberately left nil: not wired.
		adjudicator: belief.NewAdjudicator(store, &recordingSampler{}, belief.DefaultSweepConfig()),
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
	require.Len(t, store.saved, 1)
	require.Equal(t, belief.StatusConfirmed, store.saved[0].Status,
		"an unwired witness provider must read as 'no witness', not 'lookup failed'")
}

// failedPeersAssembler simulates a SUCCESSFUL context assembly (no error)
// whose internal peer-findings query failed — PeersKnown stays false, the
// same shape buildContextPack produces on a peer-query error.
type failedPeersAssembler struct{}

func (failedPeersAssembler) Context(context.Context, finding.Finding) (respond.ContextPack, error) {
	return respond.ContextPack{Exposure: respond.ExposureFlags{PeersKnown: false}, Blast: respond.BlastSummary{Known: true}}, nil
}

// failedBlastAssembler simulates a successful assembly whose blast walk
// failed: the pack carries Count 0 with Known false.
type failedBlastAssembler struct{}

func (failedBlastAssembler) Context(context.Context, finding.Finding) (respond.ContextPack, error) {
	return respond.ContextPack{Exposure: respond.ExposureFlags{PeersKnown: true}}, nil
}

// TestAdjudicateWorker_FailedBlastWalkFlagsForReview: an unmeasured blast
// radius must not let a demotion through as if the resource reached nothing.
func TestAdjudicateWorker_FailedBlastWalkFlagsForReview(t *testing.T) {
	src, store := eligibleFindings(
		finding.Finding{ID: "f1", ResourceID: "arn:s3:bucket", Title: "public bucket", Score: 95, ScoreBand: "page"},
	)
	w := &AdjudicateWorker{
		findings:    src,
		assembler:   failedBlastAssembler{},
		adjudicator: belief.NewAdjudicator(store, &recordingSampler{}, belief.DefaultSweepConfig()),
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
	require.Len(t, store.saved, 1)
	require.Equal(t, belief.StatusProposed, store.saved[0].Status,
		"a failed blast walk must flag the demotion for review, not corroborate it")
}

// TestAdjudicateWorker_FailedPeerQueryFlagsForReview: a failed peer-findings
// query previously left ExposureFlags.InternetFacing (and therefore
// GroundingFacts.ExposureConfirmed) at its zero value, indistinguishable from "queried and
// found no exposure peer" — silently letting through exactly the demotion the
// corroboration gate exists to catch.
func TestAdjudicateWorker_FailedPeerQueryFlagsForReview(t *testing.T) {
	src, store := eligibleFindings(
		finding.Finding{ID: "f1", ResourceID: "arn:s3:bucket", Title: "public bucket", Score: 95, ScoreBand: "page"},
	)
	w := &AdjudicateWorker{
		findings:    src,
		assembler:   failedPeersAssembler{},
		adjudicator: belief.NewAdjudicator(store, &recordingSampler{}, belief.DefaultSweepConfig()),
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
	require.Len(t, store.saved, 1)
	flagged := store.saved[0]
	require.Equal(t, belief.StatusProposed, flagged.Status,
		"a failed peer query must flag the demotion for review, not silently accept it")
}

// erroringPublicAccess always fails the lookup — simulates the graph/query
// error path the corroboration gate must never read as "confirmed false".
type erroringPublicAccess struct{}

func (erroringPublicAccess) PublicAccessConfirmed(context.Context, string) (bool, error) {
	return false, errors.New("public-access lookup: connection reset")
}

// TestAdjudicateWorker_FailedWitnessLookupFlagsForReview: before this fix, a
// failed PublicAccessConfirmed
// lookup left GroundingFacts.PublicAccessConfirmed at its zero value —
// indistinguishable from a genuinely-checked "not publicly exposed" — so a
// demotion the gate exists specifically to catch was silently accepted.
// A failed lookup must instead flag the demotion for review, the same as a
// confirmed-true witness does.
func TestAdjudicateWorker_FailedWitnessLookupFlagsForReview(t *testing.T) {
	src, store := eligibleFindings(
		finding.Finding{ID: "f1", ResourceID: "arn:s3:bucket", Title: "public bucket", Score: 95, ScoreBand: "page"},
	)
	w := &AdjudicateWorker{
		findings:     src,
		assembler:    &fakeAssembler{},
		publicAccess: erroringPublicAccess{},
		adjudicator:  belief.NewAdjudicator(store, &recordingSampler{}, belief.DefaultSweepConfig()),
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[AdjudicateArgs]{}))
	require.Len(t, store.saved, 1)
	flagged := store.saved[0]
	require.Equal(t, belief.StatusProposed, flagged.Status,
		"a failed witness lookup must flag the demotion for review, not silently accept it")
	require.Equal(t, belief.ConfidenceLow, flagged.Confidence)
}

// uniq collapses repeated adjacent IDs (the cheap-check + N-sample cascade samples
// the same finding several times).
func uniq(ids []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Identity findings get scoped exposure facts: the identity's own
// internet_facing flag is labeled as a non-endpoint fact, and the must-fix
// reachability claim is scoped to the SOURCE asset — otherwise
// internet_facing=false on the identity "refutes" a source-asset claim.
func TestRenderAdjudicationContext_IdentityScoping(t *testing.T) {
	f := finding.Finding{
		ResourceType: "iam_role", Score: 91, ScoreBand: "page",
		MustFixClass: "must_fix", MustFixReason: "assumable from an internet-exposed asset · blast radius 18",
	}
	got := renderAdjudicationContext(f, respond.ContextPack{}, false)
	require.Contains(t, got, "identity_itself_internet_facing=false")
	require.Contains(t, got, "does NOT contradict reachability via a trust path")
	require.Contains(t, got, "scope: the internet-exposed SOURCE asset in the trust path, NOT this identity")
	require.Contains(t, got, "assumable from an internet-exposed asset")
	require.NotContains(t, got, "Exposure: internet_facing=")
	// The independent exposed-edge witness is rendered (false here: an identity
	// has no live exposed edge — the structural contradiction the model may act on).
	require.Contains(t, got, "Exposed_to_internet edge (fresh graph re-query): present=false")

	// Non-identity resources keep the plain exposure line.
	f.ResourceType = "ec2_instance"
	f.MustFixReason = "internet-exposed · blast radius 18"
	got = renderAdjudicationContext(f, respond.ContextPack{}, true)
	require.Contains(t, got, "Exposure: internet_facing=false")
	require.NotContains(t, got, "identity_itself_internet_facing")
	require.NotContains(t, got, "SOURCE asset")
	require.Contains(t, got, "Exposed_to_internet edge (fresh graph re-query): present=true")
}

// The identity reachability-scoping label is a claim about evidence, so it may
// only be attached to a reason that makes that claim. `routine` — the classifier's
// majority verdict and the bulk of the adjudication backlog — says the OPPOSITE
// ("no urgency evidence"), and labelling it as a claim about an internet-exposed
// source asset would manufacture reachability evidence inside the prompt whose one
// rule is to cite only facts the context contains.
func TestRenderAdjudicationContext_NonReachReasonIsNotLabelledAsReachability(t *testing.T) {
	f := finding.Finding{
		ResourceType: "iam_role", Score: 78, ScoreBand: "high",
		MustFixClass:  "routine",
		MustFixReason: "no urgency evidence: not exploitable (no KEV, no privilege escalation path)",
	}
	got := renderAdjudicationContext(f, respond.ContextPack{}, false)
	require.Contains(t, got, "Must-fix class: routine")
	require.Contains(t, got, "no urgency evidence: not exploitable")
	require.NotContains(t, got, "reachability claim")
	require.NotContains(t, got, "SOURCE asset")
	// The identity exposure framing itself is unconditional and stays.
	require.Contains(t, got, "identity_itself_internet_facing=false")
}

// A failed blast walk is not a measurement: the prompt must say "unknown",
// never "0 reachable asset(s)", which reads as "touches nothing".
func TestRenderAdjudicationContext_BlastKnownness(t *testing.T) {
	f := finding.Finding{ResourceID: "r1", ResourceType: "ec2_instance"}

	got := renderAdjudicationContext(f, respond.ContextPack{}, false)
	require.Contains(t, got, "Blast radius: unknown (lookup failed)")
	require.NotContains(t, got, "0 reachable")

	pack := respond.ContextPack{Blast: respond.BlastSummary{Count: 0, Known: true}}
	require.Contains(t, renderAdjudicationContext(f, pack, false), "Blast radius: 0 reachable asset(s)\n")

	pack.Blast = respond.BlastSummary{Count: 7, Known: true, Truncated: true}
	require.Contains(t, renderAdjudicationContext(f, pack, false), "Blast radius: 7 reachable asset(s) (truncated)")

	f.ResourceID = ""
	require.Contains(t, renderAdjudicationContext(f, respond.ContextPack{}, false), "Blast radius: not applicable (no resource)")
}
