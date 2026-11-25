package govern

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
)

// pendingOf is a pending store holding one parked decision of actionClass per id.
func pendingOf(actionClass string, ids ...string) fakePending {
	p := fakePending{}
	for _, id := range ids {
		p.entries = append(p.entries, reasoncache.Entry{FindingID: id, ActionClass: actionClass, Outcome: "parked_for_approval"})
	}
	return p
}

// statefulVerdicts remembers what was resolved, like the real verdict store.
type statefulVerdicts struct{ resolved map[string]string }

func (v *statefulVerdicts) Upsert(_ context.Context, findingID, _ string, _ Verdict, _, _, fingerprint string) error {
	v.resolved[findingID] = fingerprint
	return nil
}

func (v *statefulVerdicts) ResolvedFingerprints(context.Context) (map[string]string, error) {
	out := make(map[string]string, len(v.resolved))
	for k, fp := range v.resolved {
		out[k] = fp
	}
	return out, nil
}

func s3Findings(ids ...string) fakeFindings {
	f := fakeFindings{byID: map[string]finding.Finding{}}
	for _, id := range ids {
		f.byID[id] = finding.Finding{ID: id, CheckID: "aws-s3-public", ResourceType: "s3_bucket", ScoreBand: "pipeline"}
	}
	return f
}

// The reported abuse: one admin re-resolving the same finding over and over
// to push a confidence key to "high". Only the first verdict is evidence.
func TestResolve_RepeatResolveDoesNotMoveConfidence(t *testing.T) {
	pinned := time.Unix(1_700_000_000, 0).UTC()
	memSvc := memory.NewService(&fakeMemoryRepo{}, memory.WithClock(func() time.Time { return pinned }))
	pending := fakePending{entries: []reasoncache.Entry{{FindingID: "f1", ActionClass: "remediate", Fingerprint: "fp1"}}}
	s := NewService(&statefulVerdicts{resolved: map[string]string{}}, pending, s3Findings("f1"), memSvc, &fakeAudit{})
	s.now = func() time.Time { return pinned }

	in := ResolveInput{FindingIDs: []string{"f1"}, Verdict: VerdictDenied, Actor: "admin@x.example"}
	require.NoError(t, s.Resolve(context.Background(), in))
	for range 5 {
		require.ErrorIs(t, s.Resolve(context.Background(), in), ErrAlreadyResolved)
	}

	conf, err := memSvc.Confidence(context.Background(), "remediate", "s3_bucket")
	require.NoError(t, err)
	require.Equal(t, 1, conf.SampleCount, "one judgment, one sample")
	require.Equal(t, memory.BandInsufficient, conf.Band)
}

// A finding with no pending decision is not something a governor was asked to
// judge: no verdict, no memory outcome, no pattern verdict.
func TestResolve_NonPendingFindingIsRejected(t *testing.T) {
	verdicts := &fakeVerdicts{}
	outcomes := &fakeOutcomes{}
	patterns := &fakePatternVerdicts{}
	s := svc(verdicts, pendingOf("remediate", "f1"), s3Findings("f1", "f2"), outcomes, &fakeAudit{}).WithPatterns(patterns)

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1", "f2"}, Verdict: VerdictDenied, Actor: "admin@x.example",
	})
	require.ErrorIs(t, err, ErrNotPending)
	require.Empty(t, verdicts.upserts, "nothing in the request is resolved")
	require.Empty(t, outcomes.recorded)
	require.Empty(t, patterns.stored, "no standing denial without a real pending decision")
}

// The action class comes from the pending decision: a client-chosen class
// would file evidence under a confidence key nobody judged.
func TestResolve_ActionClassComesFromThePendingDecision(t *testing.T) {
	outcomes := &fakeOutcomes{}
	s := svc(&fakeVerdicts{}, pendingOf("remediate", "f1"), s3Findings("f1"), outcomes, &fakeAudit{})

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, ActionClass: "observe", Verdict: VerdictApproved, Actor: "admin@x.example",
	})
	require.ErrorIs(t, err, ErrTargetMismatch, "a request naming a different class is refused")
	require.Empty(t, outcomes.recorded)

	require.NoError(t, s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, Verdict: VerdictDenied, Actor: "admin@x.example",
	}))
	require.Len(t, outcomes.recorded, 1)
	require.Equal(t, "remediate", outcomes.recorded[0].ActionClass)
}

func TestResolve_MixedActionClassesAreRejected(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "remediate"},
		{FindingID: "f2", ActionClass: "destroy"},
	}}
	s := svc(&fakeVerdicts{}, pending, s3Findings("f1", "f2"), &fakeOutcomes{}, &fakeAudit{})
	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1", "f2"}, Verdict: VerdictApproved, Actor: "admin@x.example",
	})
	require.ErrorIs(t, err, ErrTargetMismatch)
}

// Two concurrent identical resolves both pass validation; the outcome they
// write carries the same key, so memory stores it once.
func TestResolve_OutcomeIsKeyedByTheDecisionSet(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "remediate", Fingerprint: "fp1"},
		{FindingID: "f2", ActionClass: "remediate", Fingerprint: "fp2"},
	}}
	a, b := &fakeOutcomes{}, &fakeOutcomes{}
	in := ResolveInput{FindingIDs: []string{"f1", "f2"}, Verdict: VerdictDenied, Actor: "admin@x.example"}
	require.NoError(t, svc(&fakeVerdicts{}, pending, s3Findings("f1", "f2"), a, &fakeAudit{}).Resolve(context.Background(), in))
	in.FindingIDs = []string{"f2", "f1"}
	require.NoError(t, svc(&fakeVerdicts{}, pending, s3Findings("f1", "f2"), b, &fakeAudit{}).Resolve(context.Background(), in))

	require.NotEmpty(t, a.recorded[0].DedupeKey)
	require.Equal(t, a.recorded[0].DedupeKey, b.recorded[0].DedupeKey, "order-independent")

	changed := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "remediate", Fingerprint: "fp1-changed"},
		{FindingID: "f2", ActionClass: "remediate", Fingerprint: "fp2"},
	}}
	c := &fakeOutcomes{}
	require.NoError(t, svc(&fakeVerdicts{}, changed, s3Findings("f1", "f2"), c, &fakeAudit{}).Resolve(context.Background(), in))
	require.NotEqual(t, a.recorded[0].DedupeKey, c.recorded[0].DedupeKey, "a changed context is a new decision")
}
