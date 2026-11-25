package govern

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

type fakeVerdicts struct {
	resolved map[string]string // findingID -> fingerprint at resolution
	upserts  []string          // findingID:verdict:fingerprint
}

func (f *fakeVerdicts) Upsert(_ context.Context, findingID, _ string, v Verdict, _, _, fingerprint string) error {
	f.upserts = append(f.upserts, findingID+":"+string(v)+":"+fingerprint)
	return nil
}
func (f *fakeVerdicts) ResolvedFingerprints(_ context.Context) (map[string]string, error) {
	if f.resolved == nil {
		return map[string]string{}, nil
	}
	return f.resolved, nil
}

type fakePending struct{ entries []reasoncache.Entry }

// ListPending mimics the real store's server-side action_class filter (unlike
// a plain in-memory return of f.entries, which would silently defeat any test
// asserting the filter is applied at the store/query level rather than on an
// already-fetched slice).
func (f fakePending) ListPending(_ context.Context, _ int, actionClass string) ([]reasoncache.Entry, error) {
	if actionClass == "" {
		return f.entries, nil
	}
	var out []reasoncache.Entry
	for _, e := range f.entries {
		if e.ActionClass == actionClass {
			out = append(out, e)
		}
	}
	return out, nil
}

type fakeFindings struct{ byID map[string]finding.Finding }

func (f fakeFindings) ByIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, id := range ids {
		if fnd, ok := f.byID[id]; ok {
			out = append(out, fnd)
		}
	}
	return out, nil
}

type fakeOutcomes struct{ recorded []memory.Outcome }

func (f *fakeOutcomes) Record(_ context.Context, o memory.Outcome) error {
	f.recorded = append(f.recorded, o)
	return nil
}

// fakeMemoryRepo is an in-memory memory.Repo used to exercise the real
// decay/banding math (memory.NewService) end-to-end from govern.Resolve,
// rather than re-stubbing that math with a fake.
type fakeMemoryRepo struct{ outcomes []memory.Outcome }

func (r *fakeMemoryRepo) Record(_ context.Context, o memory.Outcome) error {
	r.outcomes = append(r.outcomes, o)
	return nil
}

func (r *fakeMemoryRepo) Recent(_ context.Context, actionClass, assetType string, limit int) ([]memory.Outcome, error) {
	var out []memory.Outcome
	for _, o := range r.outcomes {
		if o.ActionClass == actionClass && o.AssetType == assetType {
			out = append(out, o)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *fakeMemoryRepo) RecentByAsset(_ context.Context, assetType string, limit int) ([]memory.Outcome, error) {
	var out []memory.Outcome
	for _, o := range r.outcomes {
		if o.AssetType == assetType {
			out = append(out, o)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

type fakeAudit struct{ events []respond.AuditEvent }

func (f *fakeAudit) Record(_ context.Context, e respond.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

func svc(v Verdicts, p Pending, f Findings, o Outcomes, a Audit) *Service {
	s := NewService(v, p, f, o, a)
	s.now = func() time.Time { return time.Unix(1000, 0).UTC() }
	return s
}

func TestQueue_ClustersByCheckAndExcludesResolved(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "trim privesc", Outcome: "parked_for_approval", ConfidenceBand: "insufficient", BlastRadius: 1, CoVeConcerns: []string{"destructive"}},
		{FindingID: "f2", ActionClass: "modify", Summary: "trim privesc", Outcome: "parked_for_approval", BlastRadius: 3},
		{FindingID: "f3", ActionClass: "isolate", Summary: "isolate host", Outcome: "escalated"},
		{FindingID: "f4", ActionClass: "modify", Summary: "already done", Outcome: "parked_for_approval", Fingerprint: "fp-f4"}, // resolved, unchanged
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", Title: "IAM privesc", Score: 80, ScoreBand: "high", ResourceID: "u1", Unused: true},
		"f2": {ID: "f2", CheckID: "aws-privesc-16", Title: "IAM privesc", Score: 86, ScoreBand: "page", ResourceID: "u2"},
		"f3": {ID: "f3", CheckID: "ssh-brute", Title: "SSH brute force", Score: 70, ScoreBand: "high", ResourceID: "i-1"},
		"f4": {ID: "f4", CheckID: "aws-privesc-16", Title: "IAM privesc", Score: 50, ResourceID: "u3", Unused: true},
	}}
	verdicts := &fakeVerdicts{resolved: map[string]string{"f4": "fp-f4"}}

	items, err := svc(verdicts, pending, finds, &fakeOutcomes{}, &fakeAudit{}).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 2, "two clusters: privesc + ssh-brute; the resolved f4 is excluded")

	// Worst-score first → the privesc cluster (86) leads.
	privesc := items[0]
	require.Equal(t, "aws-privesc-16|modify", privesc.ClusterKey)
	require.Equal(t, 2, privesc.Count, "f1+f2; f4 excluded as resolved")
	require.Equal(t, 2, privesc.Resources)
	require.Equal(t, uint8(86), privesc.WorstScore)
	require.Equal(t, "page", privesc.WorstBand)
	require.Equal(t, 3, privesc.BlastRadius, "max blast across the cluster")
	require.ElementsMatch(t, []string{"f1", "f2"}, privesc.FindingIDs)
	require.Equal(t, []string{"destructive"}, privesc.CoVeConcerns)
	require.Equal(t, 1, privesc.UnusedCount, "f1's resource is unused; f4's doesn't count (resolved)")
}

// TestQueue_SampleTargetsDedupedAcrossFindingsOnSameResource is the dedupe
// fix: clusterQueue's SampleTargets used to append
// one entry per FINDING, not per distinct resource — the same shape of bug
// as the approval-webhook payload, which is rebuilt the same way. Many
// findings sharing one resource must not burn all 5 sample slots on
// duplicates of that one id, starving the display of the variety it exists
// to show.
func TestQueue_SampleTargetsDedupedAcrossFindingsOnSameResource(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "s", Outcome: "parked_for_approval"},
		{FindingID: "f2", ActionClass: "modify", Summary: "s", Outcome: "parked_for_approval"},
		{FindingID: "f3", ActionClass: "modify", Summary: "s", Outcome: "parked_for_approval"},
		{FindingID: "f4", ActionClass: "modify", Summary: "s", Outcome: "parked_for_approval"},
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		// All four findings share the SAME resource (u1) plus one distinct one (u2).
		"f1": {ID: "f1", CheckID: "aws-privesc-16", Title: "t", Score: 80, ResourceID: "u1"},
		"f2": {ID: "f2", CheckID: "aws-privesc-16", Title: "t", Score: 79, ResourceID: "u1"},
		"f3": {ID: "f3", CheckID: "aws-privesc-16", Title: "t", Score: 78, ResourceID: "u1"},
		"f4": {ID: "f4", CheckID: "aws-privesc-16", Title: "t", Score: 77, ResourceID: "u2"},
	}}
	items, err := svc(&fakeVerdicts{}, pending, finds, &fakeOutcomes{}, &fakeAudit{}).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, 2, items[0].Resources, "two DISTINCT resources across four findings")
	require.ElementsMatch(t, []string{"u1", "u2"}, items[0].SampleTargets,
		"SampleTargets must hold distinct resources, not one entry per finding")
}

func TestQueue_ResurfacesResolvedWhenFingerprintChanges(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "privesc", Outcome: "parked_for_approval", Fingerprint: "v2"},
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", Title: "IAM privesc", Score: 90, ResourceID: "u1"},
	}}
	// Resolved earlier against fingerprint "v1"; the finding has since changed to "v2".
	verdicts := &fakeVerdicts{resolved: map[string]string{"f1": "v1"}}

	items, err := svc(verdicts, pending, finds, &fakeOutcomes{}, &fakeAudit{}).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1, "a resolved finding re-surfaces once its fingerprint changes (v1 -> v2)")
	require.ElementsMatch(t, []string{"f1"}, items[0].FindingIDs)
}

// TestQueue_ActionClassFilterAppliesAtThePendingStore pins that Queue's filter
// is applied by the Pending store's query (fakePending.ListPending, mirroring
// the real PGRepo's server-side WHERE), not by filtering an already-fetched
// slice in Service.Queue: the isolate cluster must never reach clusterQueue at
// all when filtering for modify, so it cannot appear even indirectly (e.g. in
// a count of dropped items).
func TestQueue_ActionClassFilterAppliesAtThePendingStore(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "trim privesc", Outcome: "parked_for_approval"},
		{FindingID: "f2", ActionClass: "isolate", Summary: "isolate host", Outcome: "escalated"},
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", Title: "IAM privesc", Score: 80, ResourceID: "u1"},
		"f2": {ID: "f2", CheckID: "ssh-brute", Title: "SSH brute force", Score: 70, ResourceID: "i-1"},
	}}
	verdicts := &fakeVerdicts{}

	items, err := svc(verdicts, pending, finds, &fakeOutcomes{}, &fakeAudit{}).Queue(context.Background(), "modify")
	require.NoError(t, err)
	require.Len(t, items, 1, "only the modify cluster should surface")
	require.Equal(t, "modify", items[0].ActionClass)
	require.ElementsMatch(t, []string{"f1"}, items[0].FindingIDs)
}

func TestResolve_SnapshotsCurrentFingerprint(t *testing.T) {
	verdicts := &fakeVerdicts{}
	pending := fakePending{entries: []reasoncache.Entry{{FindingID: "f1", Fingerprint: "fp-current"}}}
	s := svc(verdicts, pending, fakeFindings{}, &fakeOutcomes{}, &fakeAudit{})

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, Verdict: VerdictRiskAccepted, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Equal(t, []string{"f1:risk_accepted:fp-current"}, verdicts.upserts,
		"the verdict snapshots the finding's current fingerprint so a later change re-surfaces it")
}

func TestResolve_ApprovalWritesVerdictAndAuditButNoOutcome(t *testing.T) {
	verdicts := &fakeVerdicts{}
	outcomes := &fakeOutcomes{}
	audit := &fakeAudit{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", ResourceType: "iam_user"},
		"f2": {ID: "f2", ResourceType: "iam_user"},
	}}
	s := svc(verdicts, pendingOf("modify", "f1", "f2"), finds, outcomes, audit)

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs:  []string{"f1", "f2"},
		ActionClass: "modify", Verdict: VerdictApproved, Actor: "gov@x.example", Note: "ok",
	})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"f1:approved:", "f2:approved:"}, verdicts.upserts)
	require.Len(t, audit.events, 2)
	require.Equal(t, "governor_verdict", audit.events[0].Action)
	// An approval is a yes to try the fix, not evidence it worked: memory
	// learns success only from a fix that ran (TestRecordExecution_*).
	require.Empty(t, outcomes.recorded)
}

// fakeApprovalNotifier records the ApprovalPayload it was sent.
type fakeApprovalNotifier struct {
	got ApprovalPayload
	n   int
}

func (f *fakeApprovalNotifier) NotifyApproval(_ context.Context, p ApprovalPayload) error {
	f.got = p
	f.n++
	return nil
}

// TestResolve_ApprovalNotificationCarriesResourcesConcernsAndTargets: the
// rebuilt QueueItem inside Resolve's notifier branch must carry
// Resources/CoVeConcerns/SampleTargets, not their zero value (0/nil/nil) —
// most importantly CoVeConcerns, the guardrail-concerns field that explains
// WHY the decision escalated, on the payload a human approves from.
func TestResolve_ApprovalNotificationCarriesResourcesConcernsAndTargets(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "trim privesc", ConfidenceBand: "high", BlastRadius: 5, CoVeConcerns: []string{"weighted blast radius 10.4 ≥ 10.0 — human review mandatory"}},
		{FindingID: "f2", ActionClass: "modify", Summary: "trim privesc", ConfidenceBand: "high", BlastRadius: 3, CoVeConcerns: []string{"68 reachable assets with enriched score 80"}},
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", Title: "IAM privesc", Score: 80, ScoreBand: "high", ResourceID: "u1"},
		"f2": {ID: "f2", CheckID: "aws-privesc-16", Title: "IAM privesc", Score: 86, ScoreBand: "page", ResourceID: "u2"},
	}}
	notifier := &fakeApprovalNotifier{}
	s := svc(&fakeVerdicts{}, pending, finds, &fakeOutcomes{}, &fakeAudit{}).WithApprovalNotifier(notifier)

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs:  []string{"f1", "f2"},
		ActionClass: "modify", Verdict: VerdictApproved, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Equal(t, 1, notifier.n, "one notification per cluster, not per finding")
	require.Equal(t, 2, notifier.got.Resources, "distinct resources (u1, u2) must reach the payload")
	require.ElementsMatch(t, []string{"u1", "u2"}, notifier.got.SampleTargets)
	require.ElementsMatch(t,
		[]string{"weighted blast radius 10.4 ≥ 10.0 — human review mandatory", "68 reachable assets with enriched score 80"},
		notifier.got.CoVeConcerns,
		"the guardrail concerns that caused escalation must reach the human approver's notification")
}

// TestResolve_ApprovalPayloadCarriesBlastRadiusKnown is the regression test
// for a gap where the AND-reduced
// BlastRadiusKnown computed while building the cluster item was never copied
// into ApprovalPayload — the queue card got the known-ness fix (handler.go),
// but the human-authorization surface (the approval email/webhook, the one
// that actually gates a real cloud mutation) still handed a partially-
// unmeasured cluster's BlastRadius to the approver as a confident number.
func TestResolve_ApprovalPayloadCarriesBlastRadiusKnown(t *testing.T) {
	resolve := func(pending fakePending, finds fakeFindings) *fakeApprovalNotifier {
		notifier := &fakeApprovalNotifier{}
		s := svc(&fakeVerdicts{}, pending, finds, &fakeOutcomes{}, &fakeAudit{}).WithApprovalNotifier(notifier)
		err := s.Resolve(context.Background(), ResolveInput{
			FindingIDs:  []string{"f1", "f2"},
			ActionClass: "modify", Verdict: VerdictApproved, Actor: "gov@x.example",
		})
		require.NoError(t, err)
		return notifier
	}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceID: "u1"},
		"f2": {ID: "f2", CheckID: "aws-privesc-16", ResourceID: "u2"},
	}}

	// Every walk in the cluster measured: the payload must carry that
	// positively (this is the case that catches BlastRadiusKnown being
	// omitted from the literal entirely — an omitted bool defaults to
	// false, which the all-unmeasured case below cannot distinguish from
	// "correctly computed false").
	allKnown := resolve(fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "s", ConfidenceBand: "high", BlastRadius: 12, BlastRadiusKnown: true},
		{FindingID: "f2", ActionClass: "modify", Summary: "s", ConfidenceBand: "high", BlastRadius: 3, BlastRadiusKnown: true},
	}}, finds)
	require.Equal(t, 12, allKnown.got.BlastRadius, "the max across the cluster")
	require.True(t, allKnown.got.BlastRadiusKnown, "every walk in the cluster measured")

	// One unmeasured walk poisons the whole cluster's known-ness.
	onePoisoned := resolve(fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "s", ConfidenceBand: "high", BlastRadius: 12, BlastRadiusKnown: true},
		{FindingID: "f2", ActionClass: "modify", Summary: "s", ConfidenceBand: "high", BlastRadius: 0, BlastRadiusKnown: false},
	}}, finds)
	require.Equal(t, 12, onePoisoned.got.BlastRadius, "the max across the cluster")
	require.False(t, onePoisoned.got.BlastRadiusKnown,
		"one unmeasured walk in the cluster must poison the approval payload's known-ness, not just the queue card's")
}

func TestResolve_DenialRecordsNegativeMemory(t *testing.T) {
	outcomes := &fakeOutcomes{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", ResourceType: "iam_user"},
		"f2": {ID: "f2", ResourceType: "iam_user"},
	}}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "f1", "f2"), finds, outcomes, &fakeAudit{})
	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs:  []string{"f1", "f2"},
		ActionClass: "modify", Verdict: VerdictDenied, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Len(t, outcomes.recorded, 1,
		"a denial is negative evidence for this (action class, asset type) key — one sample per type, not per finding")
	for _, o := range outcomes.recorded {
		require.Equal(t, "modify", o.ActionClass)
		require.Equal(t, "iam_user", o.AssetType)
		require.False(t, o.Success)
		require.Equal(t, "governor", o.DecidedBy)
	}
}

func TestResolve_RiskAcceptedDoesNotRecordMemory(t *testing.T) {
	outcomes := &fakeOutcomes{}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "f1"), fakeFindings{}, outcomes, &fakeAudit{})
	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, Verdict: VerdictRiskAccepted, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Empty(t, outcomes.recorded, "risk acceptance is a judgment about the finding, not the proposed action")
}

// A key with more denials than a pure-success ledger could ever produce
// finally exercises the previously-dead BandMedium (both writers used to be
// success-only, so the ledger could only ever climb straight to High).
//
// The 3-executed/2-denied mix scores EXACTLY 0.6: both this service's clock
// and the ledger's are pinned to the same instant via memory.WithClock, so
// every outcome carries weight 1.0 and no real-time decay creeps in between
// Resolve calls. (This assertion used to be InDelta 0.01 with a comment
// explaining that memory.Service had no clock seam and microsecond-scale decay
// could flake the band at a boundary — the seam exists now, so the test is
// exact.)
func TestExecutionsAndDenialsComputeMediumBand(t *testing.T) {
	pinned := time.Unix(1_700_000_000, 0).UTC()
	repo := &fakeMemoryRepo{}
	memSvc := memory.NewService(repo, memory.WithClock(func() time.Time { return pinned }))
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", ResourceType: "s3_bucket"},
		"f2": {ID: "f2", ResourceType: "s3_bucket"},
		"f3": {ID: "f3", ResourceType: "s3_bucket"},
		"f4": {ID: "f4", ResourceType: "s3_bucket"},
		"f5": {ID: "f5", ResourceType: "s3_bucket"},
	}}
	// Both clocks share one instant, so the outcomes this service stamps are
	// exactly as old as the ledger thinks "now" is: zero decay, weight 1.0.
	s := NewService(&fakeVerdicts{}, pendingOf("isolate", "f1", "f2", "f3", "f4", "f5"), finds, memSvc, &fakeAudit{})
	s.now = func() time.Time { return pinned }

	for _, id := range []string{"f1", "f2", "f3"} {
		require.NoError(t, s.RecordExecution(context.Background(), ExecutedFix{
			DecisionID: "d-" + id, FindingID: id, ActionClass: "isolate", Actor: "gov@x.example",
		}))
	}
	for _, id := range []string{"f4", "f5"} {
		require.NoError(t, s.Resolve(context.Background(), ResolveInput{
			FindingIDs: []string{id}, ActionClass: "isolate", Verdict: VerdictDenied, Actor: "gov@x.example",
		}))
	}

	conf, err := memSvc.Confidence(context.Background(), "isolate", "s3_bucket")
	require.NoError(t, err)
	require.Equal(t, 0.6, conf.Score, "3 executed fixes + 2 denials at zero decay is exactly 0.6")
	require.Equal(t, memory.BandMedium, conf.Band)
}

func TestResolve_Validates(t *testing.T) {
	s := svc(&fakeVerdicts{}, fakePending{}, fakeFindings{}, &fakeOutcomes{}, &fakeAudit{})
	require.ErrorIs(t, s.Resolve(context.Background(), ResolveInput{FindingIDs: []string{"f1"}, Verdict: "bogus"}), ErrBadVerdict)
	require.ErrorIs(t, s.Resolve(context.Background(), ResolveInput{Verdict: VerdictApproved}), ErrNoTargets)
}

// ── applyPolicyRules tests ─────────────────────────────────────────────────────

type fakePolicy struct{ snap PolicySnapshot }

func (f fakePolicy) Get(_ context.Context) (PolicySnapshot, error) { return f.snap, nil }

// makeEntry returns a parked reasoncache.Entry with the given finding ID,
// action class, confidence band and score (0..1), and a measured blast radius
// of zero.
func makeEntry(findingID, actionClass, band string, score float64) reasoncache.Entry {
	return reasoncache.Entry{
		FindingID: findingID, ActionClass: actionClass,
		Summary: "s", Outcome: "parked_for_approval",
		ConfidenceBand: band, ConfidenceScore: score,
		BlastRadiusKnown: true,
	}
}

func makeQueueSvc(pol PolicySnapshot, entries []reasoncache.Entry, findings map[string]finding.Finding) *Service {
	s := svc(&fakeVerdicts{}, fakePending{entries: entries}, fakeFindings{byID: findings}, &fakeOutcomes{}, &fakeAudit{})
	s.WithPolicy(fakePolicy{snap: pol})
	return s
}

func TestApplyPolicyRules_DisabledDropsItem(t *testing.T) {
	pol := PolicySnapshot{
		SuggestThreshold: 60,
		ActionRules:      map[string]string{"isolate": "disabled"},
	}
	entries := []reasoncache.Entry{
		makeEntry("f1", "isolate", "high", 0.90),
		makeEntry("f2", "remediate", "high", 0.90),
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "ssh", Score: 80, ResourceID: "h1"},
		"f2": {ID: "f2", CheckID: "ssh", Score: 80, ResourceID: "h2"},
	}
	items, err := makeQueueSvc(pol, entries, finds).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1, "a guidance-only action class must be dropped from the approval queue")
	require.Equal(t, "remediate", items[0].ActionClass)
}

func TestApplyPolicyRules_JITForcesApproval(t *testing.T) {
	pol := PolicySnapshot{
		SuggestThreshold: 60,
		ActionRules:      map[string]string{"destroy": "jit"},
	}
	entries := []reasoncache.Entry{
		makeEntry("f1", "destroy", "low", 0.10), // below the suggest threshold
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-sg", Score: 90, ResourceID: "sg-1"},
	}
	items, err := makeQueueSvc(pol, entries, finds).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "parked_for_approval", items[0].Outcome, "a jit rule parks regardless of confidence")
}

func TestApplyPolicyRules_DefaultThresholdParked(t *testing.T) {
	pol := PolicySnapshot{SuggestThreshold: 60}
	entries := []reasoncache.Entry{
		makeEntry("f1", "patch_instance", "medium", 0.65), // above suggest
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "cve-check", Score: 75, ResourceID: "i-1"},
	}
	items, err := makeQueueSvc(pol, entries, finds).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "parked_for_approval", items[0].Outcome, "score>=suggest_threshold => parked")
}

func TestApplyPolicyRules_DefaultThresholdEscalated(t *testing.T) {
	pol := PolicySnapshot{SuggestThreshold: 60}
	entries := []reasoncache.Entry{
		makeEntry("f1", "patch_instance", "low", 0.40), // below suggest threshold
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "cve-check", Score: 75, ResourceID: "i-1"},
	}
	items, err := makeQueueSvc(pol, entries, finds).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "escalated", items[0].Outcome, "score below suggest_threshold => escalated")
}

// TestApplyPolicyRules_NothingProceedsWithoutAHuman is ADR 087 at the queue:
// the most confident, most contained cluster under every rule the policy can
// hold — including a stale "auto" written before the mode was removed — is
// still labelled as waiting for a human, or dropped as guidance only.
func TestApplyPolicyRules_NothingProceedsWithoutAHuman(t *testing.T) {
	for _, mode := range []string{"", "jit", "disabled", "auto", "anything"} {
		t.Run("mode="+mode, func(t *testing.T) {
			pol := PolicySnapshot{SuggestThreshold: 0, ActionRules: map[string]string{}}
			if mode != "" {
				pol.ActionRules["remediate"] = mode
			}
			entries := []reasoncache.Entry{makeEntry("f1", "remediate", "very_high", 1.0)}
			finds := map[string]finding.Finding{"f1": {ID: "f1", CheckID: "c", Score: 99, ResourceID: "r"}}

			items, err := makeQueueSvc(pol, entries, finds).Queue(context.Background(), "")
			require.NoError(t, err)
			for _, it := range items {
				require.Containsf(t, []string{"parked_for_approval", "escalated"}, it.Outcome,
					"mode %q labelled a queue item %q — every outcome must wait for a human", mode, it.Outcome)
			}
		})
	}
}

func TestApplyPolicyRules_NoPolicyNoChange(t *testing.T) {
	// Without a policy wired, items retain their original outcome from the cache.
	entries := []reasoncache.Entry{
		makeEntry("f1", "modify", "high", 0.90),
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "iam", Score: 80, ResourceID: "u1"},
	}
	s := svc(&fakeVerdicts{}, fakePending{entries: entries}, fakeFindings{byID: finds}, &fakeOutcomes{}, &fakeAudit{})
	items, err := s.Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, "parked_for_approval", items[0].Outcome, "without policy, original cache outcome is preserved")
}

// ── annotateTeachingValue / queue ordering tests ────────────────────────────

type fakeConfidenceReader struct {
	byKey map[string]memory.Confidence // key: actionClass+"|"+resourceType
}

func (f fakeConfidenceReader) Confidence(_ context.Context, actionClass, assetType string) (memory.Confidence, error) {
	return f.byKey[actionClass+"|"+assetType], nil
}

func TestQueue_TeachingValueOrdersClosestToThresholdFirst(t *testing.T) {
	// Three clusters, each single-finding, each a distinct confidence key:
	//   "modify|iam_user":   2 of 3 samples (EffectiveN=2, gap=1)     -> closest
	//   "modify|s3_bucket":  0 samples (EffectiveN=0, gap=3)          -> further
	//   "modify|ec2_instance": already High (EffectiveN=10, gap=0)    -> last
	entries := []reasoncache.Entry{
		makeEntry("f1", "modify", "insufficient", 0.0),
		makeEntry("f2", "modify", "insufficient", 0.0),
		makeEntry("f3", "modify", "high", 0.9),
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "check-a", ResourceID: "u1", ResourceType: "iam_user"},
		"f2": {ID: "f2", CheckID: "check-b", ResourceID: "b1", ResourceType: "s3_bucket"},
		"f3": {ID: "f3", CheckID: "check-c", ResourceID: "i1", ResourceType: "ec2_instance"},
	}
	conf := fakeConfidenceReader{byKey: map[string]memory.Confidence{
		"modify|iam_user":     {EffectiveN: 2, Score: 0.9, Band: memory.BandInsufficient},
		"modify|s3_bucket":    {EffectiveN: 0, Score: 0, Band: memory.BandInsufficient},
		"modify|ec2_instance": {EffectiveN: 10, Score: 0.95, Band: memory.BandHigh},
	}}

	s := svc(&fakeVerdicts{}, fakePending{entries: entries}, fakeFindings{byID: finds}, &fakeOutcomes{}, &fakeAudit{})
	s.WithConfidence(conf)

	items, err := s.Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 3)

	require.Equal(t, "check-a|modify", items[0].ClusterKey, "gap=1 (2-of-3-samples) is closest to the threshold")
	require.InDelta(t, 2.0, items[0].ConfidenceEffectiveN, 0.001)
	require.InDelta(t, 1.0, items[0].ConfidenceGap, 0.001)

	require.Equal(t, "check-b|modify", items[1].ClusterKey, "gap=3 (0-of-3 samples) is further from the threshold")
	require.InDelta(t, 0.0, items[1].ConfidenceEffectiveN, 0.001)
	require.InDelta(t, 3.0, items[1].ConfidenceGap, 0.001)

	require.Equal(t, "check-c|modify", items[2].ClusterKey, "already-High key sorts last: nothing left to learn")
	require.InDelta(t, 0.0, items[2].ConfidenceGap, 0.001)
}

func TestQueue_UnlocksCountsCoKeyedClusters(t *testing.T) {
	// Two clusters share the "modify|iam_user" confidence key (different
	// check_ids, same action class + dominant resource type); a third cluster
	// is on its own key.
	entries := []reasoncache.Entry{
		makeEntry("f1", "modify", "insufficient", 0.0),
		makeEntry("f2", "modify", "insufficient", 0.0),
		makeEntry("f3", "modify", "insufficient", 0.0),
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "check-a", ResourceID: "u1", ResourceType: "iam_user"},
		"f2": {ID: "f2", CheckID: "check-b", ResourceID: "u2", ResourceType: "iam_user"},
		"f3": {ID: "f3", CheckID: "check-c", ResourceID: "b1", ResourceType: "s3_bucket"},
	}
	conf := fakeConfidenceReader{byKey: map[string]memory.Confidence{
		"modify|iam_user":  {EffectiveN: 1, Band: memory.BandInsufficient},
		"modify|s3_bucket": {EffectiveN: 1, Band: memory.BandInsufficient},
	}}

	s := svc(&fakeVerdicts{}, fakePending{entries: entries}, fakeFindings{byID: finds}, &fakeOutcomes{}, &fakeAudit{})
	s.WithConfidence(conf)

	items, err := s.Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 3)

	byKey := map[string]QueueItem{}
	for _, it := range items {
		byKey[it.ClusterKey] = it
	}
	require.Equal(t, 1, byKey["check-a|modify"].Unlocks, "check-b shares its confidence key")
	require.Equal(t, 1, byKey["check-b|modify"].Unlocks, "check-a shares its confidence key")
	require.Equal(t, 0, byKey["check-c|modify"].Unlocks, "no other cluster shares s3_bucket")
}

// countingConfidenceReader counts calls per (actionClass, assetType) key so a
// test can assert the reader is consulted once per UNIQUE key, not once per
// queue item — annotateTeachingValue must memoize the lookup.
type countingConfidenceReader struct {
	byKey map[string]memory.Confidence // key: actionClass+"|"+resourceType
	calls map[string]int
}

func (f *countingConfidenceReader) Confidence(_ context.Context, actionClass, assetType string) (memory.Confidence, error) {
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	key := actionClass + "|" + assetType
	f.calls[key]++
	return f.byKey[key], nil
}

// erroringConfidenceReader fails for one key and succeeds for the rest, so a
// test can prove an UNMEASURED cluster never outranks a measured one.
type erroringConfidenceReader struct {
	failKey string // actionClass+"|"+resourceType
	byKey   map[string]memory.Confidence
}

func (f erroringConfidenceReader) Confidence(_ context.Context, actionClass, assetType string) (memory.Confidence, error) {
	key := actionClass + "|" + assetType
	if key == f.failKey {
		return memory.Confidence{}, errors.New("ledger unavailable")
	}
	return f.byKey[key], nil
}

// A failed confidence lookup leaves ConfidenceGap at zero — the SMALLEST
// possible gap — so a gap-first sort ranks measurement FAILURES above the
// clusters genuinely closest to unlocking autonomy. That is the exact failure
// this field exists to avoid. Unknown
// confidence must sort last and must be flagged as unknown on the wire.
func TestQueue_UnknownConfidenceSortsLastAndIsFlagged(t *testing.T) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: "modify", Summary: "measurable", Outcome: "escalated"},
		{FindingID: "f2", ActionClass: "isolate", Summary: "unmeasurable", Outcome: "escalated"},
	}}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "check-good", ResourceType: "iam_user"},
		"f2": {ID: "f2", CheckID: "check-bad", ResourceType: "s3_bucket"},
	}}
	reader := erroringConfidenceReader{
		failKey: "isolate|s3_bucket",
		byKey:   map[string]memory.Confidence{"modify|iam_user": {EffectiveN: 2, Band: memory.BandInsufficient}},
	}
	s := svc(&fakeVerdicts{}, pending, finds, &fakeOutcomes{}, &fakeAudit{}).WithConfidence(reader)

	items, err := s.Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 2)

	require.True(t, items[0].ConfidenceKnown, "a measured cluster must be flagged known")
	require.Equal(t, "check-good", items[0].CheckID)
	require.InDelta(t, memory.MinEffectiveN-2, items[0].ConfidenceGap, 0.001)

	require.False(t, items[1].ConfidenceKnown, "a failed lookup is not a measurement")
	require.Zero(t, items[1].ConfidenceGap, "and carries no gap to be mistaken for one")
	// Unlocks needs no confidence lookup, so it stays a real number either way.
	require.Zero(t, items[1].Unlocks, "one cluster on its key unlocks nothing")
}

func TestQueue_TeachingValueMemoizesConfidenceLookupPerUniqueKey(t *testing.T) {
	// Four clusters: three share the "modify|iam_user" key, one is on its own
	// key. Without memoization the reader would be called 4 times; with it,
	// exactly once per unique key (2 calls total).
	entries := []reasoncache.Entry{
		makeEntry("f1", "modify", "insufficient", 0.0),
		makeEntry("f2", "modify", "insufficient", 0.0),
		makeEntry("f3", "modify", "insufficient", 0.0),
		makeEntry("f4", "isolate", "insufficient", 0.0),
	}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "check-a", ResourceID: "u1", ResourceType: "iam_user"},
		"f2": {ID: "f2", CheckID: "check-b", ResourceID: "u2", ResourceType: "iam_user"},
		"f3": {ID: "f3", CheckID: "check-c", ResourceID: "u3", ResourceType: "iam_user"},
		"f4": {ID: "f4", CheckID: "check-d", ResourceID: "b1", ResourceType: "s3_bucket"},
	}
	conf := &countingConfidenceReader{byKey: map[string]memory.Confidence{
		"modify|iam_user":   {EffectiveN: 1, Band: memory.BandInsufficient},
		"isolate|s3_bucket": {EffectiveN: 1, Band: memory.BandInsufficient},
	}}

	s := svc(&fakeVerdicts{}, fakePending{entries: entries}, fakeFindings{byID: finds}, &fakeOutcomes{}, &fakeAudit{})
	s.WithConfidence(conf)

	items, err := s.Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 4)

	require.Equal(t, 1, conf.calls["modify|iam_user"],
		"3 clusters share this key — the reader must be called once, not 3 times")
	require.Equal(t, 1, conf.calls["isolate|s3_bucket"])
	require.Len(t, conf.calls, 2, "exactly one call per unique confidence key")
}

func TestQueue_NoConfidenceReaderNoChange(t *testing.T) {
	entries := []reasoncache.Entry{makeEntry("f1", "modify", "high", 0.9)}
	finds := map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "check-a", ResourceID: "u1", ResourceType: "iam_user"},
	}
	s := svc(&fakeVerdicts{}, fakePending{entries: entries}, fakeFindings{byID: finds}, &fakeOutcomes{}, &fakeAudit{})

	items, err := s.Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Zero(t, items[0].ConfidenceEffectiveN)
	require.Zero(t, items[0].ConfidenceGap)
	require.Zero(t, items[0].Unlocks)
}

// ── PatternVerdict tests ─────────────────────────────────────────────────────

type fakePatternVerdicts struct {
	stored map[string]Verdict // check_id|action_class|resource_type -> verdict
	actor  string
	err    error // when set, UpsertPattern fails (best-effort contract)
	now    func() time.Time
}

func (f *fakePatternVerdicts) UpsertPattern(_ context.Context, checkID, actionClass, resourceType string, verdict Verdict, actor string) error {
	if f.err != nil {
		return f.err
	}
	if f.stored == nil {
		f.stored = map[string]Verdict{}
	}
	f.stored[checkID+"|"+actionClass+"|"+resourceType] = verdict
	f.actor = actor
	return nil
}

func (f *fakePatternVerdicts) PatternVerdict(_ context.Context, checkID, actionClass, resourceType string) (Verdict, time.Time, bool, error) {
	v, ok := f.stored[checkID+"|"+actionClass+"|"+resourceType]
	decidedAt := time.Time{}
	if ok && f.now != nil {
		decidedAt = f.now()
	}
	return v, decidedAt, ok, nil
}

func TestResolve_WritesPatternVerdict(t *testing.T) {
	patterns := &fakePatternVerdicts{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceType: "iam_user"},
	}}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "f1"), finds, &fakeOutcomes{}, &fakeAudit{})
	s.WithPatterns(patterns)

	// No CheckID on the input: the pattern key is derived from the resolved
	// finding, so a caller cannot name the pattern it is ruling on.
	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, ActionClass: "modify",
		Verdict: VerdictDenied, Actor: "gov@x.example",
	})
	require.NoError(t, err)

	v, _, found, err := s.PatternVerdict(context.Background(), "aws-privesc-16", "modify", "iam_user")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, VerdictDenied, v)
	require.Equal(t, "gov@x.example", patterns.actor)

	_, _, found, err = s.PatternVerdict(context.Background(), "aws-privesc-16", "modify", "s3_bucket")
	require.NoError(t, err)
	require.False(t, found, "the verdict must be scoped to the resource type it was ruled on")
}

// The pattern key must come from the findings, never from the request body or
// the ClusterKey string: once the decision loop consults pattern_verdicts, a
// caller-supplied key would let a typo (or a forged body) record a standing
// human ruling for a pattern no governor ever saw.
func TestResolve_PatternKeyIgnoresClusterKeyAndUsesTheFindings(t *testing.T) {
	patterns := &fakePatternVerdicts{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceType: "iam_user"},
	}}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "f1"), finds, &fakeOutcomes{}, &fakeAudit{})
	s.WithPatterns(patterns)

	// ClusterKey names a DIFFERENT check than the finding actually carries.
	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, ActionClass: "modify",
		Verdict: VerdictApproved, Actor: "gov@x.example",
	})
	require.NoError(t, err)

	_, _, found, err := s.PatternVerdict(context.Background(), "aws-s3-public-bucket", "modify", "iam_user")
	require.NoError(t, err)
	require.False(t, found, "the ClusterKey's check must never become the pattern key")

	v, _, found, err := s.PatternVerdict(context.Background(), "aws-privesc-16", "modify", "iam_user")
	require.NoError(t, err)
	require.True(t, found, "the pattern key comes from the resolved finding")
	require.Equal(t, VerdictApproved, v)
}

// A cluster spanning two checks has no single pattern the verdict speaks for.
func TestResolve_AmbiguousPatternIsNotRecorded(t *testing.T) {
	patterns := &fakePatternVerdicts{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceType: "iam_user"},
		"f2": {ID: "f2", CheckID: "aws-s3-public-bucket", ResourceType: "s3_bucket"},
	}}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "f1", "f2"), finds, &fakeOutcomes{}, &fakeAudit{})
	s.WithPatterns(patterns)

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1", "f2"}, ActionClass: "modify",
		Verdict: VerdictApproved, Actor: "gov@x.example",
	})
	require.NoError(t, err, "an ambiguous pattern key is skipped, not an error")
	require.Empty(t, patterns.stored, "no pattern verdict may be recorded for a multi-check cluster")
}

// risk_accepted is a judgment about the finding, not a ruling on the action —
// and the table has no expiry/scope semantics to express it safely.
func TestResolve_RiskAcceptedWritesNoPatternVerdict(t *testing.T) {
	patterns := &fakePatternVerdicts{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceType: "iam_user"},
	}}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "f1"), finds, &fakeOutcomes{}, &fakeAudit{})
	s.WithPatterns(patterns)

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, ActionClass: "modify",
		Verdict: VerdictRiskAccepted, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Empty(t, patterns.stored)
}

// A pattern-store failure must not fail the whole Resolve: verdicts, audit
// rows and memory outcomes are already written and action_outcomes is
// append-only, so a retry would double-count every outcome in the cluster.
func TestResolve_PatternUpsertFailureIsBestEffort(t *testing.T) {
	patterns := &fakePatternVerdicts{err: errors.New("pg down")}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "aws-privesc-16", ResourceType: "iam_user"},
	}}
	outcomes := &fakeOutcomes{}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "f1"), finds, outcomes, &fakeAudit{})
	s.WithPatterns(patterns)

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1"}, ActionClass: "modify",
		Verdict: VerdictDenied, Actor: "gov@x.example",
	})
	require.NoError(t, err, "a pattern-store failure must not roll back an audited verdict")
	require.Len(t, outcomes.recorded, 1, "the memory outcome still landed")
}

// One human judgment is ONE piece of evidence per asset type. Recording per
// finding let a single "deny all" on a big cluster write N negative samples
// and crater the confidence key (e.g. 1.00/high → 0.167/low at N=50).
func TestResolve_ClusterVerdictRecordsOneOutcomePerAssetType(t *testing.T) {
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "c1", ResourceType: "package"},
		"f2": {ID: "f2", CheckID: "c1", ResourceType: "package"},
		"f3": {ID: "f3", CheckID: "c1", ResourceType: "package"},
		"f4": {ID: "f4", CheckID: "c1", ResourceType: "container_image"},
	}}
	outcomes := &fakeOutcomes{}
	s := svc(&fakeVerdicts{}, pendingOf("remediate", "f1", "f2", "f3", "f4"), finds, outcomes, &fakeAudit{})

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1", "f2", "f3", "f4"}, ActionClass: "remediate",
		Verdict: VerdictDenied, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Len(t, outcomes.recorded, 2, "four findings over two asset types = two samples, not four")
	types := []string{outcomes.recorded[0].AssetType, outcomes.recorded[1].AssetType}
	require.ElementsMatch(t, []string{"package", "container_image"}, types)
	for _, o := range outcomes.recorded {
		require.False(t, o.Success, "a denial records negative evidence")
	}
}

// A finding that did not load has no asset type — filing evidence under
// ("class", "") would be a zero value standing in for a measurement.
func TestResolve_UnknownAssetTypeRecordsNoOutcome(t *testing.T) {
	outcomes := &fakeOutcomes{}
	s := svc(&fakeVerdicts{}, pendingOf("modify", "missing"), fakeFindings{}, outcomes, &fakeAudit{})

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"missing"}, ActionClass: "modify",
		Verdict: VerdictApproved, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Empty(t, outcomes.recorded, "no asset type => no evidence, rather than evidence keyed on nothing")
}

// One pattern row per DISTINCT resource type in the cluster: a cluster
// spanning package + container_image findings must write two pattern rows,
// mirroring the outcome ledger's one-sample-per-asset-type rule directly
// above — a denial on one resource type must never suppress the other.
func TestResolve_WritesOnePatternVerdictPerDistinctResourceType(t *testing.T) {
	patterns := &fakePatternVerdicts{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "c1", ResourceType: "package"},
		"f2": {ID: "f2", CheckID: "c1", ResourceType: "package"},
		"f3": {ID: "f3", CheckID: "c1", ResourceType: "container_image"},
	}}
	s := svc(&fakeVerdicts{}, pendingOf("remediate", "f1", "f2", "f3"), finds, &fakeOutcomes{}, &fakeAudit{})
	s.WithPatterns(patterns)

	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1", "f2", "f3"}, ActionClass: "remediate",
		Verdict: VerdictDenied, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Len(t, patterns.stored, 2, "two distinct resource types = two pattern rows, not one and not three")

	v, _, found, err := s.PatternVerdict(context.Background(), "c1", "remediate", "package")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, VerdictDenied, v)

	v, _, found, err = s.PatternVerdict(context.Background(), "c1", "remediate", "container_image")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, VerdictDenied, v)
}

// A finding with no resolvable resource type contributes no pattern row —
// same reasoning as the outcome ledger's skip: a zero value is not a
// measurement.
func TestResolve_UnknownResourceTypeWritesNoPatternRowForThatFinding(t *testing.T) {
	patterns := &fakePatternVerdicts{}
	finds := fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "c1", ResourceType: "package"},
	}}
	s := svc(&fakeVerdicts{}, pendingOf("remediate", "f1", "missing"), finds, &fakeOutcomes{}, &fakeAudit{})
	s.WithPatterns(patterns)

	// "missing" never loads, so its resource type is unknown ("").
	err := s.Resolve(context.Background(), ResolveInput{
		FindingIDs: []string{"f1", "missing"}, ActionClass: "remediate",
		Verdict: VerdictDenied, Actor: "gov@x.example",
	})
	require.NoError(t, err)
	require.Len(t, patterns.stored, 1, "only the resolvable resource type gets a pattern row")

	_, _, found, err := s.PatternVerdict(context.Background(), "c1", "remediate", "")
	require.NoError(t, err)
	require.False(t, found, "an empty resource type must never become a pattern key")
}

func TestPatternVerdict_NotFoundWhenNoneRecorded(t *testing.T) {
	s := svc(&fakeVerdicts{}, fakePending{}, fakeFindings{}, &fakeOutcomes{}, &fakeAudit{})
	s.WithPatterns(&fakePatternVerdicts{})

	_, _, found, err := s.PatternVerdict(context.Background(), "check-x", "modify", "iam_user")
	require.NoError(t, err)
	require.False(t, found)
}

func TestPatternVerdict_NoPatternsWiredReturnsNotFound(t *testing.T) {
	s := svc(&fakeVerdicts{}, fakePending{}, fakeFindings{}, &fakeOutcomes{}, &fakeAudit{})

	_, _, found, err := s.PatternVerdict(context.Background(), "check-x", "modify", "iam_user")
	require.NoError(t, err)
	require.False(t, found)
}
