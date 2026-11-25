package finding

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeRepo is an in-memory finding store.
type fakeRepo struct {
	stored            []Finding
	storedEnrichments []Enrichment
	filter            Filter
}

func (f *fakeRepo) Upsert(_ context.Context, findings []Finding) error {
	f.stored = append(f.stored, findings...)
	return nil
}

func (f *fakeRepo) UpsertEnrichment(_ context.Context, enrichments []Enrichment) error {
	f.storedEnrichments = append(f.storedEnrichments, enrichments...)
	return nil
}

func (f *fakeRepo) List(_ context.Context, filter Filter) ([]Finding, error) {
	f.filter = filter
	return f.stored, nil
}

func (f *fakeRepo) Get(_ context.Context, id string) (Finding, error) {
	for _, fnd := range f.stored {
		if fnd.ID == id {
			return fnd, nil
		}
	}
	return Finding{}, ErrNotFound
}

func (f *fakeRepo) ByIDs(_ context.Context, ids []string) ([]Finding, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []Finding
	for _, fnd := range f.stored {
		if want[fnd.ID] {
			out = append(out, fnd)
		}
	}
	return out, nil
}

func (f *fakeRepo) Summary(_ context.Context, filter Filter) (Summary, error) {
	f.filter = filter
	out := Summary{BySeverity: map[Severity]int{}, ByBand: map[string]int{}}
	for _, fnd := range f.stored {
		out.Total++
		out.BySeverity[fnd.Severity]++
		if fnd.ScoreBand != "" {
			out.ByBand[fnd.ScoreBand]++
		}
	}
	return out, nil
}

func (f *fakeRepo) RiskByResource(_ context.Context, ids []string) (map[string]Risk, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	out := map[string]Risk{}
	for _, fnd := range f.stored {
		if !want[fnd.ResourceID] {
			continue
		}
		r := out[fnd.ResourceID]
		r.Count++
		if fnd.Score > r.MaxScore {
			r.MaxScore = fnd.Score
			r.WorstBand = fnd.ScoreBand
		}
		out[fnd.ResourceID] = r
	}
	return out, nil
}

func (f *fakeRepo) ByResourceIDs(_ context.Context, ids []string) ([]Finding, error) {
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []Finding
	for _, fnd := range f.stored {
		if want[fnd.ResourceID] {
			out = append(out, fnd)
		}
	}
	return out, nil
}

func (f *fakeRepo) RiskiestResources(_ context.Context, limit int) ([]ResourceRisk, error) {
	byRes, _ := f.RiskByResource(context.Background(), distinctResources(f.stored))
	out := make([]ResourceRisk, 0, len(byRes))
	for id, r := range byRes {
		out = append(out, ResourceRisk{ResourceID: id, Risk: r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MaxScore > out[j].MaxScore })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeRepo) SignalsByResource(_ context.Context) (map[string]ResourceSignals, error) {
	out := map[string]ResourceSignals{}
	for _, fnd := range f.stored {
		if fnd.ResourceID == "" {
			continue
		}
		s := out[fnd.ResourceID]
		if fnd.Score > s.MaxScore {
			s.MaxScore = fnd.Score
		}
		if fnd.KnownExploited {
			s.HasKEV = true
		}
		if fnd.Type == "ciem_privesc" {
			s.PrivescCount++
		}
		if fnd.Type == "nuclei" && (fnd.Severity == SeverityHigh || fnd.Severity == SeverityCritical) {
			s.Exploitable = true
		}
		out[fnd.ResourceID] = s
	}
	return out, nil
}

func distinctResources(fs []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if f.ResourceID != "" && !seen[f.ResourceID] {
			seen[f.ResourceID] = true
			out = append(out, f.ResourceID)
		}
	}
	return out
}

func (f *fakeRepo) OpenKeysByConnector(_ context.Context, source, connectorID string) ([]OpenKey, error) {
	var out []OpenKey
	for _, fnd := range f.stored {
		if fnd.Source == source && !fnd.Resolved() && fnd.Metadata[ProvenanceConnectorKey] == connectorID {
			out = append(out, OpenKey{ID: fnd.ID, Region: fnd.Region, Type: fnd.Type})
		}
	}
	return out, nil
}

// OpenIDsBehindCutoff mirrors the real query's contract: open findings only,
// enriched before the cutoff, ordered by id, starting strictly after afterID,
// capped at limit. Implemented rather than stubbed so the full-pass termination
// condition (an empty page means the walk is past the end) is exercised against
// realistic data — and so the ordering is by id, which is what makes the walk
// converge even when every candidate shares an enriched_at.
func (f *fakeRepo) OpenIDsBehindCutoff(_ context.Context, cutoff time.Time, afterID string, limit int) ([]string, error) {
	var ids []string
	for _, fnd := range f.stored {
		if fnd.Resolved() || !fnd.EnrichedAt.Before(cutoff) || fnd.ID <= afterID {
			continue
		}
		ids = append(ids, fnd.ID)
	}
	sort.Strings(ids)
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	return ids, nil
}

func (f *fakeRepo) CheckQuality(_ context.Context) ([]CheckQuality, int, error) {
	byCheck := map[string]*CheckQuality{}
	for _, fnd := range f.stored {
		q, ok := byCheck[fnd.CheckID]
		if !ok {
			q = &CheckQuality{CheckID: fnd.CheckID, Source: fnd.Source}
			byCheck[fnd.CheckID] = q
		}
		switch {
		case !fnd.Resolved():
			q.Open++
		case fnd.ResolutionReason == ReasonFixed:
			q.Fixed++
		case fnd.ResolutionReason == ReasonResourceGone:
			q.ResourceGone++
		case fnd.ResolutionReason == ReasonManual:
			q.Manual++
		default:
			q.Unknown++
		}
	}
	out := make([]CheckQuality, 0, len(byCheck))
	for _, q := range byCheck {
		out = append(out, *q)
	}
	return out, 0, nil
}

func (f *fakeRepo) UnenrichedCounts(_ context.Context) ([]SeverityCount, error) {
	bySev := map[Severity]int{}
	for _, fnd := range f.stored {
		if fnd.EnrichedAt.IsZero() && fnd.ResolvedAt.IsZero() {
			bySev[fnd.Severity]++
		}
	}
	out := make([]SeverityCount, 0, len(bySev))
	for sev, n := range bySev {
		out = append(out, SeverityCount{Severity: sev, N: n})
	}
	return out, nil
}

// MustFixCoverage mirrors the real query's contract: open AND enriched only, split
// by whether the classifier reached an opinion. Never-enriched findings are the
// enrich backlog's business, not the classifier's.
func (f *fakeRepo) MustFixCoverage(_ context.Context) ([]ClassificationCoverage, error) {
	bySource := map[string]*ClassificationCoverage{}
	for _, fnd := range f.stored {
		if !fnd.ResolvedAt.IsZero() || fnd.EnrichedAt.IsZero() {
			continue
		}
		c, ok := bySource[fnd.Source]
		if !ok {
			c = &ClassificationCoverage{Source: fnd.Source}
			bySource[fnd.Source] = c
		}
		if fnd.MustFixClass == "" {
			c.Blank++
			continue
		}
		c.Classified++
	}
	out := make([]ClassificationCoverage, 0, len(bySource))
	for _, c := range bySource {
		out = append(out, *c)
	}
	return out, nil
}

// SourceActivity mirrors sourceActivityQ's plain MAX(last_observed_at) GROUP BY
// source over the fake's stored rows — no resolved_at filter, matching the
// real query (a resolved finding's last_observed_at still proves its source
// was alive then).
func (f *fakeRepo) SourceActivity(_ context.Context) ([]SourceActivity, error) {
	bySource := map[string]int64{}
	for _, fnd := range f.stored {
		var u int64
		if !fnd.LastObservedAt.IsZero() { // Go's zero time.Time isn't the Unix epoch; CH's zero DateTime is
			u = fnd.LastObservedAt.Unix()
		}
		if u > bySource[fnd.Source] {
			bySource[fnd.Source] = u
		}
	}
	out := make([]SourceActivity, 0, len(bySource))
	for source, last := range bySource {
		out = append(out, SourceActivity{Source: source, LastActivityUnix: last})
	}
	return out, nil
}

// AgeIntegrity mirrors findingAgeIntegrity's predicates over the fake's stored
// rows. The fake holds one row per id, so its single DetectedAt is both the
// oldest and the newest — the distinction the real query makes between
// min(detected_at) and argMax(detected_at) has no analogue here, which is
// exactly why the CH-backed integration test is the one that proves the read.
func (f *fakeRepo) AgeIntegrity(_ context.Context) (AgeIntegrity, error) {
	var out AgeIntegrity
	for _, fnd := range f.stored {
		if !fnd.ResolvedAt.IsZero() {
			continue
		}
		if fnd.FirstDetectedAt.IsZero() {
			out.Missing++
			continue
		}
		if fnd.FirstDetectedAt.Before(fnd.DetectedAt.Add(-time.Minute)) {
			out.Preserved++
		}
		if age := int64(time.Since(fnd.FirstDetectedAt).Seconds()); age > out.OldestSeconds {
			out.OldestSeconds = age
		}
	}
	return out, nil
}

func (f *fakeRepo) CountByCheckID(_ context.Context, source, checkID string) (int, error) {
	seen := map[string]bool{}
	for _, fnd := range f.stored {
		if fnd.Source == source && fnd.CheckID == checkID && fnd.ResourceID != "" {
			seen[fnd.ResourceID] = true
		}
	}
	return len(seen), nil
}

func (f *fakeRepo) OpenResourcesByCheck(_ context.Context, checkIDs []string) (map[string][]string, error) {
	want := map[string]bool{}
	for _, id := range checkIDs {
		want[id] = true
	}
	out := map[string][]string{}
	for _, fnd := range f.stored {
		if want[fnd.CheckID] && fnd.ResourceID != "" && fnd.ResolvedAt.IsZero() {
			out[fnd.CheckID] = append(out[fnd.CheckID], fnd.ResourceID)
		}
	}
	return out, nil
}

func (f *fakeRepo) DistinctCheckIDs(_ context.Context, _ string) ([]string, error) {
	seen := map[string]bool{}
	for _, fnd := range f.stored {
		if fnd.CheckID != "" {
			seen[fnd.CheckID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out, nil
}

func (f *fakeRepo) Clusters(_ context.Context, filter Filter) ([]Cluster, int, error) {
	f.filter = filter
	byCheck := map[string]*Cluster{}
	res := map[string]map[string]bool{}
	for _, fnd := range f.stored {
		c := byCheck[fnd.CheckID]
		if c == nil {
			c = &Cluster{CheckID: fnd.CheckID, Title: fnd.Title, Severity: fnd.Severity, Source: fnd.Source}
			byCheck[fnd.CheckID] = c
			res[fnd.CheckID] = map[string]bool{}
		}
		c.Instances++
		res[fnd.CheckID][fnd.ResourceID] = true
		if fnd.Score > c.MaxScore {
			c.MaxScore = fnd.Score
			c.WorstBand = fnd.ScoreBand
		}
		if fnd.KnownExploited {
			c.KnownExploited = true
		}
	}
	out := make([]Cluster, 0, len(byCheck))
	for id, c := range byCheck {
		c.Resources = len(res[id])
		out = append(out, *c)
	}
	return out, len(out), nil
}

func TestRecord_StoresFindings(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)

	in := []Finding{
		{ID: "1", Source: "cspm", Severity: SeverityMedium, Title: "x", DetectedAt: time.Now()},
		{ID: "2", Source: "cspm", Severity: SeverityLow, Title: "y", DetectedAt: time.Now()},
	}
	require.NoError(t, svc.Record(context.Background(), in))
	require.Len(t, repo.stored, 2)
}

func TestRecord_EmptyIsNoop(t *testing.T) {
	repo := &fakeRepo{}
	require.NoError(t, NewService(repo).Record(context.Background(), nil))
	require.Empty(t, repo.stored)
}

func TestRecordEnrichment_StoresEnrichments(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)

	in := []Enrichment{
		{ID: "1", Score: 80, ScoreBand: "critical", EnrichedAt: time.Now()},
		{ID: "2", Score: 10, ScoreBand: "low", EnrichedAt: time.Now()},
	}
	require.NoError(t, svc.RecordEnrichment(context.Background(), in))
	require.Len(t, repo.storedEnrichments, 2)
}

func TestRecordEnrichment_EmptyIsNoop(t *testing.T) {
	repo := &fakeRepo{}
	require.NoError(t, NewService(repo).RecordEnrichment(context.Background(), nil))
	require.Empty(t, repo.storedEnrichments)
}

func TestClusters_GroupsByCheck(t *testing.T) {
	// Same check on three resources, plus a second check — clustering collapses
	// the four findings into two rows carrying the worst score + instance counts.
	repo := &fakeRepo{stored: []Finding{
		{ID: "1", CheckID: "aws-privesc-01", Title: "IAM privesc", Severity: SeverityCritical, Source: "cspm", ResourceID: "u1", Score: 80, ScoreBand: "high"},
		{ID: "2", CheckID: "aws-privesc-01", Title: "IAM privesc", Severity: SeverityCritical, Source: "cspm", ResourceID: "u2", Score: 86, ScoreBand: "page", KnownExploited: true},
		{ID: "3", CheckID: "aws-privesc-01", Title: "IAM privesc", Severity: SeverityCritical, Source: "cspm", ResourceID: "u1", Score: 70, ScoreBand: "pipeline"},
		{ID: "4", CheckID: "CVE-2023-44487", Title: "HTTP/2", Severity: SeverityHigh, Source: "supply_chain", ResourceID: "pkg1", Score: 90, ScoreBand: "page"},
	}}
	got, total, err := NewService(repo).Clusters(context.Background(), Filter{})
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, 2, total)

	byCheck := map[string]Cluster{}
	for _, c := range got {
		byCheck[c.CheckID] = c
	}
	privesc := byCheck["aws-privesc-01"]
	require.Equal(t, 3, privesc.Instances, "three findings collapse into one cluster")
	require.Equal(t, 2, privesc.Resources, "across two distinct resources (u1 twice)")
	require.Equal(t, uint8(86), privesc.MaxScore, "carries the worst score")
	require.Equal(t, "page", privesc.WorstBand, "and the band of the worst instance")
	require.True(t, privesc.KnownExploited, "any KEV instance flags the cluster")
}

func TestList_PassesFilterThrough(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{ID: "1"}}}
	svc := NewService(repo)

	got, err := svc.List(context.Background(), Filter{Source: "cspm", Severity: SeverityHigh, Limit: 50})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "cspm", repo.filter.Source)
	require.Equal(t, SeverityHigh, repo.filter.Severity)
	require.Equal(t, 50, repo.filter.Limit)
}

// --- lifecycle ---

func TestRecordObserved_StampsObservationAndClearsResolution(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)

	in := []Finding{{ID: "f1", ResolvedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}}
	require.NoError(t, svc.RecordObserved(context.Background(), in))

	require.Len(t, repo.stored, 1)
	got := repo.stored[0]
	require.False(t, got.LastObservedAt.IsZero(), "observation stamped")
	require.True(t, got.ResolvedAt.IsZero(), "re-observed resolved finding is reopened (regression)")
	require.False(t, got.Resolved())
}

func TestRecord_DoesNotTouchLifecycle(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)

	resolvedAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	in := []Finding{{ID: "f1", ResolvedAt: resolvedAt, Score: 60}}
	require.NoError(t, svc.Record(context.Background(), in))

	got := repo.stored[0]
	require.Equal(t, resolvedAt, got.ResolvedAt, "a score write is not an observation — resolution preserved")
	require.True(t, got.LastObservedAt.IsZero())
}

func TestResolve_SetsResolvedAtAndReason(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{ID: "f1"}}}
	svc := NewService(repo)

	require.NoError(t, svc.Resolve(context.Background(), []Finding{{ID: "f1"}}, ReasonResourceGone))
	require.Len(t, repo.stored, 2)
	require.True(t, repo.stored[1].Resolved())
	require.Equal(t, ReasonResourceGone, repo.stored[1].ResolutionReason,
		"the reason must be persisted, not just accepted — it is the whole basis of the junk-rate metric")

	// Empty input is a no-op — no write.
	require.NoError(t, svc.Resolve(context.Background(), nil, ReasonFixed))
	require.Len(t, repo.stored, 2)
}

// Resolve writes the CURRENT row, not the caller's possibly minutes-old copy:
// a re-observation recorded since (new metadata, title, last_observed_at)
// must survive, and only the resolution and its annotations come from the
// caller. A finding the re-read cannot find is not created by resolving it.
func TestResolve_RereadsBeforeWriting(t *testing.T) {
	observed := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	repo := &fakeRepo{stored: []Finding{{ID: "f1", Title: "fresh", LastObservedAt: observed, Metadata: map[string]string{"affected_instances": "12"}}}}
	stale := Finding{ID: "f1", Title: "stale", Metadata: map[string]string{"affected_instances": "3", "resolved_by": "alice"}}

	require.NoError(t, NewService(repo).Resolve(context.Background(), []Finding{stale, {ID: "gone"}}, ReasonManual))
	require.Len(t, repo.stored, 2, "only the finding that still exists is written")
	got := repo.stored[1]
	require.Equal(t, "fresh", got.Title)
	require.Equal(t, observed, got.LastObservedAt)
	require.Equal(t, "12", got.Metadata["affected_instances"])
	require.Equal(t, "alice", got.Metadata["resolved_by"])
	require.True(t, got.Resolved())
}

// An unexplained resolution must fail rather than write a blank reason. Silently
// defaulting is how "resolved" became unmeasurable in the first place: every
// resolution looked alike, so a check driving real remediation and a check
// narrating cloud churn produced identical data.
func TestResolve_RejectsInvalidReason(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)

	for _, bad := range []ResolutionReason{"", "because", "FIXED"} {
		err := svc.Resolve(context.Background(), []Finding{{ID: "f1"}}, bad)
		require.ErrorIs(t, err, ErrInvalidResolution, "reason %q must be rejected", bad)
	}
	require.Empty(t, repo.stored, "a rejected resolution must not write anything")
}

func TestCheckQuality_JunkRate(t *testing.T) {
	// unknown (no reason recorded) is excluded rather than guessed at.
	q := CheckQuality{Fixed: 10, ResourceGone: 30, Manual: 10, Unknown: 900}
	require.InDelta(t, 0.6, q.JunkRate(), 0.0001)
	require.True(t, q.Measurable())

	// Nothing quality-bearing yet: a harmless zero, not NaN — a caller that skips
	// Measurable() must not paint a wild number on a dashboard.
	empty := CheckQuality{Unknown: 1000}
	require.Zero(t, empty.JunkRate())
	require.False(t, empty.Measurable())

	// A handful of resolutions is not evidence about a check.
	require.False(t, CheckQuality{Fixed: 1, ResourceGone: 2}.Measurable())
}

// A provider archiving a finding is neither remediation nor evidence of noise,
// so provider_closed is accepted by Resolve but grades nothing.
func TestReasonProviderClosed_ValidButNotQualityBearing(t *testing.T) {
	require.True(t, ReasonProviderClosed.Valid())
	require.False(t, ReasonProviderClosed.CountsTowardQuality())
}

func TestFindingResolved_SentinelSafe(t *testing.T) {
	// ClickHouse zero DateTime scans as 1970 — both true-zero and epoch count as open.
	require.False(t, Finding{}.Resolved())
	require.False(t, Finding{ResolvedAt: time.Unix(0, 0)}.Resolved())
	require.True(t, Finding{ResolvedAt: time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)}.Resolved())
}

// The counterpart to asset.Service.PurgeAccount: every OPEN finding on a
// purged resource must resolve as resource_gone, and an already-resolved one
// must not be touched twice (its resolution reason/timestamp should stay
// whatever it already was, not get silently overwritten by a purge sweep
// that has no idea why it was already closed).
func TestResolveGoneByResourceIDs(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{
		{ID: "f1", ResourceID: "asset-1"},
		{ID: "f2", ResourceID: "asset-2"},
		{ID: "f3", ResourceID: "asset-3", ResolvedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ResolutionReason: ReasonFixed},
		{ID: "f4", ResourceID: "asset-not-in-batch"},
	}}
	svc := NewService(repo)

	n, err := svc.ResolveGoneByResourceIDs(context.Background(), []string{"asset-1", "asset-2", "asset-3"})
	require.NoError(t, err)
	require.Equal(t, 2, n, "only the 2 OPEN findings among the 3 resource IDs get resolved")

	byID := map[string]Finding{}
	for _, f := range repo.stored {
		byID[f.ID] = f
	}
	require.True(t, byID["f1"].Resolved())
	require.Equal(t, ReasonResourceGone, byID["f1"].ResolutionReason)
	require.True(t, byID["f2"].Resolved())
	require.Equal(t, ReasonFixed, byID["f3"].ResolutionReason,
		"an already-resolved finding must keep its real reason, not get relabeled resource_gone")
	require.False(t, byID["f4"].Resolved(), "a resource ID outside the batch must not be touched")
}

// Batching must not lose or double-resolve findings when the resource-ID list
// spans more than one resourceIDBatchSize page.
func TestResolveGoneByResourceIDs_BatchesAcrossPages(t *testing.T) {
	var stored []Finding
	var ids []string
	for i := range resourceIDBatchSize + 50 {
		id := fmt.Sprintf("asset-%d", i)
		ids = append(ids, id)
		stored = append(stored, Finding{ID: fmt.Sprintf("f%d", i), ResourceID: id})
	}
	repo := &fakeRepo{stored: stored}
	svc := NewService(repo)

	n, err := svc.ResolveGoneByResourceIDs(context.Background(), ids)
	require.NoError(t, err)
	require.Equal(t, resourceIDBatchSize+50, n)

	// fakeRepo.Upsert appends rather than replacing, so dedupe by ID to the
	// LAST write per finding — the real ClickHouse ReplacingMergeTree behavior
	// TestResolveGoneByResourceIDs already relies on the same way.
	byID := map[string]Finding{}
	for _, f := range repo.stored {
		byID[f.ID] = f
	}
	require.Len(t, byID, resourceIDBatchSize+50)
	for _, f := range byID {
		require.True(t, f.Resolved())
	}
}

type fakeResolveObserver struct{ ids []string }

func (o *fakeResolveObserver) FindingsResolved(_ context.Context, ids []string) error {
	o.ids = append(o.ids, ids...)
	return nil
}

// Every resolve tells the observer which findings it closed (enrichcache ends
// their alert episode, so a regression re-alerts) — and only those it wrote.
func TestResolve_NotifiesTheResolveObserver(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{ID: "f1"}}}
	obs := &fakeResolveObserver{}
	require.NoError(t, NewService(repo).WithResolveObserver(obs).Resolve(context.Background(), []Finding{{ID: "f1"}, {ID: "gone"}}, ReasonFixed))
	require.Equal(t, []string{"f1"}, obs.ids)
}
