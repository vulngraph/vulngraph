package jobs

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/notify"
)

// fakeFetcher satisfies FindingFetcher for tests, returning a finding by ID.
type fakeFetcher struct {
	findings map[string]finding.Finding
}

func newFakeFetcher(findings ...finding.Finding) *fakeFetcher {
	m := make(map[string]finding.Finding, len(findings))
	for _, f := range findings {
		m[f.ID] = f
	}
	return &fakeFetcher{findings: m}
}

func (f *fakeFetcher) Get(_ context.Context, id string) (finding.Finding, error) {
	if fnd, ok := f.findings[id]; ok {
		return fnd, nil
	}
	return finding.Finding{}, finding.ErrNotFound
}

type fakeEnricher struct {
	score enrich.Score
	err   error
	calls int
}

func (f *fakeEnricher) Enrich(context.Context, finding.Finding) (enrich.Score, error) {
	f.calls++
	return f.score, f.err
}

type fakeSuppressionChecker struct {
	suppressed bool
	err        error
	calls      int
}

func (f *fakeSuppressionChecker) IsSuppressed(context.Context, string) (bool, error) {
	f.calls++
	return f.suppressed, f.err
}

// simpleFetcher returns a minimal finding for any ID (tests that don't care about content).
func simpleFetcher(id string) *fakeFetcher { return newFakeFetcher(finding.Finding{ID: id}) }

// Below the pipeline threshold: enriched but never enqueued for a decision.
// (No river client in context — proves the worker doesn't reach the enqueue.)
func TestEnrichWorker_BelowThreshold_NoDecide(t *testing.T) {
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline - 1, Band: enrich.BandMonitor}}
	w := &EnrichWorker{enrich: e, findings: simpleFetcher("f1")}

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
	require.NoError(t, err)
	require.Equal(t, 1, e.calls)
}

// At/above the threshold the worker attempts the decide enqueue; with no client
// in context that is logged and skipped (client-safe), not a panic or error.
func TestEnrichWorker_AboveThreshold_EnqueuesClientSafe(t *testing.T) {
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	w := &EnrichWorker{enrich: e, findings: simpleFetcher("f1")}

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
	require.NoError(t, err)
}

// An above-threshold but suppressed finding is checked and then skipped — it
// never reaches the decide enqueue. The check is consulted exactly once.
func TestEnrichWorker_Suppressed_SkipsDecide(t *testing.T) {
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{suppressed: true}
	w := &EnrichWorker{enrich: e, findings: simpleFetcher("f1"), suppress: sup}

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls)
}

// A suppression-store error must not drop the decision: the worker logs and
// proceeds (fail-soft), reaching the client-safe enqueue without erroring.
func TestEnrichWorker_SuppressionCheckError_ProceedsSoft(t *testing.T) {
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{err: errors.New("pg down")}
	w := &EnrichWorker{enrich: e, findings: simpleFetcher("f1"), suppress: sup}

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls)
}

// A non-suppressed finding above threshold passes the gate and proceeds to the
// client-safe enqueue.
func TestEnrichWorker_NotSuppressed_Proceeds(t *testing.T) {
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{suppressed: false}
	w := &EnrichWorker{enrich: e, findings: simpleFetcher("f1"), suppress: sup}

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls)
}

type fakeAlertDispatcher struct{ calls int }

func (f *fakeAlertDispatcher) Deliver(context.Context, notify.Notification) (int, error) {
	f.calls++
	return 1, nil
}

// A suppressed critical must not page: suppression silences the outbound alert,
// not just the decision pipeline — otherwise an acknowledged finding re-alerts
// on every cache-miss re-enrich and on the 24h freshness backstop.
func TestEnrichWorker_Suppressed_SkipsAlert(t *testing.T) {
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{suppressed: true}
	alerts := &fakeAlertDispatcher{}
	w := &EnrichWorker{
		enrich: e, suppress: sup, notify: alerts,
		findings: newFakeFetcher(finding.Finding{ID: "f1", Severity: finding.SeverityCritical}),
	}

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
	require.NoError(t, err)
	require.Zero(t, alerts.calls, "a suppressed critical must not dispatch an alert")
}

// A non-suppressed page-band finding still alerts (the suppression gate must not
// swallow legitimate pages), and a suppression-store error fails soft: the
// alert goes out rather than being silently dropped on a PG hiccup.
func TestEnrichWorker_PageAlerts_UnlessSuppressed(t *testing.T) {
	for name, sup := range map[string]*fakeSuppressionChecker{
		"not suppressed":   {suppressed: false},
		"check error soft": {err: errors.New("pg down")},
	} {
		t.Run(name, func(t *testing.T) {
			e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPage, Band: enrich.BandPage}}
			alerts := &fakeAlertDispatcher{}
			w := &EnrichWorker{
				enrich: e, suppress: sup, notify: alerts,
				findings: newFakeFetcher(finding.Finding{ID: "f1", Severity: finding.SeverityCritical}),
			}

			err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
			require.NoError(t, err)
			require.Equal(t, 1, alerts.calls)
		})
	}
}

func TestEnrichWorker_EnrichError(t *testing.T) {
	w := &EnrichWorker{enrich: &fakeEnricher{err: errors.New("ch down")}, findings: simpleFetcher("f1")}
	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}})
	require.ErrorContains(t, err, "Work")
}

// --- change-gate ---

type fakeEnrichCache struct {
	entries     map[string]enrichcache.Entry
	getErr      error
	puts        int
	invalidated []string
	alerts      map[string]enrichcache.AlertState
	alertErr    error
}

func newFakeEnrichCache() *fakeEnrichCache {
	return &fakeEnrichCache{entries: map[string]enrichcache.Entry{}}
}

func (c *fakeEnrichCache) Get(_ context.Context, id string) (enrichcache.Entry, error) {
	if c.getErr != nil {
		return enrichcache.Entry{}, c.getErr
	}
	if e, ok := c.entries[id]; ok {
		return e, nil
	}
	return enrichcache.Entry{}, enrichcache.ErrNotFound
}

func (c *fakeEnrichCache) Put(_ context.Context, e enrichcache.Entry) error {
	c.entries[e.FindingID] = e
	c.puts++
	return nil
}

func (c *fakeEnrichCache) InvalidateFingerprints(_ context.Context, ids []string) error {
	for _, id := range ids {
		c.invalidated = append(c.invalidated, id)
		if e, ok := c.entries[id]; ok {
			e.InputFP = ""
			c.entries[id] = e
		}
	}
	return nil
}

func (c *fakeEnrichCache) AlertState(_ context.Context, id string) (enrichcache.AlertState, error) {
	if c.alertErr != nil {
		return enrichcache.AlertState{}, c.alertErr
	}
	if a, ok := c.alerts[id]; ok {
		return a, nil
	}
	return enrichcache.AlertState{}, enrichcache.ErrNotFound
}

func (c *fakeEnrichCache) RecordAlert(_ context.Context, a enrichcache.AlertState) error {
	if c.alerts == nil {
		c.alerts = map[string]enrichcache.AlertState{}
	}
	c.alerts[a.FindingID] = a
	return nil
}

var gateNow = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

// defaultFinding is the finding used by simple tests that only care about a specific field.
var defaultFinding = finding.Finding{ID: "f1", CheckID: "c1"}

func gatedWorker(e enricher, cache EnrichCache, findings ...finding.Finding) *EnrichWorker {
	ff := newFakeFetcher(findings...)
	if len(findings) == 0 {
		ff = newFakeFetcher(defaultFinding)
	}
	return &EnrichWorker{enrich: e, findings: ff, cache: cache, maxAge: time.Hour, now: func() time.Time { return gateNow }}
}

func cachedFP(f finding.Finding, age time.Duration) enrichcache.Entry {
	return enrichcache.Entry{
		FindingID:  f.ID,
		InputFP:    enrichcache.Fingerprint(fingerprintInput(f)),
		EnrichedAt: gateNow.Add(-age),
	}
}

func TestEnrichWorker_UnchangedAndFresh_Skips(t *testing.T) {
	// The cache-skip only applies when Score>0 (already enriched at least once).
	// A re-ingested finding that lost its score (Score=0) must always be enriched.
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityHigh, Score: enrich.ThresholdPipeline}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = cachedFP(f, 30*time.Minute) // fresh within the 1h backstop
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline}}

	err := gatedWorker(e, cache, f).Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 0, e.calls, "unchanged + fresh + score>0 => enrich skipped (no graph walk, no decide)")
}

func TestEnrichWorker_ZeroScore_AlwaysEnriches(t *testing.T) {
	// A finding with Score=0 is a sentinel meaning "never enriched" or "score lost
	// after ClickHouse re-ingest". Always enrich regardless of cache freshness.
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityHigh, Score: 0}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = cachedFP(f, 30*time.Minute) // cache says fresh — should be ignored
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline - 1, Band: enrich.BandMonitor}}

	err := gatedWorker(e, cache, f).Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 1, e.calls, "score=0 => always enrich even if cache says fresh")
}

func TestEnrichWorker_Stale_Reenriches(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1"}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = cachedFP(f, 2*time.Hour) // older than the 1h backstop
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline - 1, Band: enrich.BandMonitor}}

	w := gatedWorker(e, cache, f)
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}}))
	require.Equal(t, 1, e.calls, "stale beyond backstop => re-enrich")
	require.Equal(t, 1, cache.puts, "and refresh the cache")
}

func TestEnrichWorker_ContentChanged_Reenriches(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityLow}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = enrichcache.Entry{FindingID: "f1", InputFP: "different-fp", EnrichedAt: gateNow}
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline - 1, Band: enrich.BandMonitor}}

	require.NoError(t, gatedWorker(e, cache, f).Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}}))
	require.Equal(t, 1, e.calls, "fingerprint mismatch => re-enrich even when fresh")
}

func TestEnrichWorker_KEVFlip_Reenriches(t *testing.T) {
	base := finding.Finding{ID: "f1", CheckID: "c1"}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = cachedFP(base, time.Minute) // fresh, fingerprint without KEV
	kevd := base
	kevd.KnownExploited = true
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline - 1, Band: enrich.BandMonitor}}

	require.NoError(t, gatedWorker(e, cache, kevd).Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: kevd.ID}}))
	require.Equal(t, 1, e.calls, "KEV escalation flips the fingerprint => re-enrich within the backstop")
}

func TestEnrichWorker_FirstSeen_EnrichesAndCaches(t *testing.T) {
	cache := newFakeEnrichCache()
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline - 1, Band: enrich.BandMonitor}}

	require.NoError(t, gatedWorker(e, cache).Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}}))
	require.Equal(t, 1, e.calls, "no cache entry => enrich")
	require.Equal(t, 1, cache.puts, "first enrich populates the cache")
}

func TestEnrichWorker_CacheError_FailOpen(t *testing.T) {
	cache := newFakeEnrichCache()
	cache.getErr = errors.New("pg down")
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline - 1, Band: enrich.BandMonitor}}

	require.NoError(t, gatedWorker(e, cache).Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: "f1"}}))
	require.Equal(t, 1, e.calls, "cache read error => fail open, enrich anyway")
}

// --- version-only re-score skip: a version-bump-only miss skips decide/alert when the band is unchanged ---

// versionOnlyEntry builds a cache entry that looks like it was written under a
// DIFFERENT LogicVersion for the same finding: its ContextFP matches what f
// hashes to today (context unchanged) but its InputFP does not (so the
// change-gate's full-fingerprint fast path misses), with a recorded prior
// ScoreBand.
func versionOnlyEntry(f finding.Finding, priorBand enrich.Band, age time.Duration) enrichcache.Entry {
	return enrichcache.Entry{
		FindingID:  f.ID,
		InputFP:    "stale-version-fp", // deliberately not enrichcache.Fingerprint(...): simulates a version bump
		ContextFP:  enrichcache.ContextFingerprint(fingerprintInput(f)),
		ScoreBand:  string(priorBand),
		EnrichedAt: gateNow.Add(-age),
	}
}

// A version-bump-only miss (context unchanged) whose recomputed band matches
// the stored one must skip both the decide enqueue and the alert dispatch —
// the recompute happened so the new scoring logic took effect, but nothing
// about this finding's disposition moved, so it must not re-enter the decide
// pipeline or re-page.
func TestEnrichWorker_VersionBumpOnly_SameBand_SkipsDecideAndAlert(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityCritical, Score: enrich.ThresholdPipeline}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = versionOnlyEntry(f, enrich.BandPipeline, time.Minute)
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{}
	alerts := &fakeAlertDispatcher{}
	w := gatedWorker(e, cache, f)
	w.suppress = sup
	w.notify = alerts

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 1, e.calls, "the score must still be recomputed so new logic takes effect")
	require.Equal(t, 1, cache.puts, "the recomputed fingerprint/band must be persisted")
	require.Zero(t, sup.calls, "band unchanged => decide gate never reached")
	require.Zero(t, alerts.calls, "band unchanged => must not re-alert on a version-only re-score")
}

// A version-bump-only miss whose recomputed band DID move must still decide
// (and is eligible to alert) — the version bump revealed a real change in the
// finding's disposition, even though its inputs never changed.
func TestEnrichWorker_VersionBumpOnly_BandChanged_Decides(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityCritical, Score: enrich.ThresholdPipeline}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = versionOnlyEntry(f, enrich.BandMonitor, time.Minute)
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{}
	w := gatedWorker(e, cache, f)
	w.suppress = sup

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls, "band changed => the decide gate must still be reached")
}

// An entry with no stored context fingerprint cannot prove the miss is
// version-only, so it must fall through to a decide — fail-open, we cannot
// prove nothing changed.
func TestEnrichWorker_NoStoredContext_Decides(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityCritical,
		Score: enrich.ThresholdPipeline, ScoreBand: string(enrich.BandPipeline)}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = enrichcache.Entry{
		FindingID: f.ID, InputFP: "fp-from-another-version", ContextFP: "", ScoreBand: string(enrich.BandPipeline),
		EnrichedAt: gateNow.Add(-time.Minute),
	}
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{}
	w := gatedWorker(e, cache, f)
	w.suppress = sup

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls, "a miss with no stored context must fail open to deciding")
}

// The freshness backstop outranks the version-only skip: an entry older than
// the backstop was due a re-decide regardless of the bump (the backstop exists
// for graph drift the fingerprint can't see).
func TestEnrichWorker_VersionBumpOnly_StaleEntry_StillDecides(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityCritical, Score: enrich.ThresholdPipeline}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = versionOnlyEntry(f, enrich.BandPipeline, 2*time.Hour) // gatedWorker's maxAge is 1h
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{}
	w := gatedWorker(e, cache, f)
	w.suppress = sup

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls, "a stale entry must decide even when the miss is version-only")
}

// A genuine context change (real input differs, not just LogicVersion) must
// keep enqueueing exactly as before, regardless of whether the resulting band
// happens to match the prior one.
func TestEnrichWorker_ContextChanged_AlwaysDecidesEvenIfBandSame(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityCritical, Score: enrich.ThresholdPipeline}
	cache := newFakeEnrichCache()
	cache.entries["f1"] = enrichcache.Entry{
		FindingID:  f.ID,
		InputFP:    "totally-different-fp",
		ContextFP:  "totally-different-context-fp", // real input change, not a version bump
		ScoreBand:  string(enrich.BandPipeline),    // same band as what's about to be recomputed
		EnrichedAt: gateNow.Add(-time.Minute),
	}
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPipeline, Band: enrich.BandPipeline}}
	sup := &fakeSuppressionChecker{}
	w := gatedWorker(e, cache, f)
	w.suppress = sup

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls, "a real context change must always reach the decide gate, "+
		"even when the recomputed band happens to match the prior one")
}

// A brand-new finding (no prior cache entry) always decides and is eligible
// to alert — there is no "version-only" classification without a prior entry
// to compare against.
func TestEnrichWorker_BrandNewFinding_DecidesAndAlerts(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityCritical}
	cache := newFakeEnrichCache()
	e := &fakeEnricher{score: enrich.Score{Value: enrich.ThresholdPage, Band: enrich.BandPage}}
	sup := &fakeSuppressionChecker{}
	alerts := &fakeAlertDispatcher{}
	w := gatedWorker(e, cache, f)
	w.suppress = sup
	w.notify = alerts

	err := w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}})
	require.NoError(t, err)
	require.Equal(t, 1, sup.calls, "brand-new finding must reach the decide gate")
	require.Equal(t, 1, alerts.calls, "a brand-new page-band finding must alert")
}

type fakeLister struct {
	found []finding.Finding
	err   error
}

func (f fakeLister) List(context.Context, finding.Filter) ([]finding.Finding, error) {
	return f.found, f.err
}

func TestEnrichSweepWorker_ListError(t *testing.T) {
	w := &EnrichSweepWorker{findings: fakeLister{err: errors.New("ch down")}}
	err := w.Work(context.Background(), &river.Job[EnrichSweepArgs]{})
	require.ErrorContains(t, err, "list findings")
}

// The sweep enqueues per finding via the client-safe path, so with no client it
// completes (logs) rather than panicking. No client also means the capacity
// check is skipped — the sweep proceeds, matching enqueueEnrich's fallback.
func TestEnrichSweepWorker_EnqueuesClientSafe(t *testing.T) {
	w := &EnrichSweepWorker{findings: fakeLister{found: []finding.Finding{{ID: "f1"}, {ID: "f2"}}}}
	err := w.Work(context.Background(), &river.Job[EnrichSweepArgs]{})
	require.NoError(t, err)
}

// TestEnrichSweepPriority_NeverOutranksIngestTimeEnrich is the regression
// guard for a backlog bug: the periodic full-corpus re-enrich sweep used the
// SAME priority as ingest-time enrichment of a brand-new detection or a
// KEV-escalation re-enrich, so a deep routine backlog could starve the urgent
// half indefinitely. River's priority is a hard ordering, not a tie-break, so
// this only needs to hold as an inequality, not an exact value.
func TestEnrichSweepPriority_NeverOutranksIngestTimeEnrich(t *testing.T) {
	require.Greater(t, enrichSweepPriority, river.PriorityDefault,
		"the periodic sweep must be strictly lower-priority (higher number) than ingest-time/KEV enrichment")
	require.LessOrEqual(t, enrichSweepPriority, 4, "River rejects a priority outside 1-4")
}

// recordingLister records every Filter it is asked for so a test can assert the
// sweep's pass ordering. An empty backlog (nil result) means one call per filter.
type recordingLister struct{ seen []finding.Filter }

func (r *recordingLister) List(_ context.Context, f finding.Filter) ([]finding.Finding, error) {
	r.seen = append(r.seen, f)
	return nil, nil
}

// The sweep must backfill never-enriched findings most-severe-first BEFORE the
// drift re-enrichment pass — otherwise critical findings hide at score 0 while
// the drift pass spends budget on already-enriched findings.
func TestEnrichSweepWorker_BackfillsUnenrichedSeverityFirst(t *testing.T) {
	r := &recordingLister{}
	w := &EnrichSweepWorker{findings: r}
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichSweepArgs]{}))

	require.Len(t, r.seen, 5, "4 unenriched severity passes + 1 drift pass")
	wantSev := []finding.Severity{
		finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow,
	}
	for i, sev := range wantSev {
		require.True(t, r.seen[i].Unenriched, "phase-1 pass %d targets never-enriched findings", i)
		require.Equal(t, sev, r.seen[i].Severity, "phase-1 pass %d severity order", i)
	}
	require.False(t, r.seen[4].Unenriched, "phase-2 drift pass targets already-enriched findings")
	require.True(t, r.seen[4].StaleFirst,
		"phase-2 drift pass must sort oldest-enriched-first (not detected_at desc) or it "+
			"never reaches a corpus tail bigger than one tick's budget — the root cause of "+
			"a large share of findings stuck without must_fix_class after the feature shipped")
	require.Empty(t, r.seen[4].Severity)
}

// pagingStaleLister returns enrichSweepLimit findings on the first call (to force
// drain into a second page) and none after, recording the cursor it was called
// with each time — so the test can assert drain advances the StaleFirst cursor
// with EncodeStaleCursor (enriched_at-keyed), not EncodeCursor (detected_at-keyed).
type pagingStaleLister struct {
	calls   int
	cursors []string
}

func (p *pagingStaleLister) List(_ context.Context, f finding.Filter) ([]finding.Finding, error) {
	p.cursors = append(p.cursors, f.Cursor)
	p.calls++
	if p.calls > 1 {
		return nil, nil
	}
	out := make([]finding.Finding, enrichSweepLimit)
	for i := range out {
		out[i] = finding.Finding{
			ID:         "f" + string(rune('a'+i%26)) + string(rune('0'+i/26)),
			EnrichedAt: time.Unix(int64(i), 0),
		}
	}
	return out, nil
}

// A StaleFirst drain that spans multiple pages must seek with the enriched_at-
// keyed EncodeStaleCursor. Before this fix, drain always used EncodeCursor(_,
// false) (detected_at-keyed) regardless of sort mode — a decode-mode mismatch
// (ErrBadCursor) on the very next page of any StaleFirst drift-pass sweep.
func TestEnrichSweepWorker_Drain_StaleFirst_UsesStaleCursor(t *testing.T) {
	p := &pagingStaleLister{}
	w := &EnrichSweepWorker{findings: p}

	n, err := w.drain(context.Background(), finding.Filter{StaleFirst: true}, enrichSweepMax, enrichSweepPriority)
	require.NoError(t, err)
	require.Equal(t, enrichSweepLimit, n)
	require.Len(t, p.cursors, 2, "first page (empty cursor) + second page (seeked)")
	require.Empty(t, p.cursors[0])

	last := finding.Finding{
		ID:         "f" + string(rune('a'+(enrichSweepLimit-1)%26)) + string(rune('0'+(enrichSweepLimit-1)/26)),
		EnrichedAt: time.Unix(int64(enrichSweepLimit-1), 0),
	}
	require.Equal(t, finding.EncodeStaleCursor(last), p.cursors[1],
		"drain must seek StaleFirst pages with the enriched_at-keyed cursor")
}

type fakeJobLister struct {
	jobs int
	err  error
}

func (f fakeJobLister) JobList(context.Context, *river.JobListParams) (*river.JobListResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &river.JobListResult{Jobs: make([]*rivertype.JobRow, f.jobs)}, nil
}

// Depth drives both the sweep skip and the ingest-time backpressure gate:
// at or over enrichQueueMax means no capacity, and a failed check is
// fail-closed (treated as full).
func TestEnrichQueueDepth(t *testing.T) {
	depth, err := enrichQueueDepth(context.Background(), fakeJobLister{jobs: 3}, enrichQueueMax)
	require.NoError(t, err)
	require.Equal(t, 3, depth)
	require.Less(t, depth, enrichQueueMax, "3 jobs is under capacity")

	depth, err = enrichQueueDepth(context.Background(), fakeJobLister{jobs: enrichQueueMax + 1}, enrichQueueMax)
	require.NoError(t, err)
	require.GreaterOrEqual(t, depth, enrichQueueMax, "over the cap reads as full")

	_, err = enrichQueueDepth(context.Background(), fakeJobLister{err: errors.New("pg down")}, enrichQueueMax)
	require.ErrorContains(t, err, "enrichQueueDepth")
}

// TestEnrichSweepWorker_Phase1RunsWithoutARiverClient pins that Phase 1 runs to
// completion and Phase 2 follows it (no pass dropped).
//
// sweepHasCapacity fails open with no River client in context, so this test cannot
// see either phase's gate. TestEnrichSweepWorker_Phase1CeilingIsHigherNotAbsent below
// pins that Phase 1 is gated on backfillQueueCeiling, which is strictly greater than
// the enrichQueueMax that gates Phase 2.
func TestEnrichSweepWorker_Phase1RunsWithoutARiverClient(t *testing.T) {
	r := &recordingLister{}
	w := &EnrichSweepWorker{findings: r}
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichSweepArgs]{}))
	require.Len(t, r.seen, 5, "4 backfill passes + 1 drift pass")
}

// TestEnrichSweepWorker_Phase1CeilingIsHigherNotAbsent pins the invariant BETWEEN the
// two ways this has now been got wrong.
//
// Phase 1 is the never-enriched backfill: a finding at score 0 with enriched_at unset is
// invisible in triage, because a score-sorted worklist hides score 0.
//
//   - Gating it on enrichQueueMax made the pass that CREATES that depth (the
//     full-corpus reenrich) the thing that stopped the repair: never-enriched
//     findings stay at enriched_at=0 behind a queue held above the ceiling.
//   - Removing the gate entirely was worse. enrichSweepMax bounds one TICK,
//     not the accumulated queue, so at a 15-minute cadence depth grew without limit:
//     the backlog swells without bound and the worker runs out of memory,
//     starving the graph queue too.
//
// So the property is not "gated" or "ungated" — it is "gated on a strictly higher
// ceiling". Asserted on the source because the distinction is which ceiling each call
// site passes, and expressing it behaviourally needs a live River client plus a primed
// queue of specific depth.
func TestEnrichSweepWorker_Phase1CeilingIsHigherNotAbsent(t *testing.T) {
	require.Greater(t, backfillQueueCeiling, enrichQueueMax,
		"Phase 1 must outrank the routine-drift ceiling, or reenrich depth stops the repair")
	require.Positive(t, backfillQueueCeiling,
		"Phase 1 must stay bounded: enrichSweepMax caps a tick, not the accumulated queue")
	require.Greater(t, backfillQueueCeiling, enrichSweepMax,
		"a ceiling below one tick's budget would make Phase 1 self-blocking")

	src, err := os.ReadFile("enrich.go")
	require.NoError(t, err)
	body := string(src)

	start := strings.Index(body, "func (w *EnrichSweepWorker) Work(")
	require.Positive(t, start, "Work not found — this guard is asserting against a moved target")
	end := strings.Index(body[start:], "\nfunc ")
	require.Positive(t, end)
	work := body[start : start+end]

	p1 := strings.Index(work, "backfillSeverities")
	p2 := strings.Index(work, "StaleFirst: true")
	require.Positive(t, p1)
	require.Positive(t, p2)
	require.Less(t, p1, p2, "Phase 1 must run before Phase 2")

	// BOTH phases must be gated — the regression was one of them not being.
	require.Equal(t, 2, strings.Count(work, "sweepHasCapacity(ctx,"),
		"both phases must consult a ceiling; exactly one gate means one phase is unbounded")
	backfillGate := strings.Index(work, "sweepHasCapacity(ctx, backfillQueueCeiling)")
	driftGate := strings.Index(work, "sweepHasCapacity(ctx, enrichQueueMax)")
	require.Positive(t, backfillGate, "Phase 1 must be gated on backfillQueueCeiling")
	require.Positive(t, driftGate, "Phase 2 must stay gated on enrichQueueMax")
	require.Less(t, backfillGate, p2, "Phase 1's gate must guard Phase 1, not Phase 2")
	require.Greater(t, driftGate, p1, "Phase 2's gate must guard Phase 2")

	// Priority asymmetry is unchanged: repair outranks routine drift.
	require.Contains(t, work, "river.PriorityDefault")
	require.Contains(t, work, "enrichSweepPriority")
}

// TestQueueCeilingsAreMeasurable is the guard that would have caught two gates
// shipping inert: it pins reachability, not just the constants' ordering.
//
// enrichQueueDepth measures via River's JobList, whose First(n) both CAPS the result
// at n and PANICS above 10,000. So a ceiling compared against that depth is only
// reachable if the probe can count that high. Two ceilings were not:
//
//   - backfillQueueCeiling once sat well above a probe hardcoded to
//     enrichQueueMax+1. `depth >= backfillQueueCeiling` was arithmetically
//     impossible, so enrich sweep Phase 1 was exactly as ungated as the
//     regression it claimed to fix.
//   - reenrichQueueCeiling was likewise set above that probe from the start, and
//     was the precedent the backfill ceiling was copied from.
//
// A guard that only asserts the gate is CALLED with the right constant and that
// the constants are correctly ORDERED passes while the gate does nothing.
// Reachability is the property that matters.
func TestQueueCeilingsAreMeasurable(t *testing.T) {
	ceilings := map[string]int{
		"enrichQueueMax":       enrichQueueMax,
		"backfillQueueCeiling": backfillQueueCeiling,
		"reenrichQueueCeiling": reenrichQueueCeiling,
	}
	for name, c := range ceilings {
		require.Positive(t, c, "%s must be positive", name)
		require.LessOrEqual(t, c, jobListMaxFirst,
			"%s (%d) exceeds jobListMaxFirst (%d): the depth probe saturates below it, so "+
				"`depth >= %s` can never be true and the gate is silently dead. River's "+
				"JobList.First also panics above that limit, so probing deeper is not the fix — "+
				"either lower the ceiling or count river_job directly.", name, c, jobListMaxFirst, name)
	}

	require.Greater(t, backfillQueueCeiling, enrichQueueMax,
		"repair must outrank routine drift, or reenrich depth re-darkens the backfill")
	require.Greater(t, backfillQueueCeiling, reenrichQueueCeiling,
		"the reenrich pass must yield to the backfill, not share its waterline: equal ceilings "+
			"(or, worse, reenrichQueueCeiling above backfillQueueCeiling, as previously shipped) "+
			"mean a reenrich pass holding depth at or above the backfill's line closes the repair "+
			"gate too, which is the original starvation bug rebuilt: "+
			"graph_findings_unenriched climbs behind exactly this inversion")
}

// The probe must clamp to River's panic limit. JobListParams.limit is unexported, so
// the panic itself is the observable: River's First(n) panics above 10,000, so a probe
// derived naively as ceiling+1 would crash the worker for any ceiling at or above that.
// Not hypothetical — the fix for the inert gate is precisely to derive the probe from
// the ceiling, which introduces this hazard.
func TestEnrichQueueDepthClampsToRiversPanicLimit(t *testing.T) {
	for _, ceiling := range []int{1, enrichQueueMax, backfillQueueCeiling, reenrichQueueCeiling, jobListMaxFirst, 50_000} {
		require.NotPanics(t, func() {
			_, err := enrichQueueDepth(context.Background(), fakeJobLister{jobs: 3}, ceiling)
			require.NoError(t, err)
		}, "ceiling %d made the probe exceed River's First() limit", ceiling)
	}
}

// recordingJobLister captures the JobListParams so a test can assert the probe DEPTH,
// not just that the call happened.
type recordingJobLister struct {
	params *river.JobListParams
	jobs   int
}

func (r *recordingJobLister) JobList(_ context.Context, p *river.JobListParams) (*river.JobListResult, error) {
	r.params = p
	return &river.JobListResult{Jobs: make([]*rivertype.JobRow, r.jobs)}, nil
}

// probeLimit reads JobListParams' unexported limit — the value First() sets.
//
// Reflection is warranted here: the limit is the entire mechanism by which two gates
// shipped inert, and there is no exported accessor. The IsValid check makes a River
// rename fail loudly rather than letting this guard silently stop guarding.
func probeLimit(t *testing.T, p *river.JobListParams) int {
	t.Helper()
	require.NotNil(t, p, "JobList was never called — the depth probe did not run")
	f := reflect.ValueOf(p).Elem().FieldByName("limit")
	require.True(t, f.IsValid(),
		"river.JobListParams no longer has a 'limit' field — update probeLimit or this guard is inert")
	return int(reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Int())
}

// TestEnrichQueueDepthProbeScalesWithCeiling closes the last hole in the inert-gate
// story, and it is the test whose absence let the bug ship twice.
//
// TestQueueCeilingsAreMeasurable proves the CONSTANTS are in range. That is not
// sufficient: the probe was once HARDCODED to enrichQueueMax+1 while callers compared
// its result against a higher ceiling, so the gate was dead even though every constant
// looked fine.
// A probe that does not scale with its ceiling saturates below it, and the only symptom
// is a log line that never appears.
func TestEnrichQueueDepthProbeScalesWithCeiling(t *testing.T) {
	for _, ceiling := range []int{1, 500, enrichQueueMax, backfillQueueCeiling, reenrichQueueCeiling} {
		rec := &recordingJobLister{jobs: 3}
		_, err := enrichQueueDepth(context.Background(), rec, ceiling)
		require.NoError(t, err)

		got := probeLimit(t, rec.params)
		require.Equal(t, min(ceiling+1, jobListMaxFirst), got,
			"ceiling %d needs a probe of %d to be measurable, got %d — `depth >= %d` is "+
				"unreachable and the gate is silently dead", ceiling, min(ceiling+1, jobListMaxFirst), got, ceiling)
		require.Greater(t, got, ceiling,
			"the probe must be able to COUNT PAST the ceiling, or the comparison can never fire")
	}
}

// TestEnrichSweepInsertOptsCapsRetries pins MaxAttempts against River's library
// default of 25, which this InsertOpts silently inherited by setting only Queue —
// the identical omission correlate already paid for (see
// TestCorrelateInsertOptsCapsRetries).
//
// A sweep tick keeps its pagination cursor in a stack local, so a retry restarts
// phase 1 from the beginning against the same data: when the failure is a
// property of the query rather than the moment, every attempt reproduces it.
// With the default, jobs pile up at state=retryable near the max attempt count on
// a recurring ClickHouse error, with attempt^4 backoff scheduling them a day and a
// half out. Those retryable rows then suppress the periodic's fresh inserts
// (River dedupes by kind against non-finalized states) and inflate
// enrichQueueDepth, which gates the sweep and the reenrich chain — so the wedge
// throttles the very work it was supposed to do.
func TestEnrichSweepInsertOptsCapsRetries(t *testing.T) {
	opts := EnrichSweepArgs{}.InsertOpts()
	require.Equal(t, 2, opts.MaxAttempts,
		"the 15-minute periodic tick IS the retry, and it re-derives its work set from "+
			"ClickHouse; a backed-off attempt at the same tick is strictly worse")
	require.Equal(t, queueEnrich, opts.Queue)
	require.Equal(t, uniqueStates, opts.UniqueOpts.ByState, "a sweep is a singleton while queued/running")
}

// extractRequestedStates reads JobListParams' unexported states field — the
// filter States() sets. Reflection is warranted for the same reason
// probeLimit uses it: there is no exported accessor, and this is exactly the
// field whose omission (Retryable/Pending) let respond's backpressure probe
// undercount its own queue.
func extractRequestedStates(p *river.JobListParams) []rivertype.JobState {
	f := reflect.ValueOf(p).Elem().FieldByName("states")
	if !f.IsValid() {
		return nil
	}
	sf := reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
	states := make([]rivertype.JobState, sf.Len())
	for i := range states {
		states[i] = sf.Index(i).Interface().(rivertype.JobState)
	}
	return states
}

// stateFilteringJobLister replicates River's server-side state filtering for a
// fixed set of fake jobs, so a test can prove which STATE SET a probe asked
// for actually changes the count — a plain job-count fake (fakeJobLister)
// can't distinguish "asked for all states" from "asked for three states".
type stateFilteringJobLister struct {
	jobStates []rivertype.JobState
}

func (s stateFilteringJobLister) JobList(_ context.Context, p *river.JobListParams) (*river.JobListResult, error) {
	requested := make(map[rivertype.JobState]bool, len(extractRequestedStates(p)))
	for _, st := range extractRequestedStates(p) {
		requested[st] = true
	}
	var matched []*rivertype.JobRow
	for _, st := range s.jobStates {
		if requested[st] {
			matched = append(matched, &rivertype.JobRow{})
		}
	}
	return &river.JobListResult{Jobs: matched}, nil
}

// TestRespondQueueDepth_CountsRetryableAndPending pins the fix: respond's
// depth probe now uses the same uniqueStates set as enrichQueueDepth and
// correlateQueueDepth, so retryable/pending decide jobs are no longer
// invisible to the respondQueueMax backpressure guard.
func TestRespondQueueDepth_CountsRetryableAndPending(t *testing.T) {
	lister := stateFilteringJobLister{
		jobStates: []rivertype.JobState{rivertype.JobStateRetryable, rivertype.JobStatePending},
	}

	depth, err := respondQueueDepth(context.Background(), lister)
	require.NoError(t, err)
	require.Equal(t, 2, depth,
		"respondQueueDepth must count retryable and pending decide jobs, not just "+
			"available/running/scheduled")

	// Sanity check: the OLD probe (Available, Running, Scheduled only) would
	// have missed both jobs above entirely — this is the bug being fixed.
	oldStates := map[rivertype.JobState]bool{
		rivertype.JobStateAvailable: true,
		rivertype.JobStateRunning:   true,
		rivertype.JobStateScheduled: true,
	}
	var oldDepth int
	for _, st := range lister.jobStates {
		if oldStates[st] {
			oldDepth++
		}
	}
	require.Equal(t, 0, oldDepth,
		"sanity: the pre-fix state set would have undercounted this backlog as empty")

	_, err = respondQueueDepth(context.Background(), fakeJobLister{err: errors.New("pg down")})
	require.ErrorContains(t, err, "respondQueueDepth")
}

// TestRespondQueueGuard_DropLogsWarn pins the fix for the second half of the
// bug: an over-cap (or failed-probe) decide drop now logs a Warn carrying the
// queue depth, matching enqueuePartialCorrelate's analogous drop in
// correlate_coalescer.go — the old code dropped silently with no log at all.
func TestRespondQueueGuard_DropLogsWarn(t *testing.T) {
	f := finding.Finding{ID: "f-over-cap"}

	logs := captureLog(t, func() {
		dropped := respondQueueGuard(context.Background(), f, respondQueueMax, nil)
		require.True(t, dropped, "at-cap depth must drop the decide job")
	})
	require.Contains(t, logs, "respond queue at capacity")
	require.Contains(t, logs, "\"queue_depth\":500")
	require.Contains(t, logs, "f-over-cap")

	// Under capacity: no drop, no warn.
	logs = captureLog(t, func() {
		dropped := respondQueueGuard(context.Background(), f, 3, nil)
		require.False(t, dropped, "under-cap depth must not drop the decide job")
	})
	require.Empty(t, logs, "an under-capacity guard must not log anything")

	// A failed depth probe is fail-closed: dropped and logged, same as over-cap.
	logs = captureLog(t, func() {
		dropped := respondQueueGuard(context.Background(), f, 0, errors.New("pg down"))
		require.True(t, dropped, "a failed depth probe must fail closed")
	})
	require.Contains(t, logs, "respond queue at capacity")
	require.Contains(t, logs, "pg down")
}

// An enrichment with an unmeasured source (EPSS before its first catalog load)
// is cached so the gate re-admits it after unmeasuredRetryAfter, not after the
// full backstop — its fingerprint is unchanged, so nothing else would.
func TestEnrichWorker_UnmeasuredSource_RetriesBeforeBackstop(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "CVE-2021-44228", Score: 40}
	cache := newFakeEnrichCache()
	e := &fakeEnricher{score: enrich.Score{Value: 40, Band: enrich.BandMonitor, Unmeasured: []string{"epss"}}}
	w := gatedWorker(e, cache, f)
	w.maxAge = 24 * time.Hour

	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}}))
	require.Equal(t, 1, e.calls)

	w.now = func() time.Time { return gateNow.Add(10 * time.Minute) }
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}}))
	require.Equal(t, 1, e.calls, "within the retry window the gate still skips")

	w.now = func() time.Time { return gateNow.Add(unmeasuredRetryAfter + time.Minute) }
	e.score.Unmeasured = nil
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}}))
	require.Equal(t, 2, e.calls, "past the retry window the finding re-enriches")

	w.now = func() time.Time { return gateNow.Add(unmeasuredRetryAfter + 2*time.Hour) }
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: f.ID}}))
	require.Equal(t, 2, e.calls, "once measured, the normal backstop applies again")
}

// FindingsResolved mirrors enrichcache.Service.FindingsResolved.
func (c *fakeEnrichCache) FindingsResolved(ctx context.Context, ids []string) error {
	for _, id := range ids {
		delete(c.alerts, id)
	}
	return c.InvalidateFingerprints(ctx, ids)
}
