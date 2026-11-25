package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/notify"
)

// alertRecorder records every alert; failing makes no channel deliver, err
// makes the channel list unreadable.
type alertRecorder struct {
	sent    []notify.Notification
	failing bool
	err     error
}

func (d *alertRecorder) Deliver(_ context.Context, n notify.Notification) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	d.sent = append(d.sent, n)
	if d.failing {
		return 0, nil
	}
	return 1, nil
}

func work(t *testing.T, w *EnrichWorker, id string) {
	t.Helper()
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichArgs]{Args: EnrichArgs{FindingID: id}}))
}

// The P0: every 30-minute correlate sweep invalidated the enrich cache of every
// finding on an exposed asset and re-enqueued it, and every cache miss re-sent
// "New critical finding". N sweeps over an unchanged page-band finding must
// produce exactly one alert.
func TestEnrichWorker_NSweeps_OneAlert(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "CVE-1", Severity: finding.SeverityCritical, KnownExploited: true, ResourceID: "i-web", Score: 90}
	cache := newFakeEnrichCache()
	alerts := &alertRecorder{}
	w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 90, Band: enrich.BandPage, MustFixClass: enrich.MustFixElevated}}, cache, f)
	w.notify = alerts

	for range 10 {
		require.NoError(t, cache.InvalidateFingerprints(context.Background(), []string{f.ID})) // what invalidateExposedFindings does
		work(t, w, f.ID)
	}
	require.Len(t, alerts.sent, 1, "ten sweeps over an unchanged finding are one alert")
	assert.Contains(t, alerts.sent[0].Title, "New ")
}

func TestEnrichWorker_AlertsOnUrgencyTransitionsOnly(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", Severity: finding.SeverityHigh, ResourceID: "r"}
	cache := newFakeEnrichCache()
	alerts := &alertRecorder{}
	e := &fakeEnricher{}
	w := &EnrichWorker{enrich: e, findings: newFakeFetcher(f), cache: cache, notify: alerts, now: func() time.Time { return gateNow }}

	steps := []struct {
		name      string
		score     enrich.Score
		wantTotal int
	}{
		{"raw high severity in the high band: not alertable", enrich.Score{Value: 75, Band: enrich.BandHigh, MustFixClass: enrich.MustFixElevated}, 0},
		{"entering must_fix alerts whatever the band", enrich.Score{Value: 75, Band: enrich.BandHigh, MustFixClass: enrich.MustFix}, 1},
		{"the same state again is silent", enrich.Score{Value: 76, Band: enrich.BandHigh, MustFixClass: enrich.MustFix}, 1},
		{"rising into page escalates", enrich.Score{Value: 90, Band: enrich.BandPage, MustFixClass: enrich.MustFix}, 2},
		{"falling back is silent", enrich.Score{Value: 70, Band: enrich.BandHigh, MustFixClass: enrich.MustFixElevated}, 2},
		{"re-entering an urgency already alerted is flapping, not news", enrich.Score{Value: 92, Band: enrich.BandPage, MustFixClass: enrich.MustFix}, 2},
	}
	for _, st := range steps {
		e.score = st.score
		work(t, w, f.ID)
		require.Lenf(t, alerts.sent, st.wantTotal, st.name)
	}
	assert.Contains(t, alerts.sent[1].Title, "Escalated ")
}

func TestAlertTransition(t *testing.T) {
	none := enrichcache.AlertState{}
	pagedElevated := enrichcache.AlertState{ScoreBand: string(enrich.BandPage), MustFixClass: enrich.MustFixElevated}
	tests := []struct {
		name  string
		prev  enrichcache.AlertState
		band  enrich.Band
		class string
		want  bool
	}{
		{"never alerted, page", none, enrich.BandPage, "", true},
		{"never alerted, must_fix below page", none, enrich.BandPipeline, enrich.MustFix, true},
		{"never alerted, high band elevated", none, enrich.BandHigh, enrich.MustFixElevated, false},
		{"paged before, page again", pagedElevated, enrich.BandPage, enrich.MustFixElevated, false},
		{"paged before, now must_fix", pagedElevated, enrich.BandPage, enrich.MustFix, true},
		{"paged before, must_fix at a lower band still enters must_fix", pagedElevated, enrich.BandHigh, enrich.MustFix, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, alertTransition(tt.prev, enrich.Score{Band: tt.band, MustFixClass: tt.class}))
		})
	}
}

// A resolved finding is never enriched or alerted on, however it was enqueued.
func TestEnrichWorker_ResolvedFindingSkipped(t *testing.T) {
	f := finding.Finding{ID: "f1", Severity: finding.SeverityCritical, KnownExploited: true, ResolvedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}
	e := &fakeEnricher{score: enrich.Score{Value: 95, Band: enrich.BandPage}}
	alerts := &alertRecorder{}
	w := &EnrichWorker{enrich: e, findings: newFakeFetcher(f), notify: alerts}
	work(t, w, f.ID)
	assert.Zero(t, e.calls)
	assert.Empty(t, alerts.sent)
}

type fakeCarrier struct {
	carrier string
	err     error
}

func (c fakeCarrier) AlertCarrier(context.Context, finding.Finding, enrich.Band) (string, error) {
	return c.carrier, c.err
}

// A package finding its root cause carries stays silent; a failed root-cause
// lookup alerts for the finding itself.
func TestEnrichWorker_RootCauseCarriedFindingDoesNotAlert(t *testing.T) {
	f := finding.Finding{ID: "pkg", Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:deb/debian/openssl@3", KnownExploited: true}
	page := enrich.Score{Value: 90, Band: enrich.BandPage}
	for name, tc := range map[string]struct {
		carrier fakeCarrier
		want    int
	}{
		"carried":       {fakeCarrier{carrier: "base-image root cause rc-1"}, 0},
		"not carried":   {fakeCarrier{}, 1},
		"lookup failed": {fakeCarrier{err: errors.New("ch down")}, 1},
	} {
		t.Run(name, func(t *testing.T) {
			alerts := &alertRecorder{}
			w := &EnrichWorker{enrich: &fakeEnricher{score: page}, findings: newFakeFetcher(f), notify: alerts, carriers: tc.carrier}
			work(t, w, f.ID)
			assert.Len(t, alerts.sent, tc.want)
		})
	}
}

// An unreadable last-alert state alerts (a duplicate is recoverable, a
// swallowed page is not).
func TestEnrichWorker_AlertStateUnreadable_Alerts(t *testing.T) {
	f := finding.Finding{ID: "f1", Severity: finding.SeverityCritical}
	cache := newFakeEnrichCache()
	cache.alertErr = errors.New("pg down")
	alerts := &alertRecorder{}
	w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 90, Band: enrich.BandPage}}, cache, f)
	w.notify = alerts
	work(t, w, f.ID)
	assert.Len(t, alerts.sent, 1)
}

// A changed vm_vuln fleet finding clears its package finding's fingerprint, so
// the regroup's re-enqueue of the package is not skipped by the change-gate.
func TestEnrichWorker_FleetChangeInvalidatesPackage(t *testing.T) {
	fleet := finding.Finding{ID: "fleet-1", Source: "vm_vuln", CheckID: "CVE-1", ResourceID: "i-a",
		Metadata: map[string]string{"package_finding_id": "pkg-1"}}
	cache := newFakeEnrichCache()
	cache.entries["pkg-1"] = enrichcache.Entry{FindingID: "pkg-1", InputFP: "fp", EnrichedAt: gateNow}
	w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 40, Band: enrich.BandMonitor}}, cache, fleet)

	work(t, w, fleet.ID)
	assert.Equal(t, []string{"pkg-1"}, cache.invalidated)
	assert.Empty(t, cache.entries["pkg-1"].InputFP)

	// Unchanged on its backstop re-enrich: no invalidation.
	cache.invalidated = nil
	e := cache.entries[fleet.ID]
	e.EnrichedAt = gateNow.Add(-2 * time.Hour)
	cache.entries[fleet.ID] = e
	work(t, w, fleet.ID)
	assert.Empty(t, cache.invalidated)
}

// flakyGraph answers graph reads, or fails them all.
type flakyGraph struct {
	fail    bool
	exposed bool
	hops    int
	found   bool
}

func (g *flakyGraph) IsExposedEdge(context.Context, string) (bool, error) {
	if g.fail {
		return false, errors.New("ch down")
	}
	return g.exposed, nil
}

func (g *flakyGraph) PrivescBucket(context.Context, string) (string, error) {
	if g.fail {
		return "", errors.New("ch down")
	}
	return "1", nil
}

func (g *flakyGraph) InternetHops(context.Context, string) (int, bool, error) {
	if g.fail {
		return 0, false, errors.New("ladybug down")
	}
	return g.hops, g.found, nil
}

// A failed graph read (or Ladybug missing the node mid-rebuild) carries the last
// measured context forward: the fingerprint does not move, so the finding is
// not re-enriched — once on the failure and again on recovery.
func TestEnrichWorker_GraphReadErrorIsNotAStateChange(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "c1", ResourceID: "i-web", Score: 70}
	cache := newFakeEnrichCache()
	e := &fakeEnricher{score: enrich.Score{Value: 70, Band: enrich.BandHigh}}
	g := &flakyGraph{exposed: true, hops: 0, found: true}
	w := gatedWorker(e, cache, f)
	w.graph = g

	work(t, w, f.ID)
	require.Equal(t, 1, e.calls)
	require.Equal(t, enrichcache.GraphContext{Exposed: "true", PrivescBucket: "1", ReachBucket: "direct"}, cache.entries[f.ID].Graph)

	g.fail = true
	work(t, w, f.ID)
	assert.Equal(t, 1, e.calls, "every graph read failing must not look like a topology change")

	g.fail, g.found = false, false // Ladybug mid-rebuild: node not loaded yet
	work(t, w, f.ID)
	assert.Equal(t, 1, e.calls, "a node Ladybug cannot see yet is not a reachability change")

	g.found, g.exposed = true, false // a real change
	work(t, w, f.ID)
	assert.Equal(t, 2, e.calls, "a measured change still re-enriches")
}

// A page no channel delivered (Slack down, the channel list unreadable, no
// channel accepting it) is not recorded: the next enrich alerts again, and the
// fingerprint is cleared so that next enrich is not skipped by the change-gate.
func TestEnrichWorker_UndeliveredAlertIsRetried(t *testing.T) {
	for name, rec := range map[string]*alertRecorder{
		"every send failed / no recipient": {failing: true},
		"channel list unreadable":          {err: errors.New("pg down")},
	} {
		t.Run(name, func(t *testing.T) {
			f := finding.Finding{ID: "f1", CheckID: "CVE-1", Severity: finding.SeverityCritical, KnownExploited: true, Score: 90}
			cache := newFakeEnrichCache()
			w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 90, Band: enrich.BandPage}}, cache, f)
			w.notify = rec

			work(t, w, f.ID)
			_, recorded := cache.alerts[f.ID]
			require.False(t, recorded, "an undelivered alert must not be recorded as sent")
			require.Empty(t, cache.entries[f.ID].InputFP, "the retry must not wait out the change-gate")

			rec.failing, rec.err = false, nil
			work(t, w, f.ID)
			_, recorded = cache.alerts[f.ID]
			require.True(t, recorded)
			sentBefore := len(rec.sent)
			work(t, w, f.ID)
			require.Len(t, rec.sent, sentBefore, "once delivered, it is deduped")
		})
	}
}

// The regression the ledger used to swallow: a finding pages, is resolved, is
// reopened by a later observation (same deterministic id) and re-enriched — it
// must page again.
func TestEnrichWorker_RegressionAfterResolveReAlerts(t *testing.T) {
	open := finding.Finding{ID: "f1", CheckID: "CVE-1", Severity: finding.SeverityCritical, KnownExploited: true, Score: 90}
	cache := newFakeEnrichCache()
	alerts := &alertRecorder{}
	w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 90, Band: enrich.BandPage}}, cache, open)
	w.notify = alerts

	work(t, w, open.ID)
	require.Len(t, alerts.sent, 1)

	resolved := open
	resolved.ResolvedAt = gateNow
	w.findings = newFakeFetcher(resolved)
	require.NoError(t, cache.FindingsResolved(context.Background(), []string{open.ID})) // what finding.Service.Resolve's observer does
	work(t, w, open.ID)
	require.Len(t, alerts.sent, 1, "no alert while resolved")

	w.findings = newFakeFetcher(open) // RecordObserved reopened it
	work(t, w, open.ID)
	require.Len(t, alerts.sent, 2, "a regression is a new episode and pages again")
}

// Every act-now class that a page floor never lifts still alerts from the high
// band; a high-band finding without one does not.
func TestAlertable_ReachIndependentClasses(t *testing.T) {
	high := func(fs ...enrich.Factor) enrich.Score {
		return enrich.Score{Value: 70, Band: enrich.BandHigh, MustFixClass: enrich.MustFixElevated, Factors: fs}
	}
	tests := []struct {
		name  string
		score enrich.Score
		want  bool
	}{
		{"GuardDuty C&C/Backdoor/Exfiltration/PrivilegeEscalation/Persistence/Impact (threat floor high)", high(enrich.Factor{Source: "threat_floor", Floor: enrich.ThresholdHigh}), true},
		{"GCP SCC high/critical threat (threat floor high)", high(enrich.Factor{Source: "threat_floor", Floor: enrich.ThresholdHigh}), true},
		{"live secret, public or private repo (signal floor high)", high(enrich.Factor{Source: "signal_floor", Floor: enrich.ThresholdHigh}), true},
		{"dangling DNS takeover (dns_takeover floor high)", high(enrich.Factor{Source: "dns_takeover", Floor: enrich.ThresholdHigh}), true},
		{"page band", enrich.Score{Band: enrich.BandPage}, true},
		{"must_fix below page", enrich.Score{Band: enrich.BandPipeline, MustFixClass: enrich.MustFix}, true},
		{"high band on points alone", high(), false},
		{"test-mode secret (signal floor pipeline)", enrich.Score{Band: enrich.BandPipeline, Factors: []enrich.Factor{{Source: "signal_floor", Floor: enrich.ThresholdPipeline}}}, false},
		{"threat floor high but scored down to pipeline", enrich.Score{Band: enrich.BandPipeline, Factors: []enrich.Factor{{Source: "threat_floor", Floor: enrich.ThresholdHigh}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { assert.Equal(t, tt.want, alertable(tt.score)) })
	}
}

// A base gaining a KEV member re-scores: its membership counts are in its
// fingerprint. Ordinary findings hash exactly as before.
func TestFingerprintInput_RootCauseCounts(t *testing.T) {
	rc := finding.Finding{ID: "rc", Source: "base_image", CheckID: "base-image-root-cause", Severity: finding.SeverityMedium,
		Metadata: map[string]string{"base_layer_kev": "0", "base_layer_cves": "40", "running_images": "3"}}
	kev := rc
	kev.Metadata = map[string]string{"base_layer_kev": "1", "base_layer_cves": "40", "running_images": "3"}
	assert.NotEqual(t, enrichcache.Fingerprint(fingerprintInput(rc)), enrichcache.Fingerprint(fingerprintInput(kev)))

	plain := finding.Finding{ID: "f", CheckID: "c", Metadata: map[string]string{"base_layer_kev": "1"}}
	assert.Empty(t, fingerprintInput(plain).RootCause)
}

// GitHub revoking a leaked key (validity active → inactive) moves its must-fix
// class, so it must move the fingerprint too, or the cached class is served.
// A finding with no validity verdict hashes exactly as before.
func TestFingerprintInput_SecretValidity(t *testing.T) {
	leak := func(v string) finding.Finding {
		return finding.Finding{ID: "s", Source: "ghas_secrets", CheckID: "stripe_secret_key",
			Metadata: map[string]string{finding.SecretValidityKey: v}}
	}
	assert.NotEqual(t,
		enrichcache.Fingerprint(fingerprintInput(leak(finding.SecretValidityActive))),
		enrichcache.Fingerprint(fingerprintInput(leak(finding.SecretValidityInactive))))
	none := finding.Finding{ID: "s", Source: "ghas_secrets", CheckID: "stripe_secret_key"}
	assert.Equal(t,
		enrichcache.Fingerprint(enrichcache.FingerprintInput{FindingID: "s", CheckID: "stripe_secret_key"}),
		enrichcache.Fingerprint(fingerprintInput(none)))
}

type fakePruner struct{ olderThan time.Time }

func (p *fakePruner) PruneAlertStates(_ context.Context, t time.Time) (int64, error) {
	p.olderThan = t
	return 1, nil
}

func TestEnrichSweep_PrunesAlertState(t *testing.T) {
	p := &fakePruner{}
	w := &EnrichSweepWorker{findings: fakeLister{}, alerts: p}
	require.NoError(t, w.Work(context.Background(), &river.Job[EnrichSweepArgs]{}))
	require.WithinDuration(t, time.Now().Add(-alertStateRetention), p.olderThan, time.Minute)
}

// seqFetcher returns its findings in order, repeating the last.
type seqFetcher struct {
	seq []finding.Finding
	n   int
}

func (s *seqFetcher) Get(context.Context, string) (finding.Finding, error) {
	f := s.seq[min(s.n, len(s.seq)-1)]
	s.n++
	return f, nil
}

// A resolve landing while the enrich runs: no "New" alert, no cache entry or
// alert state written back over what the resolve observer cleared.
func TestEnrichWorker_ResolvedDuringEnrich_NothingRecorded(t *testing.T) {
	open := finding.Finding{ID: "f1", CheckID: "CVE-1", Severity: finding.SeverityCritical, Score: 90}
	resolved := open
	resolved.ResolvedAt = gateNow
	cache := newFakeEnrichCache()
	alerts := &alertRecorder{}
	w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 90, Band: enrich.BandPage}}, cache)
	w.findings = &seqFetcher{seq: []finding.Finding{open, resolved}}
	w.notify = alerts
	work(t, w, open.ID)
	assert.Empty(t, alerts.sent)
	assert.Zero(t, cache.puts)
	assert.Empty(t, cache.alerts)
}

// noChannelRecorder is a deliverer with no channel configured at all.
type noChannelRecorder struct{ alertRecorder }

func (noChannelRecorder) HasEnabledChannels(context.Context) (bool, error) { return false, nil }

// With no channel configured, an undelivered alert is not retried by clearing
// the fingerprint — that would disable the change-gate on every visit.
func TestEnrichWorker_NoChannelsConfigured_KeepsTheChangeGate(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "CVE-1", Severity: finding.SeverityCritical, Score: 90}
	cache := newFakeEnrichCache()
	rec := &noChannelRecorder{alertRecorder{failing: true}}
	w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 90, Band: enrich.BandPage}}, cache, f)
	w.notify = rec
	work(t, w, f.ID)
	assert.NotEmpty(t, cache.entries[f.ID].InputFP)
	assert.Empty(t, cache.alerts)
}

// failingChannelCheck is a deliverer whose channel check itself fails.
type failingChannelCheck struct{ alertRecorder }

func (failingChannelCheck) HasEnabledChannels(context.Context) (bool, error) {
	return false, errors.New("pg down")
}

// An unreadable channel list is not "no channels": the undelivered alert is
// retried (fingerprint cleared), never given up on.
func TestEnrichWorker_ChannelCheckError_StillRetries(t *testing.T) {
	f := finding.Finding{ID: "f1", CheckID: "CVE-1", Severity: finding.SeverityCritical, Score: 90}
	cache := newFakeEnrichCache()
	w := gatedWorker(&fakeEnricher{score: enrich.Score{Value: 90, Band: enrich.BandPage}}, cache, f)
	w.notify = &failingChannelCheck{alertRecorder{failing: true}}
	work(t, w, f.ID)
	assert.Empty(t, cache.entries[f.ID].InputFP)
	assert.Empty(t, cache.alerts)
}
