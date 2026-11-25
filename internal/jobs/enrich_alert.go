package jobs

import (
	"context"
	"errors"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AlertCarrier names the open root-cause finding that carries a finding's
// alerting at the given band, or "" when the finding must alert for itself
// (ADR 088 amendment: root-cause findings are the alerting unit).
// enrich.SupplyChainExposure implements it.
type AlertCarrier interface {
	AlertCarrier(ctx context.Context, f finding.Finding, band enrich.Band) (string, error)
}

// bandRank orders bands for the "rose a band" transition.
var bandRank = map[string]int{
	string(enrich.BandMonitor):  1,
	string(enrich.BandPipeline): 2,
	string(enrich.BandHigh):     3,
	string(enrich.BandPage):     4,
}

// alertable is the alerting bar: the page band; the must-fix class (the
// evidence-backed "fix this now" verdict, whatever the score); or the high band
// lifted there by a reach-independent act-now floor — an active-threat
// detection, a live leaked credential, a DNS takeover — which never page-floor
// and so would otherwise never alert. Raw scanner severity is deliberately not
// part of it: "high" from a scanner is an input to the score, not a page.
func alertable(score enrich.Score) bool {
	if score.Band == enrich.BandPage || score.MustFixClass == enrich.MustFix {
		return true
	}
	return score.Band == enrich.BandHigh && enrich.UrgentRegardlessOfReach(score.Factors)
}

// alertTransition reports whether a finding now at score must alert, given
// the high-water mark of its current alert episode (zero = never alerted, or
// resolved since): it is alertable AND it entered must_fix or rose above the
// band it already alerted at. A finding that falls back and re-enters the same
// urgency stays quiet — that is flapping, not news. Resolving a finding ends
// the episode (enrichcache.Service.FindingsResolved), so a regression alerts.
func alertTransition(prev enrichcache.AlertState, score enrich.Score) bool {
	if !alertable(score) {
		return false
	}
	if score.MustFixClass == enrich.MustFix && prev.MustFixClass != enrich.MustFix {
		return true
	}
	return bandRank[string(score.Band)] > bandRank[prev.ScoreBand]
}

// maybeAlert delivers the finding's alert when its urgency transitioned, and
// records the new high-water mark ONLY once a channel delivered it. Package
// findings an open root cause carries (at their band) do not alert on their
// own.
//
// Nothing delivered — the channel list unreadable, every send failing, or no
// channel accepting it — records nothing and clears the finding's input
// fingerprint, so its next visit re-enriches and tries again rather than the
// ledger claiming a page nobody received. An unreadable alert state alerts
// anyway: a duplicate page on a Postgres hiccup is recoverable, a swallowed one
// is not.
func (w *EnrichWorker) maybeAlert(ctx context.Context, f finding.Finding, score enrich.Score) {
	logger := log.FromContext(ctx)
	if !alertable(score) {
		return
	}
	if w.carriers != nil {
		carrier, err := w.carriers.AlertCarrier(ctx, f, score.Band)
		if err != nil {
			logger.Warn().Err(err).Str("finding_id", f.ID).Msg("alert: root-cause lookup failed; alerting for the finding itself")
		}
		if carrier != "" {
			logger.Debug().Str("finding_id", f.ID).Str("carried_by", carrier).Msg("alert: carried by its root cause")
			return
		}
	}
	var prev enrichcache.AlertState
	if w.cache != nil {
		st, err := w.cache.AlertState(ctx, f.ID)
		switch {
		case err == nil:
			prev = st
		case !errors.Is(err, enrichcache.ErrNotFound):
			logger.Warn().Err(err).Str("finding_id", f.ID).Msg("alert: last-alert state unreadable; alerting")
		}
	}
	if !alertTransition(prev, score) {
		return
	}
	delivered, err := w.notify.Deliver(ctx, newFindingNotification(f, score, prev.ScoreBand != ""))
	if err != nil || delivered == 0 {
		if err == nil && !w.anyChannels(ctx) {
			// No channel configured at all: delivering nothing is the install's
			// choice, not a failure. Clearing the fingerprint here would disable
			// the change-gate for every alertable finding (a full re-enrich per
			// visit) to retry something that cannot succeed.
			return
		}
		logger.Warn().Err(err).Str("finding_id", f.ID).Int("delivered", delivered).
			Msg("alert: no channel delivered the alert; not recorded, retried on the finding's next enrich")
		if w.cache != nil {
			if err := w.cache.InvalidateFingerprints(ctx, []string{f.ID}); err != nil {
				logger.Error().Err(err).Str("finding_id", f.ID).Msg("alert: could not schedule the retry; it waits for the freshness backstop")
			}
		}
		return
	}
	if w.cache == nil {
		return
	}
	// The store keeps the high-water mark (the band never moves down, must_fix
	// stays), so writing the current state is enough.
	if err := w.cache.RecordAlert(ctx, enrichcache.AlertState{
		FindingID: f.ID, ScoreBand: string(score.Band), MustFixClass: score.MustFixClass, AlertedAt: w.clock(),
	}); err != nil {
		logger.Error().Err(err).Str("finding_id", f.ID).Msg("alert: recording the alert failed; the next transition check may re-alert")
	}
}

// channelChecker reports whether any alert channel is enabled.
// *notify.Service implements it.
type channelChecker interface {
	HasEnabledChannels(ctx context.Context) (bool, error)
}

// The production deliverer must keep both capabilities: anyChannels and
// noticeDeliverer narrow by type assertion, which would fail silently.
var (
	_ channelChecker  = (*notify.Service)(nil)
	_ NoticeDeliverer = (*notify.Service)(nil)
)

// anyChannels reports whether the deliverer has an enabled channel. Unknown
// (no checker, or the read failed) counts as yes, so an undelivered alert is
// retried rather than given up on.
func (w *EnrichWorker) anyChannels(ctx context.Context) bool {
	c, ok := w.notify.(channelChecker)
	if !ok {
		return true
	}
	has, err := c.HasEnabledChannels(ctx)
	return err != nil || has
}

// refreshFleetPackage re-enriches the package finding a changed vm_vuln fleet
// finding derives from. Whether the package is fleet-canonical (and so capped
// below page and silent) depends on its fleet findings, which its own input
// fingerprint cannot see: the fleet regroup re-enqueues it, but the change-gate
// then skipped it as unchanged. Clearing its fingerprint first makes the
// re-enrich land.
func (w *EnrichWorker) refreshFleetPackage(ctx context.Context, f finding.Finding) {
	pkgID := f.Metadata["package_finding_id"]
	if f.Source != "vm_vuln" || pkgID == "" {
		return
	}
	if w.cache != nil {
		if err := w.cache.InvalidateFingerprints(ctx, []string{pkgID}); err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("package_finding_id", pkgID).
				Msg("enrich: could not invalidate the fleet's package finding; it re-enriches at its backstop")
			return
		}
	}
	enqueueEnrich(ctx, []finding.Finding{{ID: pkgID}})
}

// alertStatePruner keeps a nil or non-pruning cache a nil interface.
func alertStatePruner(c EnrichCache) AlertStatePruner {
	p, ok := c.(AlertStatePruner)
	if !ok || c == nil {
		return nil
	}
	return p
}
