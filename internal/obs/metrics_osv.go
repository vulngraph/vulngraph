package obs

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// OSVScanStalenessStat is the current OSV per-package-scan coverage at scrape
// time — the "how stale is our actual package coverage?" signal
// graph_feed_last_success_timestamp_seconds{feed="osv"} cannot answer: that
// gauge stamps fresh on every successful refresh_osv run even when it scanned
// zero new packages (everything already inside osvRescanAfter's 7-day skip
// window), so a job that "ran fine" can still be sitting on stale coverage.
//
// Split into its own file (rather than living in metrics.go alongside the
// other Sources-backed stats) purely to keep metrics.go under CLAUDE.md's
// 800-line ceiling — no functional distinction from any other source.
type OSVScanStalenessStat struct {
	TotalPackages   int64 // current distinct (ecosystem,name,version) inventory size
	NeverScanned    int64 // in inventory but absent from osv_scanned_packages
	OldestScannedAt int64 // unix seconds of the oldest scanned_at across all scanned packages; 0 if none scanned yet
}

var (
	descOSVScanTotal  = prometheus.NewDesc(namespace+"_osv_scan_total_packages", "Current distinct (ecosystem,name,version) package inventory size — the denominator for graph_osv_scan_never_scanned.", nil, nil)
	descOSVScanNever  = prometheus.NewDesc(namespace+"_osv_scan_never_scanned", "Packages in the current inventory that have NEVER been checked against OSV (absent from osv_scanned_packages) — the never-covered gap, distinct from staleness of coverage that already exists.", nil, nil)
	descOSVScanOldest = prometheus.NewDesc(namespace+"_osv_scan_oldest_scanned_timestamp_seconds", "Unix time of the OLDEST scanned_at across every currently-tracked package (0 if none scanned yet). Directly answers 'how stale is our worst-covered package?', which graph_feed_last_success_timestamp_seconds{feed=\"osv\"} cannot: that gauge stamps fresh on every successful refresh_osv run even when 0 new packages were scanned. A value more than osvRescanAfter (7d) + osvInterval (24h) in the past means the daily sweep is not keeping the estate's actual coverage current, independent of whether the job itself reports healthy.", nil, nil)
)

// describeOSVScanStaleness/collectOSVScanStaleness are called from
// liveCollector's Describe/Collect (metrics.go) — split out here for line
// count only, same as the type and descs above.
func (c *liveCollector) describeOSVScanStaleness(ch chan<- *prometheus.Desc) {
	ch <- descOSVScanTotal
	ch <- descOSVScanNever
	ch <- descOSVScanOldest
}

func (c *liveCollector) collectOSVScanStaleness(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.s.OSVScanStaleness == nil {
		return
	}
	for _, s := range readSource(ctx, c, "osv_scan_staleness", 0, c.s.OSVScanStaleness) {
		ch <- prometheus.MustNewConstMetric(descOSVScanTotal, prometheus.GaugeValue, float64(s.TotalPackages))
		ch <- prometheus.MustNewConstMetric(descOSVScanNever, prometheus.GaugeValue, float64(s.NeverScanned))
		ch <- prometheus.MustNewConstMetric(descOSVScanOldest, prometheus.GaugeValue, float64(s.OldestScannedAt))
	}
}
