package obs

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// ImageScanCoverageStat is the container-image vulnerability sweep's actual
// coverage of the estate at scrape time, read from the sweep's own cursor
// rather than inferred from whether its job succeeded.
//
// Job status alone is an unreliable signal here in both directions: a sweep
// can look dark by job-terminal-status while its cursor shows real recent
// coverage, or report ok while a truncated pass silently chains a
// continuation instead of erroring. CoveredRecent is the number that cannot
// move unless images are really being scanned.
//
// Split into its own file for the same reason as OSVScanStalenessStat: metrics.go's
// 800-line ceiling, no functional distinction.
type ImageScanCoverageStat struct {
	TrackedDigests  int64 // image digests the sweep has ever attempted
	NeverScanned    int64 // attempted but never once scanned cleanly
	CoveredRecent   int64 // scanned inside the rescan window (+ one interval of grace)
	OldestScannedAt int64 // unix seconds of the oldest scanned_at; 0 if nothing has ever been scanned
}

var (
	descImgScanTracked = prometheus.NewDesc(namespace+"_image_scan_tracked_digests", "Container-image digests the image-vuln sweep has ever attempted — the denominator for graph_image_scan_never_scanned and graph_image_scan_covered_recent.", nil, nil)
	descImgScanNever   = prometheus.NewDesc(namespace+"_image_scan_never_scanned", "Image digests the sweep has attempted but NEVER once scanned cleanly, so they carry no packages, no CVEs and no runs_package edge. Read as a ratio of graph_image_scan_tracked_digests, not as an absolute: a known, irreducible floor exists (pull-denied registries, images with no wired keychain). A RISING ratio is the signal — new registries or expired credentials silently removing images from coverage.", nil, nil)
	descImgScanRecent  = prometheus.NewDesc(namespace+"_image_scan_covered_recent", "Image digests scanned inside the sweep's rescan window plus one interval of grace (imageRescanAfter 20h + imageVulnInterval 24h). THIS is the sweep's liveness signal and it can only move if images are really scanned: zero means no image has been inventoried in nearly two days, so every runs_package edge has left the 48h edge freshness window and image CVEs have silently stopped being able to reach must_fix. Job status cannot substitute — a truncated-but-productive sweep reports ok by design (a truncated pass chains a continuation instead of erroring), so an ok job with this at 0 is precisely the failure to catch.", nil, nil)
	descImgScanOldest  = prometheus.NewDesc(namespace+"_image_scan_oldest_scanned_timestamp_seconds", "Unix time of the OLDEST clean scan across every tracked digest (0 if none scanned yet) — how stale is our worst-covered image. A value further back than imageRescanAfter (20h) + a couple of intervals means the continuation chain is not cycling the estate within its own rescan window, which drifts runs_package toward the 48h edge-freshness cliff whatever the job reports.", nil, nil)
)

// describeImageScanCoverage/collectImageScanCoverage are called from
// liveCollector's Describe/Collect (metrics.go).
func (c *liveCollector) describeImageScanCoverage(ch chan<- *prometheus.Desc) {
	ch <- descImgScanTracked
	ch <- descImgScanNever
	ch <- descImgScanRecent
	ch <- descImgScanOldest
}

func (c *liveCollector) collectImageScanCoverage(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.s.ImageScanCoverage == nil {
		return
	}
	for _, s := range readSource(ctx, c, "image_scan_coverage", 0, c.s.ImageScanCoverage) {
		ch <- prometheus.MustNewConstMetric(descImgScanTracked, prometheus.GaugeValue, float64(s.TrackedDigests))
		ch <- prometheus.MustNewConstMetric(descImgScanNever, prometheus.GaugeValue, float64(s.NeverScanned))
		ch <- prometheus.MustNewConstMetric(descImgScanRecent, prometheus.GaugeValue, float64(s.CoveredRecent))
		ch <- prometheus.MustNewConstMetric(descImgScanOldest, prometheus.GaugeValue, float64(s.OldestScannedAt))
	}
}
