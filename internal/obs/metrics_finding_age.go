package obs

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// FindingAgeStat is the scrape-time state of the immutable first-observation
// timestamp on open findings (finding.AgeIntegrity). Split into its own file for
// the same reason as OSVScanStalenessStat: metrics.go's 800-line ceiling.
//
// This exists to make one specific failure loud. `detected_at` is re-stamped by
// every producer on every re-observation, so finding age — a must-fix scoring
// input — would otherwise read as "time since last seen" rather than true age.
// A separate first_detected_at pins the first observation; if that pin does not hold, nothing
// else changes visibly (scores stay plausible, no query errors, findings
// simply never get old). Preserved is 0 while the pin is broken and non-zero
// once it works, distinguishing "deployed and working" from "deployed and inert".
type FindingAgeStat struct {
	Preserved     int64 // open findings whose first observation predates the oldest detected_at any surviving row version holds
	Missing       int64 // open findings with no first observation recorded (expected 0)
	OldestSeconds int64 // age of the oldest open finding, seconds
}

var (
	descFindingAgePreserved = prometheus.NewDesc(namespace+"_finding_age_preserved",
		"Open findings whose first_detected_at is older than the OLDEST detected_at any surviving row version carries — i.e. whose true age survived a ReplacingMergeTree merge. Zero by construction if the RecordObserved first-observation pin does not hold (the column defaults to each row's own detected_at), so a sustained 0 across a merge cycle on a corpus that is being re-observed means the pin is inert.", nil, nil)
	descFindingAgeMissing = prometheus.NewDesc(namespace+"_finding_age_missing",
		"Open findings with no first_detected_at recorded. The column defaults to detected_at, so this should be 0; a non-zero value means some writer inserts finding rows without a first observation, which the min-over-nonzero read deliberately hides from scoring (unknown must never demote) and would otherwise show up only as findings that never age.", nil, nil)
	descFindingAgeOldest = prometheus.NewDesc(namespace+"_finding_age_oldest_seconds",
		"Age of the oldest open finding, from its first observation. It should climb monotonically while the first-observation pin holds; a value stuck near the sweep interval, or a drop back toward zero, means detected_at re-stamping is leaking into age.", nil, nil)
)

// describeFindingAge/collectFindingAge are called from liveCollector's
// Describe/Collect (metrics.go) — split out here for line count only.
func (c *liveCollector) describeFindingAge(ch chan<- *prometheus.Desc) {
	ch <- descFindingAgePreserved
	ch <- descFindingAgeMissing
	ch <- descFindingAgeOldest
}

func (c *liveCollector) collectFindingAge(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.s.FindingAge == nil {
		return
	}
	for _, s := range readSource(ctx, c, "finding_age", 0, c.s.FindingAge) {
		ch <- prometheus.MustNewConstMetric(descFindingAgePreserved, prometheus.GaugeValue, float64(s.Preserved))
		ch <- prometheus.MustNewConstMetric(descFindingAgeMissing, prometheus.GaugeValue, float64(s.Missing))
		ch <- prometheus.MustNewConstMetric(descFindingAgeOldest, prometheus.GaugeValue, float64(s.OldestSeconds))
	}
}
