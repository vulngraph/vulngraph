package obs

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// QueueAgeStat is the age of the oldest job still sitting in the `available`
// state on one River queue, at scrape time.
//
// graph_river_queue_depth (metrics.go, QueueStat) answers "how many jobs are
// waiting", but a single wedged job on an otherwise-idle queue sits under
// even that queue's own depth threshold indefinitely. This answers the
// question depth cannot: how long has the oldest available job been waiting,
// regardless of how many others are behind it.
type QueueAgeStat struct {
	Queue string
	// OldestAvailableSeconds is how long the oldest `available` job on this
	// queue has been waiting to be picked up, in seconds. A queue with no
	// available jobs at scrape time is simply absent from the slice — there
	// is no natural "0" for a queue with nothing to report.
	OldestAvailableSeconds int64
}

var descQueueOldestAvailable = prometheus.NewDesc(namespace+"_river_queue_oldest_available_seconds",
	"Age, in seconds, of the oldest job still in the available state on a River queue (queue label). Complements graph_river_queue_depth: a single wedged job on an otherwise-idle queue never crosses a depth threshold but sits here indefinitely. Absent for a queue with nothing available.", []string{"queue"}, nil)

// describeQueueAge/collectQueueAge are called from liveCollector's
// Describe/Collect (metrics.go) — split out here for line count only, same
// reason as metrics_finding_age.go.
func (c *liveCollector) describeQueueAge(ch chan<- *prometheus.Desc) {
	ch <- descQueueOldestAvailable
}

func (c *liveCollector) collectQueueAge(ctx context.Context, ch chan<- prometheus.Metric) {
	if c.s.QueueOldestAvailable == nil {
		return
	}
	for _, q := range readSource(ctx, c, "queue_oldest_available", 0, c.s.QueueOldestAvailable) {
		ch <- prometheus.MustNewConstMetric(descQueueOldestAvailable, prometheus.GaugeValue, float64(q.OldestAvailableSeconds), q.Queue)
	}
}
