package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/intel"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const domainMonitorInterval = 6 * time.Hour

// DomainMonitorArgs runs the domain squatting scan pipeline.
type DomainMonitorArgs struct{}

func (DomainMonitorArgs) Kind() string { return "domain_monitor" }

// MaxAttempts 2, not River's library default of 25: periodic.go already
// re-arms this job on every worker restart plus every domainMonitorInterval,
// so one retry absorbing a transient blip is enough — past that, grinding
// through River's ~attempt^4 backoff for up to 25 attempts while an upstream
// dependency (e.g. crt.sh) stays down is strictly worse than discarding loud
// and letting the next periodic fire pick it back up.
func (DomainMonitorArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueFeeds, 2)
}

// DomainMonitorWorker queries CT logs for monitored domains, triages hits with
// Claude, and stores phishing candidates in ClickHouse.
type DomainMonitorWorker struct {
	river.WorkerDefaults[DomainMonitorArgs]
	intel *intel.Service
}

func (w *DomainMonitorWorker) Timeout(_ *river.Job[DomainMonitorArgs]) time.Duration {
	return 10 * time.Minute
}

func (w *DomainMonitorWorker) Work(ctx context.Context, _ *river.Job[DomainMonitorArgs]) error {
	result, err := w.intel.RunScan(ctx)
	if err != nil {
		return fmt.Errorf("domain_monitor: %w", err)
	}
	log.FromContext(ctx).Info().
		Int("domains", result.Domains).
		Int("hits", result.Hits).
		Int("new", result.New).
		Int("ai_triaged", result.AITriaged).
		Int("heuristic_triaged", result.HeuristicTriaged).
		Msg("domain monitor scan complete")
	return nil
}
