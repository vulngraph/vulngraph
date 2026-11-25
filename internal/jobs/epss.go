package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/intel/epss"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// feedStaleAfter is how old an intel feed's own publish/score date may be before
// a successful refresh warns. The daily feeds (KEV, EPSS) should never be older
// than a day; 48h absorbs a weekend/publish hiccup before flagging the data as
// stale — a signal the job-success gauge cannot see.
const feedStaleAfter = 48 * time.Hour

// EPSSFetcher downloads the EPSS catalog. *epss.Fetcher implements it; tests fake it.
type EPSSFetcher interface {
	Fetch(ctx context.Context) (*epss.Catalog, error)
}

// EPSSCache receives the freshly-fetched catalog. *epss.Cache implements it.
type EPSSCache interface {
	Set(cat *epss.Catalog)
}

// RefreshEPSSArgs refreshes the in-memory EPSS catalog. Scores are read
// by the enrich EPSS source on the next enrichment pass — no finding is rewritten
// here, so this runs on queueFeeds purely as a periodic intel refresh, not
// respond's decide traffic.
type RefreshEPSSArgs struct{}

func (RefreshEPSSArgs) Kind() string { return "refresh_epss" }

// InsertOpts: singleton with 3 attempts (periodicSingletonOpts).
func (RefreshEPSSArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueFeeds, 3)
}

// EPSSWorker fetches the EPSS catalog and swaps it into the shared cache.
type EPSSWorker struct {
	river.WorkerDefaults[RefreshEPSSArgs]
	fetcher EPSSFetcher
	cache   EPSSCache
}

// Timeout overrides River's 1-minute default, which equals the fetcher's own
// 60s HTTP timeout: a download that just fits would then be cancelled while
// parsing the catalog.
func (EPSSWorker) Timeout(_ *river.Job[RefreshEPSSArgs]) time.Duration {
	return 3 * time.Minute
}

func (w *EPSSWorker) Work(ctx context.Context, _ *river.Job[RefreshEPSSArgs]) error {
	cat, err := w.fetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("Work: fetch epss: %w", err)
	}
	w.cache.Set(cat)
	ev := log.FromContext(ctx).Info().Int("epss_catalog", cat.Len())
	// Feed-side staleness: a successful fetch that returns old data (FIRST.org
	// stopped publishing, or we're pinned to a stale mirror) is invisible to the
	// job-success gauge — warn when the score_date itself is stale.
	if sd := cat.ScoreDate(); !sd.IsZero() {
		if age := time.Since(sd); age > feedStaleAfter {
			log.FromContext(ctx).Warn().Time("score_date", sd).Dur("age", age).
				Msg("epss catalog score_date is stale (>48h) — feed may have stopped updating")
		}
		ev = ev.Time("score_date", sd)
	}
	ev.Msg("epss catalog refreshed")
	return nil
}
