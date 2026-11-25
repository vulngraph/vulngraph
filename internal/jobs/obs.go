package jobs

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// obsMiddleware wraps every job execution in a span and records a run counter +
// duration histogram, labelled by queue and job kind. Installed globally on the
// River client (Config.Middleware) so all workers are instrumented in one place
// rather than per Work() method. A nil Metrics makes it a passthrough.
type obsMiddleware struct {
	river.MiddlewareDefaults
	m *obs.Metrics
}

func (mw *obsMiddleware) Work(ctx context.Context, job *rivertype.JobRow, doInner func(context.Context) error) error {
	ctx, end := obs.SpanJob(ctx, "job."+job.Kind)
	defer end()
	start := time.Now()
	err := doInner(ctx)
	status := "ok"
	if err != nil {
		status = "error"
	}
	mw.m.ObserveJob(job.Queue, job.Kind, status, time.Since(start).Seconds())
	// On a successful intel-feed refresh, stamp the feed's last-success gauge so
	// "is this feed still updating?" is a direct dashboard/alert signal. Derived
	// from the job kind here, so no per-feed worker needs to know about metrics.
	if err == nil {
		if feed := feedForJobKind(job.Kind); feed != "" {
			mw.m.ObserveFeedRefresh(feed, float64(time.Now().Unix()))
		}
	}
	return err
}

// feedForJobKind maps an intel-feed refresh job kind to its feed label, or "" if
// the job isn't a feed refresh.
func feedForJobKind(kind string) string {
	switch kind {
	case "refresh_kev":
		return "kev"
	case "refresh_osv":
		return "osv"
	case "refresh_osv_malfeed":
		return "osv_malfeed"
	case "refresh_epss":
		return "epss"
	case "refresh_scc":
		return "scc"
	case "domain_monitor":
		return "domain_monitor"
	}
	return ""
}

// jobErrorLogger is River's ErrorHandler: invoked whenever any job errors or
// panics, on every attempt, above all middleware. Without it, a job can fail,
// retry, and fail again indefinitely with no trace in the logs beyond the
// periodic queue-stats count — obsMiddleware.Work records the failure as a
// metric but never logs it, and never even runs on a panic, since a panic
// unwinds past its `err := doInner(ctx)` line before ObserveJob is reached.
// River's ErrorHandler is the one hook that sees both an ordinary error and a
// panic, so it lives here rather than in obsMiddleware's error branch. Always
// wired — there is no scenario where a job failure should be quieter than this.
type jobErrorLogger struct{}

func (jobErrorLogger) HandleError(ctx context.Context, job *rivertype.JobRow, err error) *river.ErrorHandlerResult {
	log.FromContext(ctx).Warn().Err(err).
		Str("kind", job.Kind).Str("queue", job.Queue).Int("attempt", job.Attempt).
		Msg("job errored")
	return nil // default retry schedule; this handler only adds visibility
}

func (jobErrorLogger) HandlePanic(ctx context.Context, job *rivertype.JobRow, panicVal any, trace string) *river.ErrorHandlerResult {
	log.FromContext(ctx).Warn().Interface("panic", panicVal).Str("trace", trace).
		Str("kind", job.Kind).Str("queue", job.Queue).Int("attempt", job.Attempt).
		Msg("job panicked")
	return nil // default retry schedule; this handler only adds visibility
}

// QueueDepths returns the current pending/running job counts per queue and
// state, for the obs metrics collector. Best-effort: a query error yields nil so
// a flaky scrape never errors the /metrics endpoint. Mirrors LogQueueStats' SQL.
func QueueDepths(ctx context.Context, pool *pgxpool.Pool) []obs.QueueStat {
	rows, err := pool.Query(ctx, `
		SELECT queue, state, count(*) AS n
		FROM river_job
		WHERE state IN ('available', 'running', 'scheduled', 'retryable')
		GROUP BY queue, state`)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("QueueDepths: query failed — queue-depth metrics skipped this scrape")
		return nil
	}
	defer rows.Close()

	var out []obs.QueueStat
	for rows.Next() {
		var s obs.QueueStat
		if err := rows.Scan(&s.Queue, &s.State, &s.N); err == nil {
			out = append(out, s)
		}
	}
	if err := rows.Err(); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("QueueDepths: row iteration failed — queue-depth metrics skipped this scrape")
		return nil
	}
	return out
}

// QueueOldestAvailable returns, per queue, the age (in seconds) of the oldest
// job still sitting in the `available` state — how long it has been eligible to
// run but not yet picked up by any worker. Backs
// obs.Sources.QueueOldestAvailable / graph_river_queue_oldest_available_seconds,
// which exists because a single wedged job on an otherwise-idle queue never
// crosses graph_river_queue_depth's own count-based thresholds.
//
// Same connection handling and error semantics as QueueDepths: a query error
// returns nil, the same as "no queue currently has an available job" — both
// produce no row for a queue, which the collector turns into omitting that
// queue's series rather than a fabricated 0 (a wedged-job alert reading age=0
// would look healthy, the one outcome this must avoid). The separate
// graph_metrics_source_up gauge tells the two cases apart across scrapes.
func QueueOldestAvailable(ctx context.Context, pool *pgxpool.Pool) []obs.QueueAgeStat {
	rows, err := pool.Query(ctx, `
		SELECT queue, EXTRACT(EPOCH FROM (now() - min(scheduled_at)))::bigint AS oldest_seconds
		FROM river_job
		WHERE state = 'available'
		GROUP BY queue`)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("QueueOldestAvailable: query failed — queue-age metrics skipped this scrape")
		return nil
	}
	defer rows.Close()

	var out []obs.QueueAgeStat
	for rows.Next() {
		var s obs.QueueAgeStat
		if err := rows.Scan(&s.Queue, &s.OldestAvailableSeconds); err == nil {
			out = append(out, s)
		}
	}
	if err := rows.Err(); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("QueueOldestAvailable: row iteration failed — queue-age metrics skipped this scrape")
		return nil
	}
	return out
}
