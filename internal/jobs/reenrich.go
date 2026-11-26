package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// A full corpus re-enrichment feeds the EXISTING per-finding enrich path rather
// than computing scores itself. A finding is normally only re-enriched when its
// underlying check re-emits it, so a logic-version bump would otherwise leave the
// whole open corpus stuck on stale scoring until each finding happens to change
// again; this mechanism walks the corpus and re-enqueues everything explicitly.
//
// A separate bulk-compute path would be faster, but it would need a second scoring
// implementation that must never disagree with this one, and it would rewrite
// every row from a single snapshot — one degraded provider would poison the whole
// corpus at once rather than one finding at a time. Reusing the per-finding path
// costs more wall-clock time but carries none of that risk: it is the same code
// that already scores everything, paced so it never starves live enrichment.
const (
	// reenrichChunk is how many findings one round enqueues, sized to the PESSIMISTIC
	// drain rate rather than the average: a version bump defeats the per-job
	// change-gate, so during a full pass every enqueued job does real (slow) work,
	// not the cheap skip most jobs normally take. Set below the worst-case
	// drain rate so queue depth trends down, not up, across a pass.
	// See TestReenrichPacingDrainsEachRoundAndFinishesWithinADay, which asserts this arithmetic.
	reenrichChunk = 1_150
	// reenrichRoundDelay paces the rounds so enrichment drains between them. This is
	// what keeps the job short-lived: each round enqueues and exits in seconds
	// instead of one job babysitting a multi-hour drain.
	reenrichRoundDelay = 5 * time.Minute
	// reenrichQueueCeiling skips a round when the enrich queue is already deeper than
	// this, so the pass never dumps a full corpus's worth of jobs onto a backlogged
	// worker (enrich.go's sweepHasCapacity guards the same risk). Must stay below
	// jobListMaxFirst or the depth probe can never observe it as reached.
	reenrichQueueCeiling = 8_000
	// reenrichCorpusHigh is the design ceiling on the open-finding corpus that the
	// round budget is sized for. Raise it if a deployment's open-finding count
	// approaches it.
	reenrichCorpusHigh = 250_000
	// reenrichMaxRounds backstops a finding that never stamps enriched_at — a
	// permanently failing enrich would otherwise make the pass loop forever, since
	// rounds terminate on "nothing left older than the cutoff". Derived from the
	// corpus size with real headroom rather than a hand-picked constant, since a
	// tight margin turns this into a coin flip on whether the pass converges at all.
	// Aborting is not a soft failure: it leaves the new enrichcache.LogicVersion
	// unapplied to whatever fraction of the corpus the pass did not reach.
	reenrichMaxRounds = 3 * (reenrichCorpusHigh/reenrichChunk + 1)
	// reenrichMaxSkips bounds consecutive backpressure skips, on their own budget
	// separate from Round: a skipped round enqueues nothing, so charging it against
	// the round budget would let sustained enrich-queue depth abort the pass without
	// processing a single finding. 144 skips at reenrichRoundDelay is well past any
	// transient backlog, and the budget resets on the first productive round.
	reenrichMaxSkips = 144
	// reenrichTimeout bounds ONE round: a page read plus a batched insert. Rounds are
	// deliberately small, so this needs no relation to the multi-hour total.
	reenrichTimeout = 5 * time.Minute
)

// ReenrichAllArgs drives one round of a full corpus re-enrichment.
//
// Rounds are self-continuing: each enqueues a chunk of the stalest open findings,
// then schedules the next round. Termination is "no open finding is older than the
// cutoff", which needs no persisted cursor — re-enriching bumps enriched_at, pushing
// a finding to the back of the same ordering (the self-balancing property
// EnrichSweepWorker's drift pass already relies on).
type ReenrichAllArgs struct {
	// Round counts rounds, for logging and the runaway backstop. It also makes each
	// continuation's args distinct, which matters: with identical args River's
	// UniqueOpts would refuse to insert the next round while this one is still
	// running, and the pass would stop after one chunk.
	Round int `json:"round"`
	// Skips counts consecutive rounds skipped for enrich-queue backpressure. It is
	// separate from Round because a skipped round enqueues nothing: charging it to
	// the round budget made backpressure — the mechanism protecting the worker —
	// the thing that aborted the pass. It also keeps each retry's args distinct so
	// River's ByArgs dedup doesn't swallow the continuation.
	Skips int `json:"skips"`
	// Cutoff (unix seconds) is the instant the pass began. Findings enriched before
	// it still need reprocessing. Zero means "this is the first round — stamp now",
	// which is what the boot trigger inserts.
	Cutoff int64 `json:"cutoff"`
	// Version is the enrichcache.LogicVersion this chain is converging toward,
	// stamped on the round that (re)started it. Checked every round against the
	// CURRENT LogicVersion (Work) rather than trusted blindly: without this, a
	// chain that started under an old version keeps chasing its own stale cutoff
	// forever, and insertReenrichIfIdle's "a pass already exists" guard means a
	// later version bump never gets a pass of its own while the old chain is still
	// alive. Empty (the zero value) never equals a real version string, so the very
	// next round any in-flight chain runs restarts it against the current version.
	Version string `json:"version"`
	// AfterID is the walk cursor: the last id enqueued by the previous productive
	// round. Empty means "start at the beginning" — every finding id sorts after "".
	// It lives in the job args because river_job already persists them, so the pass
	// needs no table of its own.
	//
	// The pass needs a cursor because ordering by enriched_at ASC is not
	// self-balancing, and cannot be: the epoch-stamped head refills (see finding.openIDsBehindCutoffQ), so ordering over a column the
	// write path resets can never converge. A SKIPPED round must preserve this
	// value rather than advance it — a skipped round enqueues nothing, so advancing
	// would silently skip a whole page.
	AfterID string `json:"after_id,omitempty"`
}

func (ReenrichAllArgs) Kind() string { return "reenrich_all" }

// InsertOpts puts rounds on their own single-worker lane so a pass can never occupy
// an enrich slot, and dedups by args so a re-inserted identical round is a no-op.
func (ReenrichAllArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		Queue: queueReenrich,
		UniqueOpts: river.UniqueOpts{
			ByArgs:  true,
			ByState: uniqueStates,
		},
	}
}

// reenrichPager walks the corpus by id from a caller-held cursor.
// finding.Service implements it.
type reenrichPager interface {
	OpenIDsBehindCutoff(ctx context.Context, cutoff time.Time, afterID string, limit int) ([]string, error)
}

// fullPassMarker records which enrichment LogicVersion the corpus has been fully
// processed for. enrichcache.Service implements it.
type fullPassMarker interface {
	MarkFullPassComplete(ctx context.Context) error
}

// ReenrichWorker runs one round of the full pass. A nil findings pager disables it.
type ReenrichWorker struct {
	river.WorkerDefaults[ReenrichAllArgs]
	findings reenrichPager
	cache    fullPassMarker
	// clock is injectable so tests can assert cutoff handling without sleeping.
	clock func() time.Time
}

func (w *ReenrichWorker) Timeout(_ *river.Job[ReenrichAllArgs]) time.Duration {
	return reenrichTimeout
}

func (w *ReenrichWorker) now() time.Time {
	if w.clock != nil {
		return w.clock()
	}
	return time.Now()
}

func (w *ReenrichWorker) Work(ctx context.Context, job *river.Job[ReenrichAllArgs]) error {
	if w.findings == nil {
		return nil // full-pass re-enrichment not wired in this deployment
	}
	logger := log.FromContext(ctx)
	args := job.Args

	// The version this chain is converging toward has moved on — restart as a
	// fresh pass against the CURRENT version instead of continuing to chase a
	// stale target. See the Version field doc for why this is load-bearing, not
	// defensive: without it, this is the ONLY full pass that will ever run.
	if args.Version != enrichcache.LogicVersion {
		logger.Warn().Str("from_version", args.Version).Str("to_version", enrichcache.LogicVersion).
			Int("abandoned_round", args.Round).
			Msg("reenrich: logic version changed mid-pass — restarting against the current version")
		args = ReenrichAllArgs{Version: enrichcache.LogicVersion}
	}
	round := args.Round

	// Stamp the cutoff on the first round and carry it forward, so the pass targets
	// the corpus as it stood when the version changed. Re-deriving "now" each round
	// would chase its own tail: findings enriched by round 1 would qualify again in
	// round 2, and the pass would never terminate.
	cutoff := time.Unix(args.Cutoff, 0).UTC()
	if args.Cutoff <= 0 {
		cutoff = w.now()
	}

	if round >= reenrichMaxRounds {
		// Something is not stamping enriched_at — a permanently failing enrich, or a
		// corpus larger than this backstop anticipated. Either way, stopping loudly
		// beats looping forever, and NOT marking the pass complete is deliberate: the
		// corpus genuinely has not converged.
		logger.Error().Int("round", round).Time("cutoff", cutoff).
			Msg("reenrich: hit the round backstop without converging — corpus NOT fully reprocessed")
		return nil
	}
	if args.Skips >= reenrichMaxSkips {
		logger.Error().Int("round", round).Int("skips", args.Skips).Time("cutoff", cutoff).
			Msg("reenrich: enrich queue has been saturated for hours — pass abandoned, corpus NOT fully reprocessed")
		return nil
	}

	// Backpressure before adding work. Fail-open on a missing client (unit tests
	// driving the worker directly), matching enqueueEnrich's contract.
	if client, err := river.ClientFromContextSafely[pgx.Tx](ctx); err == nil {
		depth, derr := enrichQueueDepth(ctx, client, reenrichQueueCeiling)
		if derr != nil || depth >= reenrichQueueCeiling {
			logger.Warn().Int("queue_depth", depth).Int("round", round).Int("skips", args.Skips).Err(derr).
				Msg("reenrich: enrich queue too deep — skipping this round, will retry")
			return w.schedule(ctx, nextRound(args, cutoff, true, args.AfterID))
		}
	}

	ids, err := w.findings.OpenIDsBehindCutoff(ctx, cutoff, args.AfterID, reenrichChunk)
	if err != nil {
		return fmt.Errorf("ReenrichWorker: %w", err)
	}
	if len(ids) == 0 {
		// The walk has passed the last open finding behind the cutoff: converged.
		logger.Info().Int("rounds", round).Str("logic_version", enrichcache.LogicVersion).
			Msg("reenrich: full corpus pass complete — every open finding reprocessed")
		if w.cache == nil {
			return nil
		}
		if err := w.cache.MarkFullPassComplete(ctx); err != nil {
			// The corpus IS converged; failing the job would replay the whole pass for
			// a bookkeeping error. The cost of not recording it is one redundant pass
			// on the next boot, which is safe.
			logger.Error().Err(err).Msg("reenrich: pass converged but recording the logic version failed")
		}
		return nil
	}

	enqueued := w.enqueue(ctx, ids)
	logger.Info().
		Int("round", round).Int("candidates", len(ids)).Int("enqueued", enqueued).
		Time("cutoff", cutoff).
		Msg("reenrich: round enqueued")

	return w.schedule(ctx, nextRound(args, cutoff, false, ids[len(ids)-1]))
}

// nextRound is the continuation's args. A SKIPPED round keeps the round number and
// spends a skip instead: it enqueued nothing, so charging it to the round budget
// made backpressure — the mechanism that protects the worker from a deep enrich
// queue — the thing that aborted the pass part-way and left the new LogicVersion
// unapplied to the rest of the corpus. A productive round advances the round and
// resets the skip budget.
//
// lastID is the walk cursor to carry forward, and it is only meaningful on a
// productive round: a skipped round enqueued nothing, so it MUST keep the cursor
// it came in with or a whole page is silently skipped.
func nextRound(cur ReenrichAllArgs, cutoff time.Time, skipped bool, lastID string) ReenrichAllArgs {
	if skipped {
		return ReenrichAllArgs{
			Round: cur.Round, Skips: cur.Skips + 1, Cutoff: cutoff.Unix(),
			Version: cur.Version, AfterID: cur.AfterID,
		}
	}
	return ReenrichAllArgs{
		Round: cur.Round + 1, Cutoff: cutoff.Unix(),
		Version: cur.Version, AfterID: lastID,
	}
}

// reenrichInsertParams builds the per-finding InsertMany params for a round, each
// demoted to enrichSweepPriority: this is routine full-corpus convergence work, not
// a new detection or a KEV escalation, so it must never compete for a worker slot
// against either. Pulled out as its own pure function so the priority can be
// asserted on directly without needing a real river client in a test.
func reenrichInsertParams(ids []string) []river.InsertManyParams {
	opts := &river.InsertOpts{Priority: enrichSweepPriority}
	params := make([]river.InsertManyParams, 0, len(ids))
	for _, id := range ids {
		params = append(params, river.InsertManyParams{Args: EnrichArgs{FindingID: id}, InsertOpts: opts})
	}
	return params
}

// enqueue inserts an enrich job per finding and returns how many landed. A single
// failed insert is logged and skipped rather than failing the round: the next round
// will see the finding again, because its enriched_at is still behind the cutoff.
// That self-healing is why this can afford to be best-effort.
func (w *ReenrichWorker) enqueue(ctx context.Context, ids []string) int {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("reenrich: no river client in context")
		return 0
	}
	params := reenrichInsertParams(ids)
	// One bounded InsertMany avoids a round trip per finding.
	inserted, err := client.InsertMany(ctx, params)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Int("batch", len(ids)).
			Msg("reenrich: batch enqueue failed — these findings retry next round")
		return 0
	}
	return len(inserted)
}

// schedule queues the continuation after the pacing delay. A failure here ENDS the
// pass, so it is returned rather than swallowed: the corpus would silently stop
// converging part-way, which is the exact failure mode this whole mechanism exists to
// eliminate. The next worker boot re-triggers from the version watermark, which is
// the backstop.
func (w *ReenrichWorker) schedule(ctx context.Context, next ReenrichAllArgs) error {
	client, err := river.ClientFromContextSafely[pgx.Tx](ctx)
	if err != nil {
		return nil // no client (unit test) — nothing to schedule
	}
	if _, err := client.Insert(ctx, next,
		&river.InsertOpts{ScheduledAt: w.now().Add(reenrichRoundDelay)}); err != nil {
		return fmt.Errorf("schedule: %w", err)
	}
	return nil
}

// FullPassChecker reports whether the deployed enrichment LogicVersion differs from
// the one a full corpus pass last completed for. enrichcache.Service implements it.
type FullPassChecker interface {
	FullPassNeeded(ctx context.Context) (bool, string, error)
}

// insertReenrichIfIdle enqueues round 0 only when no round is already queued or
// running. River's UniqueOpts cannot help here: this runs at boot, before the client
// is started, so the insert is raw SQL — and a crashlooping worker would otherwise
// start a fresh pass per restart, each re-walking the whole corpus.
const insertReenrichIfIdle = `
INSERT INTO river_job (kind, args, queue, state, max_attempts, priority)
SELECT 'reenrich_all', '{"round":0,"cutoff":0}'::jsonb, 'reenrich', 'available', 3, 1
WHERE NOT EXISTS (
    SELECT 1 FROM river_job
    WHERE kind = 'reenrich_all'
      AND state IN ('available', 'pending', 'running', 'retryable', 'scheduled')
)`

// TriggerFullPassIfVersionChanged enqueues a full corpus re-enrichment when
// enrichment semantics have changed since the corpus was last fully processed. Call
// at worker boot, before starting the River client.
//
// Bumping enrichcache.LogicVersion invalidates the change-gate so a re-enrich
// RECOMPUTES, but nothing re-enqueues a finding whose asset never changed — this is
// the piece that makes sure the whole corpus actually gets requalified.
//
// Best-effort by design: a failure here must not stop the worker booting. A missed
// trigger costs a stale corpus until the next boot, which is the status quo; failing
// to boot costs everything.
func TriggerFullPassIfVersionChanged(ctx context.Context, pool *pgxpool.Pool, checker FullPassChecker) {
	logger := log.FromContext(ctx)
	if checker == nil {
		return
	}
	needed, last, err := checker.FullPassNeeded(ctx)
	if err != nil {
		// FullPassNeeded fails safe (reports true), so fall through and enqueue — a
		// redundant pass is recoverable, a skipped one is invisible.
		logger.Error().Err(err).Msg("reenrich: version check failed; enqueueing a pass anyway")
	}
	if !needed {
		logger.Debug().Str("logic_version", enrichcache.LogicVersion).
			Msg("reenrich: corpus already processed for this enrichment version")
		return
	}
	tag, err := pool.Exec(ctx, insertReenrichIfIdle)
	if err != nil {
		logger.Error().Err(err).Msg("reenrich: boot enqueue failed; corpus stays on the previous enrichment version")
		return
	}
	if tag.RowsAffected() == 0 {
		logger.Info().Msg("reenrich: a full pass is already in progress; not starting another")
		return
	}
	logger.Warn().
		Str("from_version", last).Str("to_version", enrichcache.LogicVersion).
		Msg("reenrich: enrichment logic changed — full corpus pass started")
}
