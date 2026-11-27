package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/vulngraph/vulngraph/pkg/querybudget"
)

// defaultSelectTimeout is a backstop deadline for read queries that arrive
// without one. A runaway SELECT otherwise holds one of the CH semaphore slots
// for a caller's entire (possibly very long) job, starving every other
// ClickHouse consumer. It is deliberately generous so it never trips a normal
// read; callers needing a tighter bound set their own deadline.
const defaultSelectTimeout = 10 * time.Minute

// defaultCHMaxConcurrent is the per-process cap on in-flight ClickHouse queries,
// used when NewCH's maxConcurrent argument is <= 0. The semaphore lives here in
// the client layer so call sites never double-acquire (CLAUDE.md ClickHouse
// rules). It is a per-pod cap; the server-side cap is maxConcurrentQueries in
// clickhouse-config.yaml.
//
// Each pod type (worker, serve, scanner) opens its own CH and so its own
// semaphore; the value is chosen against the server-side cap across however
// many pods run concurrently.
//
// The semaphore bounds query COUNT, not bytes — a handful of large aggregations
// can still exceed server memory even with every slot well under the count cap.
// Query shapes must be small enough that a full set of slots fits in the
// server's memory budget; lowering this number instead trades a memory failure
// for queue starvation without fixing the underlying shape.
//
// Overridable per-process by the caller (cmd/graph reads CH_MAX_CONCURRENT) —
// this file does not read env vars itself; that is cmd/graph's job.
const defaultCHMaxConcurrent = 8

// CH wraps a ClickHouse connection and a concurrency semaphore. All repositories
// that read or write ClickHouse share one CH.
type CH struct {
	conn     driver.Conn
	sem      chan struct{}
	singleMu sync.Mutex
	single   map[string]*singleBatcher
}

// NewCH opens a ClickHouse connection from a clickhouse:// DSN and verifies
// it. maxConcurrent bounds in-flight queries on this connection (see
// defaultCHMaxConcurrent for how the value relates to the server-side
// maxConcurrentQueries) — pass <= 0 to use defaultCHMaxConcurrent. cmd/graph
// threads CH_MAX_CONCURRENT through here so a self-host with a bigger box and a
// raised server-side cap can raise it without a source change.
func NewCH(ctx context.Context, dsn string, maxConcurrent int) (*CH, error) {
	if maxConcurrent <= 0 {
		maxConcurrent = defaultCHMaxConcurrent
	}
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("NewCH: parse dsn: %w", err)
	}
	// Pool sized above maxConcurrent so the semaphore — not the pool — is the
	// bottleneck. The driver's default MaxOpenConns (5) is below the default
	// 8-slot semaphore, which caused "context deadline exceeded" waiting for a
	// pool connection under load.
	opts.MaxOpenConns = maxConcurrent + 4 // headroom over the semaphore for concurrent syncs
	opts.MaxIdleConns = maxConcurrent
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("NewCH: open: %w", err)
	}
	if err := conn.Ping(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("NewCH: ping: %w", err)
	}
	return &CH{conn: conn, sem: make(chan struct{}, maxConcurrent)}, nil
}

func (c *CH) Close() error { return c.conn.Close() }

// acquire blocks until a query slot is free or ctx is done.
func (c *CH) acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *CH) release() { <-c.sem }

// WithQuerySettings returns a context carrying ClickHouse per-query settings
// (e.g. max_execution_time, join_use_nulls). The clickhouse-go driver reads
// these from context and includes them in the query request, so ClickHouse
// enforces them server-side. A cancelled Go context also stops the query (the
// driver sends a cancel to the server); max_execution_time is a second bound
// the server applies on its own.
//
// Usage:
//
//	ctx = ch.WithQuerySettings(ctx, map[string]any{"max_execution_time": 10})
func (*CH) WithQuerySettings(ctx context.Context, settings map[string]any) context.Context {
	// Preserve tracing and other caller settings when a repository adds query
	// bounds. Copy both maps so parallel reads cannot mutate the parent context.
	merged := make(map[string]any, len(settings))
	if prior, ok := ctx.Value(querySettingsKey{}).(map[string]any); ok {
		for k, v := range prior {
			merged[k] = v
		}
	}
	for k, v := range settings {
		merged[k] = v
	}
	settings = merged
	// Recorded alongside the driver option because the driver's settings are
	// replaced, not merged, by a later WithSettings: applyBudget needs them to
	// add its own bound without dropping the caller's tuning.
	ctx = context.WithValue(ctx, querySettingsKey{}, settings)
	return clickhouse.Context(ctx, clickhouse.WithSettings(settings))
}

type querySettingsKey struct{}

// applyBudget bounds a read by the querybudget the request carries (an LLM
// tool call, for one): a client deadline that cancels the query server-side,
// ClickHouse's own max_execution_time so the server stops it too, and a
// query_id so the query is findable in system.query_log. It only ever
// tightens: a caller's shorter deadline or lower max_execution_time stands.
func applyBudget(ctx context.Context) (context.Context, context.CancelFunc) {
	b, ok := querybudget.From(ctx)
	if !ok {
		return ctx, func() {}
	}
	cancel := context.CancelFunc(func() {})
	if b.Timeout > 0 {
		if d, has := ctx.Deadline(); !has || time.Until(d) > b.Timeout {
			ctx, cancel = context.WithTimeout(ctx, b.Timeout)
		}
	}
	settings := budgetedSettings(ctx, b)
	ctx = clickhouse.Context(ctx, clickhouse.WithSettings(settings), clickhouse.WithQueryID(uuid.NewString()))
	return ctx, cancel
}

// budgetedSettings is the caller's recorded settings with max_execution_time
// lowered to the budget's (never raised).
func budgetedSettings(ctx context.Context, b querybudget.Budget) map[string]any {
	settings := map[string]any{}
	if cur, ok := ctx.Value(querySettingsKey{}).(map[string]any); ok {
		for k, v := range cur {
			settings[k] = v
		}
	}
	if b.MaxExecutionTime > 0 {
		if cur, ok := seconds(settings["max_execution_time"]); !ok || cur <= 0 || cur > b.MaxExecutionTime {
			settings["max_execution_time"] = b.MaxExecutionTime
		}
	}
	return settings
}

// seconds reads a numeric ClickHouse setting a caller may have passed as any
// Go integer type; anything else is treated as unset.
func seconds(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint64:
		return int(n), true
	case int32:
		return int(n), true
	}
	return 0, false
}

// Select runs a read query under the semaphore, scanning rows via fn.
//
// A backstop deadline is applied only when the caller set none; it never
// shortens a caller's own (tighter) deadline and never touches CH query
// settings, so per-query tuning (e.g. max_bytes_before_external_group_by) is
// preserved. clickhouse-go propagates ctx cancellation to abort the query
// server-side, so this frees the semaphore slot, not just the client wait.
func (c *CH) Select(ctx context.Context, scan func(driver.Rows) error, query string, args ...any) error {
	// Derived generations publish their commit marker in the same table as
	// their rows. Every reference must use that table's one query snapshot;
	// a DSN, server profile or caller override must not disable this invariant.
	ctx = c.WithQuerySettings(ctx, map[string]any{"enable_shared_storage_snapshot_in_query": 1})
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultSelectTimeout)
		defer cancel()
	}
	ctx, cancelBudget := applyBudget(ctx)
	defer cancelBudget()

	if err := c.acquire(ctx); err != nil {
		return fmt.Errorf("Select: %w", err)
	}
	defer c.release()

	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("Select: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	if err := scan(rows); err != nil {
		return fmt.Errorf("Select: scan: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("Select: rows: %w", err)
	}
	return nil
}

// WithWriteBudget guarantees an idempotent bulk write at least budget of
// wall-clock, even when the caller's context is already expired or nearly so.
//
// A sync job shares ONE deadline across collect → ingest → check. If
// collection consumes most of it, the ingest that follows would otherwise
// inherit a near-dead context and discard every collected row — which is
// worse than finishing late: the rows are already in memory and the target is
// a ReplacingMergeTree, so a re-run of the same write is a no-op anyway.
//
// Cancellation is re-based, not lost: the returned context detaches from the
// parent's deadline but keeps its values, and the explicit budget bounds it so a
// terminating pod still drains. A pod killed mid-write simply re-collects next
// sweep; a partial insert cannot corrupt a ReplacingMergeTree.
func WithWriteBudget(ctx context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) >= budget {
		return context.WithCancel(ctx) // the caller already grants enough time
	}
	return context.WithTimeout(context.WithoutCancel(ctx), budget)
}

// Exec runs a statement that returns no rows (DDL, mutations) under the semaphore.
func (c *CH) Exec(ctx context.Context, query string, args ...any) error {
	if err := c.acquire(ctx); err != nil {
		return fmt.Errorf("Exec: %w", err)
	}
	defer c.release()

	if err := c.conn.Exec(ctx, query, args...); err != nil {
		return fmt.Errorf("Exec: %w", err)
	}
	return nil
}

// Batch runs a batched INSERT under the semaphore. append is called once to add
// every row to the prepared batch.
//
// The driver sees ctx's deadline but never its cancellation — see
// batchContext. Cancelling ctx (as opposed to its deadline passing) does not
// interrupt a batch that is already prepared. That is acceptable because every
// caller writes a bounded chunk: the ReplacingMergeTree targets dedupe a write
// that lands twice, and for the append-only MergeTree tables (audit_events,
// asset_change_log) finishing a write that has started is the outcome we want.
func (c *CH) Batch(ctx context.Context, query string, append func(driver.Batch) error) error {
	if err := c.acquire(ctx); err != nil {
		return fmt.Errorf("Batch: %w", err)
	}
	defer c.release()

	// Batch promises immediate readback on success. Server defaults (or caller
	// settings) enabling asynchronous acknowledgement must not weaken it.
	// These writes are already grouped locally; a second server buffer also
	// adds its flush delay to every dependent enrichment step.
	ctx = c.WithQuerySettings(ctx, map[string]any{"async_insert": 0})
	batch, err := c.conn.PrepareBatch(batchContext(ctx), query)
	if err != nil {
		return fmt.Errorf("Batch: prepare: %w", batchErr(ctx, err))
	}
	defer func() {
		if !batch.IsSent() {
			_ = batch.Abort()
		}
	}()
	if err := append(batch); err != nil {
		_ = batch.Abort()
		return fmt.Errorf("Batch: append: %w", err)
	}
	if err := batch.Send(); err != nil {
		return fmt.Errorf("Batch: send: %w", batchErr(ctx, err))
	}
	return nil
}

// batchContext returns the context handed to PrepareBatch: ctx's values and
// deadline, but a nil Done channel, so it can never be cancelled.
//
// Why: clickhouse-go v2.46.0 through at least v2.48.0, batch.Send in
// conn_batch.go starts contextWatchdog(b.ctx, ...), whose callback closes the
// batch's raw TCP socket. Its stop function (context_watchdog.go) only closes
// an exit channel; it does not wait for the watchdog goroutine. If that
// goroutine has not reached its select by the time Send returns, the conn is
// already back in the idle pool, and a cancellation of b.ctx right afterwards
// (a caller's `defer cancel()`) leaves both select cases ready. Go picks one at
// random, so the callback can close a pooled conn, possibly mid-query for
// another caller, and the next query on it fails with "use of closed network
// connection". With a nil Done channel the watchdog can only exit via stop.
//
// The deadline is still enforced, by the driver and only on the conn it owns:
// prepareBatch and the response read in closeQuery call conn.SetDeadline with
// ctx.Deadline(), so an overrun fails with an i/o timeout and the driver closes
// that conn instead of pooling it. The one step without a deadline is the
// block write inside Send; TCP and the server's receive_timeout bound it.
// Pool acquisition (clickhouse.go acquire) can wait on ctx without a timer
// when the deadline is under DialTimeout away, but it never waits: c.sem caps
// in-flight conns below MaxOpenConns, and dialing uses its own DialTimeout.
func batchContext(ctx context.Context) context.Context {
	dl, ok := ctx.Deadline()
	return deadlineOnlyContext{Context: context.WithoutCancel(ctx), deadline: dl, hasDeadline: ok}
}

// deadlineOnlyContext reports a deadline without ever becoming Done (see
// batchContext). The embedded context comes from context.WithoutCancel, so
// Done() and Err() are both nil.
type deadlineOnlyContext struct {
	context.Context
	deadline    time.Time
	hasDeadline bool
}

func (c deadlineOnlyContext) Deadline() (time.Time, bool) { return c.deadline, c.hasDeadline }

// batchErr attaches ctx's own error when a batch fails after ctx expired, so
// callers matching context.DeadlineExceeded still match: under batchContext
// the driver reports a deadline overrun as a net i/o timeout.
func batchErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, ctxErr) {
		return fmt.Errorf("%w: %w", ctxErr, err)
	}
	return err
}
