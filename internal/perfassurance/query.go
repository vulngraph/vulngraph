package perfassurance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/db"
)

// QuerySample retains server cost alongside end-to-end elapsed time. Telemetry
// and independent result validation are outside the measured log_comment.
type QuerySample struct {
	BudgetError             string      `json:"budget_error,omitempty"`
	AllocatedBytes          uint64      `json:"allocated_bytes"`
	HeapBytes               uint64      `json:"heap_bytes_after"`
	ExpectedBudgetViolation string      `json:"expected_budget_violation,omitempty"`
	Name                    string      `json:"name"`
	Seconds                 float64     `json:"seconds"`
	Queries                 []QueryCost `json:"queries"`
}

// QueryCost is a completed query's system.query_log record.
type QueryCost struct {
	ProfileEvents map[string]uint64 `json:"profile_events"`
	MaxBlockSize  string            `json:"max_block_size_setting,omitempty"`
	MaxThreads    string            `json:"max_threads_setting,omitempty"`
	SQL           string            `json:"sql"`
	Milliseconds  uint64            `json:"milliseconds"`
	ReadRows      uint64            `json:"read_rows"`
	ReadBytes     uint64            `json:"read_bytes"`
	Memory        uint64            `json:"peak_query_memory_bytes"`
	Exception     string            `json:"exception"`
}

// QueryReport is exploratory evidence, never a complete deployment profile pass.
type QueryReport struct {
	DefaultMaxThreads uint64              `json:"default_max_threads,omitempty"`
	QueryConcurrency  int                 `json:"query_concurrency"`
	GoVersion         string              `json:"go_version"`
	GoMaxProcs        int                 `json:"gomaxprocs"`
	Experiment        string              `json:"experiment,omitempty"`
	Versions          string              `json:"inventory_seeded_versions"`
	FixtureVersion    int                 `json:"fixture_version"`
	Source            string              `json:"source"`
	Platform          string              `json:"platform"`
	Rows              int                 `json:"fixture_rows"`
	Passed            bool                `json:"passed"`
	Samples           []QuerySample       `json:"samples"`
	Plans             map[string][]string `json:"plans"`
}

// QueryLogAccess is supplied by an isolated integration test. Administrative
// SQL stays with that test, outside the application's privilege surface.
type QueryLogAccess struct {
	Flush  func(context.Context) error
	Select string
}

// Measure records the whole operation; fn must return errors and validate output.
// The isolated integration test supplies its privileged log-flush operation;
// benchmark administration must not become an application-user capability.
func Measure(ctx context.Context, ch *db.CH, queryLog QueryLogAccess, name string, fn func(context.Context) error) (QuerySample, error) {
	tagged := ch.WithQuerySettings(ctx, map[string]any{"log_comment": name, "log_queries": 1, "log_queries_probability": 1, "log_query_settings": 1})
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	err := fn(tagged)
	sample := QuerySample{Name: name, Seconds: time.Since(start).Seconds()}
	runtime.ReadMemStats(&after)
	sample.AllocatedBytes = after.TotalAlloc - before.TotalAlloc
	sample.HeapBytes = after.HeapAlloc
	if flushErr := queryLog.Flush(ctx); flushErr != nil {
		return sample, fmt.Errorf("flush query log: %w", flushErr)
	}
	costErr := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var c QueryCost
			if err := rows.Scan(&c.SQL, &c.Milliseconds, &c.ReadRows, &c.ReadBytes, &c.Memory, &c.Exception, &c.MaxThreads, &c.MaxBlockSize, &c.ProfileEvents); err != nil {
				return err
			}
			sample.Queries = append(sample.Queries, c)
		}
		return rows.Err()
	}, queryLog.Select, name)
	if err != nil {
		return sample, fmt.Errorf("measure %s: %w", name, err)
	}
	if costErr != nil {
		return sample, fmt.Errorf("read query costs: %w", costErr)
	}
	if len(sample.Queries) == 0 {
		return sample, fmt.Errorf("missing query telemetry: %s", name)
	}
	for _, q := range sample.Queries {
		if q.Exception != "" {
			return sample, fmt.Errorf("query exception: %s", q.Exception)
		}
	}
	return sample, nil
}

// Explain records the pruning plan with the exact query parameters.
func Explain(ctx context.Context, ch *db.CH, query string, args ...any) ([]string, error) {
	var out []string
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			out = append(out, line)
		}
		return rows.Err()
	}, "EXPLAIN indexes=1 "+query, args...)
	if err != nil {
		return nil, fmt.Errorf("explain query: %w", err)
	}
	return out, nil
}

// SaveQueryReport preserves failures as well as successful samples.
func SaveQueryReport(dir, name string, r QueryReport) error {
	r.FixtureVersion = 2
	r.QueryConcurrency = 4
	r.GoVersion = runtime.Version()
	r.GoMaxProcs = runtime.GOMAXPROCS(0)
	r.Experiment = os.Getenv("PERF_QUERY_EXPERIMENT")
	r.Versions = os.Getenv("PERF_QUERY_VERSIONS")
	if r.Versions == "" {
		r.Versions = "1"
	}
	r.Source = os.Getenv("PERF_COMMIT")
	r.Platform = runtime.GOOS + "/" + runtime.GOARCH
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode query report: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("save query report: %w", err)
	}
	return nil
}

// QueryBudget gates deterministic work, not shared-runner elapsed time.
type QueryBudget struct {
	Queries     int
	ReadRows    uint64
	ReadBytes   uint64
	MemoryBytes uint64
}

// Check returns every exceeded dimension so a larger count cannot hide behind
// an acceptable latency. Memory is a per-query bound, not a server-memory claim.
func (b QueryBudget) Check(s QuerySample) error {
	var rows, bytes, peak uint64
	for _, q := range s.Queries {
		rows += q.ReadRows
		bytes += q.ReadBytes
		peak = max(peak, q.Memory)
	}
	var exceeded []string
	if len(s.Queries) == 0 || len(s.Queries) > b.Queries {
		exceeded = append(exceeded, "query count")
	}
	if rows > b.ReadRows {
		exceeded = append(exceeded, "read rows")
	}
	if bytes > b.ReadBytes {
		exceeded = append(exceeded, "read bytes")
	}
	if peak > b.MemoryBytes {
		exceeded = append(exceeded, "query memory")
	}
	if len(exceeded) > 0 {
		return fmt.Errorf("query budget %s exceeded: %v", s.Name, exceeded)
	}
	return nil
}

// OpenQueryStore refuses a benchmark DSN outside the disposable loopback database.
func OpenQueryStore(ctx context.Context, dsn string) (*db.CH, error) {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "clickhouse" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "/vg_query_perf" {
		return nil, fmt.Errorf("query benchmark requires an isolated loopback vg_query_perf database")
	}
	ch, err := db.NewCH(ctx, dsn, 4)
	if err != nil {
		return nil, fmt.Errorf("open query benchmark store: %w", err)
	}
	return ch, nil
}
