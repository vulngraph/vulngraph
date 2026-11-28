//go:build integration

package perfassurance

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/memlimit"
)

// WorkerRuntime records actual runtime controls, not only requested settings.
// Native memory is reserved by policy; this does not imply COPY/BFS ran.
type WorkerRuntime struct {
	Policy             memlimit.Budget   `json:"production_memory_policy"`
	GoVersion          string            `json:"go_version"`
	Platform           string            `json:"platform"`
	GOMAXPROCS         int               `json:"gomaxprocs"`
	GOGC               uint64            `json:"actual_gogc_percent"`
	GoMemoryLimit      uint64            `json:"actual_go_memory_limit_bytes"`
	Cgroup             map[string]string `json:"cgroup_limits"`
	ClickHouseVersion  string            `json:"clickhouse_version"`
	ClickHouseSettings map[string]string `json:"clickhouse_session_settings"`
	ClickHouseServer   map[string]string `json:"clickhouse_server_settings"`
}

// WorkerDatabaseQueries keeps benchmark-only administrative SQL at the test
// call site, outside the application's inferred permission surface.
type WorkerDatabaseQueries struct {
	Session string
	Server  string
}

// BootstrapWorker applies the same memory governor as cmd/graph, verifies the
// live runtime readback, and records the effective database/resource cohort.
func BootstrapWorker(ctx context.Context, app, admin *db.CH, nativeBufferMiB int, queries WorkerDatabaseQueries) (WorkerRuntime, error) {
	out := WorkerRuntime{Policy: memlimit.Apply(os.Getenv, nativeBufferMiB), GoVersion: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		GOMAXPROCS: runtime.GOMAXPROCS(0), Cgroup: map[string]string{}, ClickHouseSettings: map[string]string{}, ClickHouseServer: map[string]string{}}
	samples := []metrics.Sample{{Name: "/gc/gogc:percent"}, {Name: "/gc/gomemlimit:bytes"}}
	metrics.Read(samples)
	for _, sample := range samples {
		if sample.Value.Kind() != metrics.KindUint64 {
			return out, fmt.Errorf("runtime control %s is unavailable", sample.Name)
		}
	}
	out.GOGC, out.GoMemoryLimit = samples[0].Value.Uint64(), samples[1].Value.Uint64()
	if err := verifyWorkerRuntime(out, os.Getenv("GOMAXPROCS")); err != nil {
		return out, err
	}
	for _, name := range []string{"memory.max", "memory.swap.max", "cpu.max"} {
		b, err := os.ReadFile("/sys/fs/cgroup/" + name)
		if err != nil {
			return out, fmt.Errorf("read cgroup %s: %w", name, err)
		}
		out.Cgroup[name] = strings.TrimSpace(string(b))
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := app.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing ClickHouse version")
		}
		return rows.Scan(&out.ClickHouseVersion)
	}, "SELECT version()"); err != nil {
		return out, fmt.Errorf("read ClickHouse version: %w", err)
	}
	readSettings := func(store *db.CH, query string, result map[string]string) error {
		return store.Select(ctx, func(rows driver.Rows) error {
			for rows.Next() {
				var name, value string
				if err := rows.Scan(&name, &value); err != nil {
					return err
				}
				result[name] = value
			}
			return rows.Err()
		}, query)
	}
	if err := readSettings(app, queries.Session, out.ClickHouseSettings); err != nil {
		return out, fmt.Errorf("read ClickHouse session controls: %w", err)
	}
	if err := readSettings(admin, queries.Server, out.ClickHouseServer); err != nil {
		return out, fmt.Errorf("read ClickHouse server controls: %w", err)
	}
	if len(out.ClickHouseSettings) != 5 || len(out.ClickHouseServer) != 2 {
		return out, fmt.Errorf("missing database runtime controls")
	}
	return out, nil
}

// Compare measured runtime values with the applied policy, so recording an
// intended budget cannot silently stand in for configuring the Go runtime.
func verifyWorkerRuntime(actual WorkerRuntime, procs string) error {
	if !actual.Policy.Applied || actual.GoMemoryLimit != uint64(actual.Policy.GoLimit) {
		return fmt.Errorf("benchmark requires applied production memory limit; runtime=%d policy=%d", actual.GoMemoryLimit, actual.Policy.GoLimit)
	}
	if actual.Policy.GCPercent > 0 && actual.GOGC != uint64(actual.Policy.GCPercent) {
		return fmt.Errorf("runtime GOGC %d differs from policy %d", actual.GOGC, actual.Policy.GCPercent)
	}
	wantProcs, err := strconv.Atoi(procs)
	if err != nil || wantProcs != actual.GOMAXPROCS {
		return fmt.Errorf("explicit GOMAXPROCS does not match runtime: %q/%d", procs, actual.GOMAXPROCS)
	}
	return nil
}
