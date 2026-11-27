//go:build integration

package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/vulngraph/vulngraph/internal/perfassurance"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type mixedOperation struct {
	Scheduled time.Time `json:"scheduled_at"`
	Started   time.Time `json:"started_at"`
	Finished  time.Time `json:"finished_at"`
}

type mixedServerSample struct {
	Time          time.Time `json:"time"`
	ResidentBytes float64   `json:"resident_bytes"`
}

type mixedQueryReport struct {
	Version               int                 `json:"fixture_version"`
	Variant               string              `json:"variant"`
	Source                string              `json:"source"`
	Rows                  int                 `json:"rows"`
	ReadRate              int                 `json:"read_arrivals_per_second"`
	WriteRate             int                 `json:"write_batches_per_second"`
	WriteBatchRows        int                 `json:"write_batch_rows"`
	ReadWorkers           int                 `json:"read_workers"`
	CHConcurrency         int                 `json:"ch_concurrency"`
	Started               time.Time           `json:"started_at"`
	Finished              time.Time           `json:"finished_at"`
	Reads                 []mixedOperation    `json:"reads"`
	Writes                []mixedOperation    `json:"writes"`
	Server                []mixedServerSample `json:"server_memory_samples"`
	PeakRSSBytes          int64               `json:"go_process_peak_rss_bytes"`
	QueryCount            uint64              `json:"query_count"`
	ReadRows              uint64              `json:"read_rows"`
	ReadBytes             uint64              `json:"read_bytes"`
	MaxQueryMemory        uint64              `json:"max_query_memory_bytes"`
	UserCPUMicroseconds   uint64              `json:"query_user_cpu_microseconds"`
	SystemCPUMicroseconds uint64              `json:"query_system_cpu_microseconds"`
	QueryErrors           uint64              `json:"query_errors"`
	ExactOutputs          bool                `json:"exact_outputs"`
	Passed                bool                `json:"passed"`
	WaitScope             string              `json:"admission_wait_scope"`
}

const mixedQueryCosts = `SELECT count(),sum(read_rows),sum(read_bytes),max(memory_usage),
 sum(ProfileEvents['UserTimeMicroseconds']),sum(ProfileEvents['SystemTimeMicroseconds']),countIf(exception_code!=0)
 FROM system.query_log WHERE startsWith(log_comment,?) AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart')`
const mixedServerMemory = `SELECT value FROM system.asynchronous_metrics WHERE metric='MemoryResident'`

func mixedTask(g *errgroup.Group, ctx context.Context, fn func() error) {
	g.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("mixed workload panic: %v", p)
				log.FromContext(ctx).Error().Err(err).Msg("query probe failed")
			}
		}()
		return fn()
	})
}

func waitMixedArrival(ctx context.Context, at time.Time) error {
	delay := time.Until(at)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func TestInventoryConcurrentCosts(t *testing.T) {
	if os.Getenv("PERF_QUERY_ISOLATED") != "1" || os.Getenv("PERF_QUERY_MIXED_SECONDS") == "" {
		t.Skip("opt-in matched inventory/ingest probe")
	}
	seconds, err := strconv.Atoi(os.Getenv("PERF_QUERY_MIXED_SECONDS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, seconds, 5)
	require.LessOrEqual(t, seconds, 60)
	n, err := strconv.Atoi(os.Getenv("PERF_QUERY_ROWS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 1000)
	variant := os.Getenv("PERF_QUERY_VARIANT")
	require.Contains(t, []string{"baseline", "candidate"}, variant)
	ctx := t.Context()
	ch, err := perfassurance.OpenQueryStore(ctx, os.Getenv("PERF_CLICKHOUSE_URL"))
	require.NoError(t, err)
	defer ch.Close()
	telemetry, err := perfassurance.OpenQueryStore(ctx, os.Getenv("PERF_CLICKHOUSE_URL"))
	require.NoError(t, err)
	defer telemetry.Close()
	report := mixedQueryReport{Version: 1, Variant: variant, Source: os.Getenv("PERF_COMMIT"), Rows: n, ReadRate: 20, WriteRate: 5, WriteBatchRows: 100, ReadWorkers: 8, CHConcurrency: 4,
		WaitScope: "scheduled arrival to harness worker start; call latency includes unseparated ClickHouse semaphore/pool/transport wait"}
	defer func() {
		report.Passed = !t.Failed()
		data, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_QUERY_DIR"), "mixed.json"), append(data, '\n'), 0o600))
	}()
	require.NoError(t, ch.Exec(ctx, seedInventoryQueryFixture, n))
	repo := NewCHRepo(ch)
	svc := NewService(repo)
	// Rewrite existing low-ranked resources. The selected page remains stable,
	// while real history reads, native writes, versions and merges contend with it.
	var writeIDs []string
	for _, key := range independentInventoryKeys(n, Filter{Type: "ec2_instance"}) {
		if key.n%1000 >= 800 {
			writeIDs = append(writeIDs, key.id)
			if len(writeIDs) == 100 {
				break
			}
		}
	}
	require.Len(t, writeIDs, 100)
	writes, err := repo.ByIDs(ctx, writeIDs)
	require.NoError(t, err)
	require.Len(t, writes, 100)
	q, args, err := baselineInventoryQuery(Filter{})
	require.NoError(t, err)
	want, err := readInventoryFixture(ctx, ch, q, args...)
	require.NoError(t, err)
	independent := independentInventoryKeys(n, Filter{})
	require.Len(t, want, 100)
	for i, a := range want {
		require.Equal(t, independent[i].id, a.ID)
		require.NotContains(t, writeIDs, a.ID)
	}
	initialFirstSeen := map[string]time.Time{}
	for _, a := range writes {
		initialFirstSeen[a.ID] = a.FirstDiscoveredAt
	}
	require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
	prefix := "mixed-" + variant + "-"
	samples := make(chan mixedOperation, seconds*report.ReadRate)
	arrivals := make(chan time.Time, report.ReadRate*2)
	workCtx, stopWork := context.WithCancel(ctx)
	defer stopWork()
	group, groupCtx := errgroup.WithContext(workCtx)
	report.Started = time.Now().UTC()
	start := report.Started
	var telemetryGroup errgroup.Group
	var serverMu sync.Mutex
	mixedTask(&telemetryGroup, workCtx, func() error {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return nil
			case at := <-ticker.C:
				var resident float64
				seen := false
				err := telemetry.Select(workCtx, func(rows driver.Rows) error {
					if !rows.Next() {
						return fmt.Errorf("missing whole-server resident memory metric")
					}
					seen = true
					return rows.Scan(&resident)
				}, mixedServerMemory)
				if workCtx.Err() != nil {
					return nil
				}
				if err != nil {
					return err
				}
				if !seen || resident <= 0 {
					return fmt.Errorf("unmeasured server resident memory")
				}
				serverMu.Lock()
				report.Server = append(report.Server, mixedServerSample{at, resident})
				serverMu.Unlock()
			}
		}
	})
	mixedTask(group, groupCtx, func() error {
		defer close(arrivals)
		for i := 0; i < seconds*report.ReadRate; i++ {
			at := start.Add(time.Duration(i) * time.Second / time.Duration(report.ReadRate))
			if err := waitMixedArrival(groupCtx, at); err != nil {
				return err
			}
			select {
			case <-groupCtx.Done():
				return groupCtx.Err()
			case arrivals <- at:
			}
		}
		return nil
	})
	for worker := 0; worker < report.ReadWorkers; worker++ {
		mixedTask(group, groupCtx, func() error {
			for at := range arrivals {
				op := mixedOperation{Scheduled: at, Started: time.Now().UTC()}
				readCtx, cancel := context.WithTimeout(groupCtx, 15*time.Second)
				readCtx = ch.WithQuerySettings(readCtx, map[string]any{"log_comment": prefix + "read", "log_queries": 1, "log_queries_probability": 1, "max_execution_time": 12})
				var got []Asset
				var e error
				if variant == "candidate" {
					got, e = repo.List(inventoryBufferExperiment(readCtx, ch), Filter{})
				} else {
					got, e = readInventoryFixture(readCtx, ch, q, args...)
				}
				cancel()
				if e != nil {
					return e
				}
				if !reflect.DeepEqual(want, got) {
					return fmt.Errorf("mixed read changed selected inventory page")
				}
				op.Finished = time.Now().UTC()
				samples <- op
			}
			return nil
		})
	}
	mixedTask(group, groupCtx, func() error {
		for wave := 0; wave < seconds*report.WriteRate; wave++ {
			at := start.Add(time.Duration(wave) * time.Second / time.Duration(report.WriteRate))
			if err := waitMixedArrival(groupCtx, at); err != nil {
				return err
			}
			op := mixedOperation{Scheduled: at, Started: time.Now().UTC()}
			for i := range writes {
				writes[i].Metadata["mixed_wave"] = strconv.Itoa(wave)
			}
			writeCtx := ch.WithQuerySettings(groupCtx, map[string]any{"log_comment": prefix + "write", "log_queries": 1, "log_queries_probability": 1})
			if err := svc.IngestAssets(writeCtx, writes); err != nil {
				return err
			}
			op.Finished = time.Now().UTC()
			report.Writes = append(report.Writes, op)
		}
		return nil
	})
	workErr := group.Wait()
	report.Finished = time.Now().UTC()
	stopWork()
	telemetryErr := telemetryGroup.Wait()
	close(samples)
	for sample := range samples {
		report.Reads = append(report.Reads, sample)
	}
	sort.Slice(report.Reads, func(i, j int) bool { return report.Reads[i].Scheduled.Before(report.Reads[j].Scheduled) })
	require.NoError(t, workErr)
	require.NoError(t, telemetryErr)
	require.Len(t, report.Reads, seconds*report.ReadRate)
	require.Len(t, report.Writes, seconds*report.WriteRate)
	require.NotEmpty(t, report.Server)
	persisted, err := repo.ByIDs(ctx, writeIDs)
	require.NoError(t, err)
	require.Len(t, persisted, 100)
	for _, a := range persisted {
		require.Equal(t, strconv.Itoa(seconds*report.WriteRate-1), a.Metadata["mixed_wave"])
		require.Equal(t, initialFirstSeen[a.ID], a.FirstDiscoveredAt)
	}
	report.ExactOutputs = true
	var usage syscall.Rusage
	require.NoError(t, syscall.Getrusage(syscall.RUSAGE_SELF, &usage))
	report.PeakRSSBytes = usage.Maxrss
	if runtime.GOOS != "darwin" {
		report.PeakRSSBytes *= 1024
	}
	require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing mixed query telemetry")
		}
		return rows.Scan(&report.QueryCount, &report.ReadRows, &report.ReadBytes, &report.MaxQueryMemory, &report.UserCPUMicroseconds, &report.SystemCPUMicroseconds, &report.QueryErrors)
	}, mixedQueryCosts, prefix))
	require.Zero(t, report.QueryErrors)
	// The existing conservative JSON-size estimate splits 100 wide rows into
	// three native batches; each IngestAssets also reads observation history.
	require.Equal(t, uint64(len(report.Reads)+4*len(report.Writes)), report.QueryCount, "every read/history lookup/native batch must be represented")
}
