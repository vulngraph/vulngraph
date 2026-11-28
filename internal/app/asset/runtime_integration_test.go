//go:build integration

package asset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

func TestMain(m *testing.M) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") == "1" {
		if err := bootstrapAssetBenchmark(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func bootstrapAssetBenchmark() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	app, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 1)
	if err != nil {
		return err
	}
	defer app.Close()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 1)
	if err != nil {
		return err
	}
	defer admin.Close()
	manifest, bootstrapErr := perfassurance.BootstrapWorker(ctx, app, admin, 1280, perfassurance.WorkerDatabaseQueries{
		Session: `SELECT name,value FROM system.settings WHERE name IN ('max_threads','max_memory_usage','max_execution_time','max_block_size','enable_shared_storage_snapshot_in_query')`,
		Server:  `SELECT name,value FROM system.server_settings WHERE name IN ('max_server_memory_usage','max_concurrent_queries')`,
	})
	data, err := json.MarshalIndent(struct {
		perfassurance.WorkerRuntime
		Error string `json:"error,omitempty"`
	}{manifest, func() string {
		if bootstrapErr != nil {
			return bootstrapErr.Error()
		}
		return ""
	}()}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "runtime-bootstrap.json"), data, 0600); err != nil {
		return err
	}
	return bootstrapErr
}
