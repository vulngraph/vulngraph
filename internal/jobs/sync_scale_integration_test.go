//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivertest"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/testutil/benchconfig"
)

type scaleCollector struct {
	data             []byte
	changed, partial bool
}

func (s *scaleCollector) Collect(context.Context, map[string]string) (collect.Result, error) {
	var r collect.Result
	if err := json.Unmarshal(s.data, &r); err != nil {
		return r, err
	}
	if s.changed {
		for i := 0; i < len(r.Assets); i += 100 {
			r.Assets[i].Name += "-updated"
			if r.Assets[i].Metadata == nil {
				r.Assets[i].Metadata = map[string]string{}
			}
			r.Assets[i].Metadata["benchmark_revision"] = "updated"
		}
		for i := 0; i < len(r.Edges); i += 100 {
			if r.Edges[i].Properties == nil {
				r.Edges[i].Properties = map[string]string{}
			}
			r.Edges[i].Properties["benchmark_revision"] = "updated"
		}
	}
	if s.partial {
		r.Assets = r.Assets[:len(r.Assets)/2]
		r.Partial = true
	}
	return r, nil
}

type connectorSyncMeasurement struct {
	Connector      string  `json:"connector"`
	Scenario       string  `json:"scenario"`
	Seconds        float64 `json:"seconds"`
	AllocatedBytes uint64  `json:"allocated_bytes"`
	Hashes         int     `json:"stored_hashes"`
	Partial        bool    `json:"partial_fixture"`
	Queries        uint64  `json:"queries"`
	ReadRows       uint64  `json:"read_rows"`
	ReadBytes      uint64  `json:"read_bytes"`
	MaxQueryMemory uint64  `json:"max_query_memory_bytes"`
	QueuedJobs     int     `json:"queued_jobs"`
	VerifiedAssets int     `json:"verified_assets"`
	VerifiedEdges  int     `json:"verified_edges"`
}

func TestConnectorSyncThroughput(t *testing.T) {
	if os.Getenv("PERF_ISOLATED") != "1" || os.Getenv("PERF_CONNECTOR_DIR") == "" {
		t.Skip("run scripts/benchmark-connectors.sh")
	}
	ctx := context.Background()
	pool, err := db.NewPool(ctx, os.Getenv("PERF_POSTGRES_URL"), db.MaxConnsWorker)
	require.NoError(t, err)
	defer pool.Close()
	queue, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	require.NoError(t, err)
	ctx = rivertest.WorkContext(ctx, queue)
	ch, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer func() { _ = ch.Close() }()
	cipher, err := connector.NewCipher(testKey(t))
	require.NoError(t, err)
	conns := connector.NewService(connector.NewPGRepo(pool), cipher)
	var measurements []connectorSyncMeasurement
	for _, name := range []string{"aws", "gcp", "azure", "kubernetes", "github", "okta", "google_workspace", "demo"} {
		t.Run(name, func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join(os.Getenv("PERF_CONNECTOR_DIR"), fmt.Sprintf("%s-%d-fixture.json", name, benchconfig.MaxSize(t))))
			require.NoError(t, err)
			if name == "demo" {
				files, err = filepath.Glob(filepath.Join(os.Getenv("PERF_CONNECTOR_DIR"), "demo-*-fixture.json"))
				require.NoError(t, err)
			}
			require.Len(t, files, 1, "each connector needs a measured fixture")
			data, err := os.ReadFile(files[0])
			require.NoError(t, err)
			producer := &scaleCollector{data: data}
			fixture, err := producer.Collect(ctx, nil)
			require.NoError(t, err)
			want := map[string]bool{}
			for _, a := range fixture.Assets {
				want[a.ID] = true
			}
			id := uuid.NewString()
			enc, err := cipher.EncryptWithAAD([]byte(`{}`), []byte("connector:"+id))
			require.NoError(t, err)
			_, err = pool.Exec(ctx, `INSERT INTO connectors(id,type,name,config_enc) VALUES($1,$2,$3,$4)`, id, name, "benchmark-"+name, enc)
			require.NoError(t, err)
			defer func() { _, e := pool.Exec(ctx, "DELETE FROM connectors WHERE id=$1", id); require.NoError(t, e) }()
			reg := collect.NewRegistry()
			reg.Register(connector.Type(name), producer)
			inv := asset.NewService(asset.NewCHRepo(ch))
			w := &SyncWorker{connectors: conns, registry: reg, assets: inv, findings: finding.NewService(finding.NewCHRepo(ch)), checks: checks.Default()}
			job := &river.Job[SyncConnectorArgs]{Args: SyncConnectorArgs{ConnectorID: id}}
			var priorFP string
			expectedAssets := map[string]asset.Asset{}
			expectedEdges := map[scaleEdgeKey]asset.Edge{}
			for _, scenario := range []string{"initial", "unchanged", "change_1pct", "unchanged_after", "partial"} {
				producer.changed = scenario == "change_1pct" || scenario == "unchanged_after" || scenario == "partial"
				producer.partial = scenario == "partial"
				// The insert-only queue has no consumers. Reset it outside the timed
				// region so earlier connectors cannot hide enqueue cost behind backpressure.
				_, err = pool.Exec(ctx, "DELETE FROM river_job")
				require.NoError(t, err)
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				start := time.Now()
				comment := fmt.Sprintf("sync-scale-%s-%s-%d", name, scenario, start.UnixNano())
				qctx := ch.WithQuerySettings(ctx, map[string]any{"log_comment": comment, "log_queries": 1, "log_queries_probability": 1})
				err := w.Work(qctx, job)
				seconds := time.Since(start).Seconds()
				runtime.ReadMemStats(&after)
				require.NoError(t, err)
				hashes, err := conns.GetAssetHashes(ctx, id)
				require.NoError(t, err)
				require.Len(t, hashes, len(want), "partial collection must retain omitted hashes")
				for assetID := range want {
					_, present := hashes[assetID]
					require.True(t, present, "missing hash %s", assetID)
				}
				c, err := conns.Get(ctx, id)
				require.NoError(t, err)
				fp := splitSyncFingerprint(c.SyncFingerprint).assetFP
				if strings.HasPrefix(scenario, "unchanged") {
					require.Equal(t, priorFP, fp)
				}
				if scenario == "change_1pct" {
					require.NotEqual(t, priorFP, fp)
				}
				priorFP = fp
				m := connectorSyncMeasurement{Connector: name, Scenario: scenario, Seconds: seconds, AllocatedBytes: after.TotalAlloc - before.TotalAlloc, Hashes: len(hashes), Partial: fixture.Partial || producer.partial}
				// Verify real values after timing. Hashes can advance while storage
				// still returns an older version; partial sweeps must retain omitted rows.
				observed, err := producer.Collect(ctx, nil)
				require.NoError(t, err)
				for _, a := range observed.Assets {
					expectedAssets[a.ID] = a
				}
				for _, e := range observed.Edges {
					expectedEdges[scaleEdgeKey{e.SrcID, e.EdgeType, e.DstID}] = e
				}
				verifySyncReadback(t, ctx, inv, expectedAssets, expectedEdges)
				m.VerifiedAssets, m.VerifiedEdges = len(expectedAssets), len(expectedEdges)
				require.NoError(t, ch.Exec(ctx, "SYSTEM FLUSH LOGS"))
				require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
					if !rows.Next() {
						return fmt.Errorf("query telemetry missing")
					}
					return rows.Scan(&m.Queries, &m.ReadRows, &m.ReadBytes, &m.MaxQueryMemory)
				}, `SELECT count(),sum(read_rows),sum(read_bytes),max(memory_usage) FROM system.query_log WHERE type='QueryFinish' AND log_comment=?`, comment))
				require.Positive(t, m.Queries)
				require.LessOrEqual(t, m.Queries, uint64(100+(len(fixture.Assets)+len(fixture.Edges))/25), "sync query growth must stay batched, not one query per asset")
				require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM river_job").Scan(&m.QueuedJobs))
				measurements = append(measurements, m)
				t.Logf("sync %s/%s: seconds=%.4f hashes=%d allocated=%d", name, scenario, seconds, len(hashes), m.AllocatedBytes)
			}
		})
	}
	b, err := json.MarshalIndent(struct {
		FixtureVersion int                        `json:"fixture_version"`
		Passed         bool                       `json:"passed"`
		Measurements   []connectorSyncMeasurement `json:"measurements"`
	}{2, !t.Failed(), measurements}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_CONNECTOR_DIR"), "sync.json"), b, 0600))
	if t.Failed() {
		t.Fatal(fmt.Errorf("connector sync contracts failed"))
	}
}
