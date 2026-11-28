//go:build integration

package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/memlimit"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// Same data, driver scan, result retention and breaker for both SQL shapes.
// At/above the breaker this proves query cost and refusal, not complete coverage.
func TestProductionCorrelationLoaderCosts(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated performance fixture only")
	}
	n, err := strconv.Atoi(os.Getenv("PERF_ENVELOPE_ASSETS"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 2)
	require.NoError(t, err)
	defer admin.Close()
	app, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 2)
	require.NoError(t, err)
	defer app.Close()
	budget := memlimit.Apply(os.Getenv, 1280)
	stamp := time.Now().UTC().Truncate(time.Second)
	for _, table := range []string{"assets", "asset_finding_risk", "asset_annotations"} {
		require.NoError(t, admin.Exec(ctx, "TRUNCATE TABLE "+table))
		require.NoError(t, admin.Exec(ctx, "SYSTEM STOP MERGES "+table))
	}
	for revision := 1; revision <= 2; revision++ {
		require.NoError(t, admin.Exec(ctx, productionCorrelationSeed, revision, stamp, n))
	}
	require.NoError(t, admin.Exec(ctx, `INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned)
 SELECT toDateTime64(?,9),repeat('a',64),concat('graph-load-',leftPad(toString(number),9,'0')),60,1
 FROM numbers(?) WHERE number%10=0`, stamp, n))
	require.NoError(t, admin.Exec(ctx, `INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned) VALUES (?,?,'',0,1)`, stamp, strings.Repeat("a", 64)))
	var physical uint64
	require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing row count")
		}
		return rows.Scan(&physical)
	}, "SELECT count() FROM assets"))
	require.Equal(t, uint64(2*n), physical)
	access := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") }, Select: `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds,query_id`}
	repo := NewCHRepo(app)
	for _, empty := range [][]string{nil, {}} {
		rows, truncated, emptyErr := repo.LoadViewForTypes(ctx, empty)
		require.NoError(t, emptyErr)
		require.Empty(t, rows)
		require.False(t, truncated, "empty type selection is an empty result, not all types")
	}
	types := []string{"ec2_instance", "gce_instance"}
	typePlaceholders, typeArgs := dbutil.CHIn(types)
	baseline := fmt.Sprintf(loadLegacyViewSource, metadataKeyPlaceholders, typePlaceholders) + " LIMIT ?"
	args := append(append(append([]any{}, metadataKeyArgs...), typeArgs...), correlationLimit)
	joinProbe := os.Getenv("PERF_CORRELATION_JOIN_PROBE") == "1"
	var samples []perfassurance.QuerySample
	// The fixed workload ceiling remains 512 MiB. At the 100k CI fixture,
	// a tighter measured regression guard catches a return to wide aggregation.
	regressionCeiling := uint64(512 << 20)
	if n <= 100_000 {
		regressionCeiling = 224 << 20
	}
	report := map[string]any{"source": os.Getenv("PERF_COMMIT"), "logical_assets": n, "physical_assets": physical, "go_memory_budget": budget, "source_query_memory_budget_bytes": 512 << 20, "query_regression_ceiling_bytes": regressionCeiling, "retained_result_limit": correlationLimit, "expected_truncated": n >= correlationLimit, "scope": "actual production loader and retained asset slice; fixed refusal threshold; one query, not mixed or complete million-asset analysis"}
	if joinProbe {
		report["comparison"] = "current projected loader with unconditional annotation join versus type-scoped annotation join"
	}
	defer func() {
		report["passed"] = !t.Failed()
		report["samples"] = samples
		b, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "production-correlation-source.json"), b, 0600))
	}()
	for repeat := range 3 {
		order := []string{"baseline", "production"}
		if repeat%2 != 0 {
			order = []string{"production", "baseline"}
		}
		for _, variant := range order {
			sample, e := perfassurance.Measure(ctx, admin, access, fmt.Sprintf("production-correlation:%s:%d", variant, repeat), func(ctx context.Context) error {
				var rows []asset.Asset
				var truncated bool
				var readErr error
				if variant == "production" {
					rows, truncated, readErr = repo.LoadViewForTypes(ctx, types)
				} else if joinProbe {
					rows, readErr = repo.scanAssets(ctx, fmt.Sprintf(loadView, metadataKeyPlaceholders, typePlaceholders), args...)
					truncated = len(rows) >= correlationLimit
				} else {
					queryCtx := app.WithQuerySettings(ctx, map[string]any{"max_bytes_before_external_group_by": 1 << 30})
					readErr = app.Select(queryCtx, func(result driver.Rows) error {
						for result.Next() {
							a, e := scanCorrelationAsset(result)
							if e != nil {
								return e
							}
							rows = append(rows, a)
						}
						return result.Err()
					}, baseline, args...)
					truncated = len(rows) >= correlationLimit
				}
				if readErr != nil {
					return readErr
				}
				if truncated != (n >= correlationLimit) {
					return fmt.Errorf("wrong truncation flag %t", truncated)
				}
				if len(rows) != min(n, correlationLimit) {
					return fmt.Errorf("row count %d", len(rows))
				}
				seen := make([]bool, n)
				for _, a := range rows {
					i, e := strconv.Atoi(strings.TrimPrefix(a.ID, "graph-load-"))
					if e != nil || i < 0 || i >= n || seen[i] {
						return fmt.Errorf("bad/duplicate ID %q", a.ID)
					}
					seen[i] = true
					kind := "ec2_instance"
					if i%2 != 0 {
						kind = "gce_instance"
					}
					access := "possible"
					if i%10 == 0 {
						access = "confirmed"
					}
					if a.Name != fmt.Sprintf("host-%d-v2", i) || a.Type != kind || a.AccountID != "synthetic-account" || a.PublicIP != "203.0.113.1" || a.PrivateIP != "10.0.0.1" || a.Domain != "synthetic.invalid" || !reflect.DeepEqual(a.Metadata, map[string]string{"public_access": access, "public": "false"}) || !reflect.DeepEqual(a.Tags, map[string]string{"env": "prod", "unused": strings.Repeat("x", 128)}) {
						return fmt.Errorf("latest field mismatch %s", a.ID)
					}
				}
				return nil
			})
			if e != nil {
				sample.Error = e.Error()
			}
			samples = append(samples, sample)
			if joinProbe {
				require.NoError(t, e)
			}
			if variant == "production" {
				require.NoError(t, e)
				require.Len(t, sample.Queries, 1)
				require.LessOrEqual(t, sample.Queries[0].Memory, regressionCeiling)
			}
		}
	}
	// Exercise the production annotation overlay, not only empty derived tables.
	inv := asset.NewService(asset.NewCHRepo(app))
	manifest := asset.Asset{ID: "cost-manifest", Type: "declared_k8s_workload", LastSeen: stamp, DiscoveredAt: stamp, Metadata: map[string]string{"manifest_key": "deployment/default/app", "live_type": "k8s_deployment", "namespace": "default", "drift": "old"}}
	require.NoError(t, inv.Ingest(ctx, []asset.Asset{manifest}, nil))
	check := func(want string) {
		t.Helper()
		rows, truncated, e := repo.LoadViewForTypes(ctx, []string{manifest.Type})
		require.NoError(t, e)
		require.False(t, truncated)
		require.Len(t, rows, 1)
		require.Equal(t, want, rows[0].Metadata["drift"])
		mixed, mixedTruncated, e := repo.LoadViewForTypes(ctx, []string{manifest.Type, "ec2_instance"})
		require.NoError(t, e)
		require.False(t, mixedTruncated)
		require.Len(t, mixed, (n+1)/2+1)
		found := 0
		for _, a := range mixed {
			if a.ID == manifest.ID {
				found++
				require.Equal(t, want, a.Metadata["drift"])
			}
		}
		require.Equal(t, 1, found, "mixed type reads must retain the current declaration overlay")
		if n < correlationLimit-1 {
			for _, all := range []bool{false, true} {
				var complete []asset.Asset
				if all {
					complete, mixedTruncated, e = repo.LoadView(ctx)
				} else {
					complete, mixedTruncated, e = repo.LoadViewForTypes(ctx, correlationTypes)
				}
				require.NoError(t, e)
				require.False(t, mixedTruncated)
				require.Len(t, complete, n+1)
				matched := 0
				for _, a := range complete {
					if a.ID == manifest.ID {
						matched++
						require.Equal(t, want, a.Metadata["drift"])
					}
				}
				require.Equal(t, 1, matched, "both complete-view APIs retain the declaration overlay")
			}
		}
	}
	check("old")
	version, err := inv.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	annotation := asset.Annotation{ID: manifest.ID, Source: asset.ManifestDriftSource, InputKey: "deployment/default/app\x00k8s_deployment\x00default", Metadata: map[string]string{"drift": "declared_not_live"}}
	require.NoError(t, inv.WriteAnnotations(ctx, version, []asset.Annotation{annotation}))
	check("declared_not_live")
	annotation.Metadata["drift"] = ""
	version, err = inv.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, inv.WriteAnnotations(ctx, version, []asset.Annotation{annotation}))
	check("")
	manifest.Metadata["manifest_key"] = "deployment/default/new"
	require.NoError(t, inv.Ingest(ctx, []asset.Asset{manifest}, nil))
	check("old")
}

const productionCorrelationSeed = `INSERT INTO assets
 (id,name,type,provider,region,account_id,endpoint,public_ip,private_ip,domain,tags,metadata,
 risk_score,discovered_at,first_discovered_at,last_seen,synced_at)
 WITH ? AS revision, toDateTime64(?,9) AS stamp
 SELECT concat('graph-load-',leftPad(toString(number),9,'0')),concat('host-',toString(number),'-v',toString(revision)),
 if(number%2=0,'ec2_instance','gce_instance'),if(number%2=0,'aws','gcp'),'west','synthetic-account',
 'endpoint','203.0.113.1','10.0.0.1','synthetic.invalid',map('env','prod','unused',repeat('x',128)),
 toJSONString(map('public_access',if(number%10=0,'confirmed','possible'),'public','false','encryption','AES256',
 'classification','internal','version','1.0','trust_entry','quoted "text" and unicode café',
 'payload',repeat(hex(SHA256(toString(number))),if(number%100=0,256,4)))),
 toUInt8(number%50),stamp-INTERVAL 1 DAY,stamp-INTERVAL 2 DAY,stamp,stamp+toIntervalSecond(revision)
 FROM numbers(?) SETTINGS max_block_size=512`

// Retained experiment control; production readers use projected tuple aggregation.
const loadLegacyViewSource = `SELECT id,
	argMax(name, synced_at), argMax(type, synced_at), argMax(account_id, synced_at),
	argMax(public_ip, synced_at), argMax(private_ip, synced_at), argMax(domain, synced_at), argMax(tags, synced_at),
	` + projectMetadataExpr + `
	FROM asset_versions_with_derivations
	WHERE type IN (%s) AND ` + asset.EphemeralLivenessCond + `
	GROUP BY id`
