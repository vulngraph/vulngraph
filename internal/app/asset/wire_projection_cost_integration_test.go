//go:build integration

package asset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

// Retain the independently measured SQL expression as a parity control for the
// production projection. The pre-projection SQL remains listAllForSyncQ.
const wireMetadataProjection = `if(isValidJSON(%[1]s) AND
 arrayAll(x -> startsWith(x.2,'"'), JSONExtractKeysAndValuesRaw(%[1]s)),
 concat('{',arrayStringConcat(arrayMap(x -> concat(toJSONString(x.1),':',x.2),
 arrayFilter(x -> has(?,x.1),JSONExtractKeysAndValuesRaw(%[1]s))),','),'}'),%[1]s)`

const wireSeedAssets = `INSERT INTO assets
 (id,name,type,provider,region,account_id,endpoint,public_ip,private_ip,domain,tags,metadata,risk_score,discovered_at,first_discovered_at,last_seen,synced_at)
 SELECT concat('wire-',leftPad(toString(number),9,'0')),?,'ec2_instance','aws','',concat('synthetic-',toString(number%37)),
 '','','','',map('owner','synthetic','discarded_tag',repeat('t',128)),
 toJSONString(map('region',concat('region-',toString(number%4)),'quoted',?,'unicode',?,'discarded_policy',repeat('p',if(number%10=0,16384,512)))),
 toUInt8(number%101),?,?,?,fromUnixTimestamp64Nano(toInt64(?)) FROM numbers(?,?) SETTINGS max_block_size=8192,max_threads=2`

func TestGraphSourceWireProjectionCosts(t *testing.T) { runWireProjection(t, false) }

func TestGraphSourceWireProjectionMixed(t *testing.T) { runWireProjection(t, true) }

func runWireProjection(t *testing.T, mixed bool) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("requires isolated cost fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	report := map[string]any{"fixture_version": 5, "physical_asset_versions": 2, "source": os.Getenv("PERF_COMMIT"), "scope": "isolated SQL projection before latest-row aggregation; GC between samples; no native build, concurrent pipeline or capacity acceptance"}
	var samples []perfassurance.QuerySample
	t.Cleanup(func() {
		report["passed"] = !t.Failed()
		report["samples"] = samples
		b, err := json.MarshalIndent(report, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "graph-source-wire.json"), b, 0600))
	})
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 1)
	require.NoError(t, err)
	defer admin.Close()
	app, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer app.Close()
	keys := []string{"region", "quoted", "unicode", "kept", "escaped/key", "café"}
	keep := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		keep[k] = struct{}{}
	}
	cases := []string{
		`{}`, ``, `null`, `[]`, `"text"`, `123`,
		`{"kept":"value","discard":"large"}`,
		` { "kept" : "value", "discard" : "large" } `,
		`{"kept":"first","kept":"last"}`,
		`{"kept":"first","discard":null}`, `{"kept":null}`, `{"kept":1}`, `{"kept":"value","discard":1}`,
		`{"kept":"value","discard":{"nested":"value"}}`,
		`{"kept":"value","discard":["value"]}`,
		`{"kept":"quote\" newline\n slash\/ backslash\\"}`,
		`{"unicode":"café 😀","café":"non-ascii key","escaped\/key":"slash"}`,
		`{"\u006b\u0065pt":"escaped key","unicode":"\ud83d\ude00"}`,
		`{"kept":"\ud800"}`, `{"\ud800":"invalid surrogate","kept":"valid"}`,
		`{"kept":"first",}`, `{"kept":"unterminated}`, `{"kept":"bad\x"}`,
		`{"kept":"valid"} trailing`, "{\"kept\":\"raw\xffbyte\"}",
	}
	for i, raw := range cases {
		var got string
		err := app.Select(ctx, func(rows driver.Rows) error {
			if !rows.Next() {
				return fmt.Errorf("missing projected JSON")
			}
			if err := rows.Scan(&got); err != nil {
				return err
			}
			if rows.Next() {
				return fmt.Errorf("extra projected JSON")
			}
			return rows.Err()
		}, "WITH ? AS metadata SELECT "+syncMetadataProjection, raw, keys)
		require.NoError(t, err, "case %d", i)
		require.Equal(t, decodeMapKeep(raw, keep), decodeMapKeep(got, keep), "case %d: raw=%q projected=%q", i, raw, got)
	}
	n, err := strconv.Atoi(os.Getenv("PERF_ENVELOPE_ASSETS"))
	require.NoError(t, err)
	queryBudget := uint64(512 << 20)
	if n <= 100000 {
		queryBudget = 128 << 20
	}
	report["candidate_query_budget_bytes"] = queryBudget
	repo := NewCHRepo(app)
	for _, table := range []string{"assets", "asset_finding_risk"} {
		require.NoError(t, admin.Exec(ctx, "SYSTEM STOP MERGES "+table))
	}
	stamp := time.Now().UTC().Truncate(time.Second)
	// Bulk fixture setup is outside measured reads. Keeping production-sized
	// inserts while merges are stopped creates thousands of tiny parts before
	// the query experiment starts; it measures insert backpressure instead.
	for version := range 2 {
		for start := 0; start < n; start += 100000 {
			require.NoError(t, admin.Exec(ctx, wireSeedAssets, fmt.Sprintf("revision-%d", version), "quote\" slash\\", "café 😀", stamp, stamp, stamp, stamp.UnixNano()+int64(version)*int64(time.Millisecond), start, min(100000, n-start)))
		}
	}
	physical := map[string]uint64{}
	require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var name string
			var count uint64
			if err := rows.Scan(&name, &count); err != nil {
				return err
			}
			physical[name] = count
		}
		return rows.Err()
	}, "SELECT name,count() FROM assets GROUP BY name"))
	require.Equal(t, map[string]uint64{"revision-0": uint64(n), "revision-1": uint64(n)}, physical)
	report["physical_rows_by_version"] = physical
	projection := SyncProjection{MetadataKeys: keys, SkipTags: true}
	candidate := strings.Replace(listAllForSyncQ, "tags,metadata,risk_score", "CAST(map(),'Map(String,String)'),"+fmt.Sprintf(wireMetadataProjection, "metadata")+",risk_score", 1)
	candidate += ", aggregation_in_order_max_block_bytes=4194304"
	require.NotEqual(t, listAllForSyncQ, candidate)
	var plan []string
	require.NoError(t, app.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan = append(plan, line)
		}
		return rows.Err()
	}, "EXPLAIN PIPELINE "+candidate, keys))
	report["candidate_pipeline"] = plan
	report["ordered_block_bytes"] = 4 << 20
	require.Contains(t, strings.Join(plan, "\n"), "AggregatingInOrder", "ordered-block experiment must use ordered aggregation")
	loadBaseline := func(ctx context.Context) (AssetSyncResult, error) {
		var out []Asset
		err := app.Select(ctx, func(rows driver.Rows) error {
			for rows.Next() {
				a, err := scanAssetKeep(rows, keep, true)
				if err != nil {
					return err
				}
				out = append(out, a)
			}
			return rows.Err()
		}, listAllForSyncQ)
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return AssetSyncResult{Assets: out, Truncated: len(out) >= syncAssetLimit}, err
	}
	loadCandidate := func(ctx context.Context) (AssetSyncResult, error) { return repo.ListAllForSync(ctx, projection) }
	productionQuery, productionArgs := syncAssetQuery(projection)
	require.Equal(t, candidate, productionQuery, "measured SQL must match the actual production reader")
	require.Equal(t, []any{keys}, productionArgs)
	verify := func(result AssetSyncResult) string {
		t.Helper()
		require.False(t, result.Truncated)
		require.Len(t, result.Assets, n)
		hash := sha256.New()
		encoder := json.NewEncoder(hash)
		for i, a := range result.Assets {
			a.DiscoveredAt, a.FirstDiscoveredAt, a.LastSeen = a.DiscoveredAt.UTC(), a.FirstDiscoveredAt.UTC(), a.LastSeen.UTC()
			want := Asset{ID: fmt.Sprintf("wire-%09d", i), Name: "revision-1", Type: "ec2_instance", Provider: "aws", AccountID: fmt.Sprintf("synthetic-%d", i%37), RiskScore: uint8(i % 101), DiscoveredAt: stamp, FirstDiscoveredAt: stamp, LastSeen: stamp,
				Metadata: map[string]string{"region": fmt.Sprintf("region-%d", i%4), "quoted": "quote\" slash\\", "unicode": "café 😀"}}
			require.Equal(t, want, a, "independent fixture fields, including observations and empty fields")
			require.NoError(t, encoder.Encode(a))
		}
		return hex.EncodeToString(hash.Sum(nil))
	}
	if mixed {
		report["scope"] = "fixture setup; mixed measurements in graph-source-wire-mixed.json"
		runWireMixed(t, ctx, app, admin, repo, n, stamp, loadBaseline, loadCandidate, verify)
		return
	}
	var expected string
	func() {
		result, err := loadBaseline(ctx)
		if err != nil {
			report["baseline_reference_error"] = err.Error()
			t.Errorf("baseline reference: %v", err)
			return
		}
		expected = verify(result)
	}()
	report["logical_assets"] = n
	report["json_semantics_cases"] = len(cases)
	report["expected_output_sha256"] = expected
	access := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") }, Select: `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds,query_id`}
	for repeat := range 3 {
		variants := []string{"baseline", "projected"}
		if repeat%2 == 1 {
			variants = []string{"projected", "baseline"}
		}
		for _, variant := range variants {
			runtime.GC()
			var result AssetSyncResult
			sample, err := perfassurance.Measure(ctx, admin, access, fmt.Sprintf("wire:%s:%d", variant, repeat), func(ctx context.Context) error {
				var e error
				if variant == "baseline" {
					result, e = loadBaseline(ctx)
				} else {
					result, e = loadCandidate(ctx)
				}
				return e
			})
			if err != nil {
				sample.Error = err.Error()
			}
			if err == nil && len(sample.Queries) == 1 && sample.Queries[0].Memory > queryBudget {
				sample.BudgetError = fmt.Sprintf("query memory %d exceeds %d-byte fixture ceiling", sample.Queries[0].Memory, queryBudget)
				if variant == "projected" {
					t.Error(sample.BudgetError)
				}
			}
			samples = append(samples, sample)
			if err != nil {
				t.Errorf("%s: %v", variant, err)
				continue
			}
			require.Len(t, sample.Queries, 1)
			actual := verify(result)
			if expected == "" {
				expected = actual
				report["expected_output_sha256"] = actual
			}
			require.Equal(t, expected, actual, "every returned field must match")
		}
	}
}
