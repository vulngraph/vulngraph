//go:build integration

package jobs

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
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/memlimit"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
	"golang.org/x/sync/errgroup"
)

const graphSourceSeed = `INSERT INTO assets
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

// The retained baseline is the previous graph-source query, including its
// global wide-row sort. The production variant exercises the current reader.
const graphSourceBaseline = `SELECT id,name,type,provider,region,account_id,endpoint,
 public_ip,private_ip,domain,tags,metadata,risk_score,discovered_at,first_discovered_at,last_seen
 FROM asset_current_with_derivations WHERE type NOT IN (%s) AND %s ORDER BY id LIMIT 5000000`

func TestEnvelopeGraphSourceCosts(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("run benchmark-connector-envelope.sh with PERF_ENVELOPE_TEST")
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
	traceFile, err := os.Create(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "worker-timeline.jsonl"))
	require.NoError(t, err)
	defer traceFile.Close()
	trace := &envelopeTrace{file: traceFile, active: map[string]int{}, peak: map[string]int{}}
	sampleCtx, stopSamples := context.WithCancel(ctx)
	var sampling errgroup.Group
	sampling.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("source sampler panic: %v", p)
			}
		}()
		return trace.sample(sampleCtx)
	})
	defer func() { stopSamples(); require.NoError(t, sampling.Wait()) }()
	stamp := time.Now().UTC().Truncate(time.Second)
	for _, table := range []string{"assets", "asset_finding_risk", "asset_annotations"} {
		require.NoError(t, admin.Exec(ctx, "TRUNCATE TABLE "+table))
		require.NoError(t, admin.Exec(ctx, "SYSTEM STOP MERGES "+table))
	}
	for revision := 1; revision <= 2; revision++ {
		require.NoError(t, admin.Exec(ctx, graphSourceSeed, revision, stamp, n))
	}
	require.NoError(t, admin.Exec(ctx, `INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned)
 SELECT toDateTime64(?,9),repeat('a',64),concat('graph-load-',leftPad(toString(number),9,'0')),60,1
 FROM numbers(?) WHERE number%10=0`, stamp, n))
	require.NoError(t, admin.Exec(ctx, `INSERT INTO asset_finding_risk (generation,digest,id,risk_score,pinned)
 VALUES (?,?,'',0,1)`, stamp, strings.Repeat("a", 64)))
	var physical uint64
	require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing source count")
		}
		return rows.Scan(&physical)
	}, "SELECT count() FROM assets"))
	require.Equal(t, uint64(2*n), physical)
	quoted := func(ss []string) string { return "'" + strings.Join(ss, "','") + "'" }
	baseline := fmt.Sprintf(graphSourceBaseline, quoted(asset.NeverSyncTypes), asset.EphemeralLivenessCond)
	keys := fmt.Sprintf("SELECT type,id,synced_at FROM assets FINAL WHERE type NOT IN (%s) AND %s ORDER BY id LIMIT 5000000", quoted(asset.NeverSyncTypes), asset.EphemeralLivenessCond)
	// Graph input excludes declared resources, the only annotation target.
	// Keep raw latest-version hydration ordered by the storage's (type,id) key.
	keyed := fmt.Sprintf(`SELECT a.id,a.current.1,a.type,a.current.2,a.current.3,a.current.4,a.current.5,a.current.6,a.current.7,a.current.8,a.current.9,a.current.10,
 greatest(a.current.11,r.risk_score),a.current.12,a.current.13,a.current.14
 FROM (SELECT id,type,argMax(tuple(name,provider,region,account_id,endpoint,public_ip,private_ip,domain,tags,metadata,risk_score,discovered_at,first_discovered_at,last_seen),synced_at) AS current
 FROM assets WHERE (type,id,synced_at) IN (%s) GROUP BY type,id) AS a
 LEFT JOIN (SELECT id,max(risk_score) AS risk_score FROM asset_finding_risk
 WHERE id!='' AND (generation,digest)=(SELECT max((generation,digest)) FROM asset_finding_risk WHERE id='' AND pinned=1) GROUP BY id) AS r ON a.id=r.id
 SETTINGS query_plan_join_swap_table='false', optimize_aggregation_in_order=1`, keys)
	queries := map[string]string{"pre25_observations_only": strings.Replace(baseline, "asset_current_with_derivations", "assets FINAL", 1), "baseline": baseline, "keyed_ordered_aggregation": keyed}

	report := map[string]any{"go_memory_budget": budget, "fixture_version": 6, "source": os.Getenv("PERF_COMMIT"), "logical_rows": n, "physical_rows": physical,
		"query_concurrency": 1, "risk_rows": (n+9)/10 + 1, "projection_keys": graphstore.SyncMetadataKeys,
		"limits": []string{"streaming validation does not retain the production whole-asset slice", "elapsed/client allocation include independent full JSON validation, not the production projected decoder; no application speedup claim", "single graph-source query, not concurrent ingestion/native build", "pre25 control reads stored risk only; not derived-risk output parity", "current keys retain the ordered five-million-row selection; wide rows stream unordered, production adoption must restore order in Go"}}
	var samples []perfassurance.QuerySample
	plans := map[string][]string{}
	defer func() {
		report["passed"] = !t.Failed()
		report["samples"], report["plans"] = samples, plans
		data, err := json.MarshalIndent(report, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "graph-source.json"), data, 0600))
	}()
	logAccess := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") },
		Select: `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds,query_id`}
	for name, q := range queries {
		plans[name], err = perfassurance.Explain(ctx, app, q)
		require.NoError(t, err)
	}
	for repeat := range 3 {
		order := []string{"pre25_observations_only", "baseline", "keyed_ordered_aggregation", "production"}
		if repeat%2 != 0 {
			order = []string{"production", "keyed_ordered_aggregation", "baseline", "pre25_observations_only"}
		}
		for _, variant := range order {
			sample, err := perfassurance.Measure(ctx, admin, logAccess, fmt.Sprintf("graph-source:%s:%d", variant, repeat), func(ctx context.Context) error {
				done := trace.begin("graph_source_"+variant, strconv.Itoa(repeat))
				var readErr error
				if variant == "production" {
					readErr = verifyProductionGraphSource(ctx, app, n, stamp)
				} else {
					readErr = verifyGraphSource(ctx, app, queries[variant], n, stamp, variant != "keyed_ordered_aggregation", variant != "pre25_observations_only")
				}
				done(readErr)
				return readErr
			})
			if err != nil {
				sample.Error = err.Error()
			}
			samples = append(samples, sample)
			// Baseline failures remain evidence. Both candidate shapes must pass
			// the same independent field/count/duplicate oracle before acceptance.
			if (variant == "keyed_ordered_aggregation" || variant == "production") && err != nil {
				t.Errorf("%s: %v", variant, err)
			}
		}
	}
}

func verifyGraphSource(ctx context.Context, ch *db.CH, query string, n int, stamp time.Time, ordered, derived bool) error {
	seen := make([]bool, n)
	count, prior := 0, ""
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var a asset.Asset
			var provider, metadata string
			if err := rows.Scan(&a.ID, &a.Name, &a.Type, &provider, &a.Region, &a.AccountID, &a.Endpoint, &a.PublicIP, &a.PrivateIP, &a.Domain, &a.Tags, &metadata, &a.RiskScore, &a.DiscoveredAt, &a.FirstDiscoveredAt, &a.LastSeen); err != nil {
				return err
			}
			i, err := strconv.Atoi(strings.TrimPrefix(a.ID, "graph-load-"))
			if err != nil || i < 0 || i >= n || seen[i] {
				return fmt.Errorf("unexpected or duplicate identity %q", a.ID)
			}
			seen[i], count = true, count+1
			if ordered && a.ID <= prior {
				return fmt.Errorf("unordered source %q after %q", a.ID, prior)
			}
			prior = a.ID
			a.Provider = asset.Provider(provider)
			if err := json.Unmarshal([]byte(metadata), &a.Metadata); err != nil {
				return err
			}
			if err := verifyGraphSourceAsset(a, i, stamp, derived); err != nil {
				return err
			}
		}
		return rows.Err()
	}, query)
	if err != nil {
		return err
	}
	if count != n {
		return fmt.Errorf("source count %d want %d", count, n)
	}
	return nil
}

func verifyGraphSourceAsset(a asset.Asset, i int, stamp time.Time, derived bool) error {
	kind, cloud, risk := "ec2_instance", "aws", uint8(i%50)
	if i%2 != 0 {
		kind, cloud = "gce_instance", "gcp"
	}
	access := "possible"
	if i%10 == 0 {
		access = "confirmed"
		if derived {
			risk = 60
		}
	}
	if a.Name != fmt.Sprintf("host-%d-v2", i) || a.Type != kind || string(a.Provider) != cloud || a.RiskScore != risk || a.Region != "west" || a.AccountID != "synthetic-account" || a.Endpoint != "endpoint" || a.PublicIP != "203.0.113.1" || a.PrivateIP != "10.0.0.1" || a.Domain != "synthetic.invalid" || !a.LastSeen.Equal(stamp) || !a.DiscoveredAt.Equal(stamp.Add(-24*time.Hour)) || !a.FirstDiscoveredAt.Equal(stamp.Add(-48*time.Hour)) {
		return fmt.Errorf("incorrect current observation %s", a.ID)
	}
	delete(a.Metadata, "payload") // identical client projection for the baseline
	want := map[string]string{"public_access": access, "public": "false", "encryption": "AES256", "classification": "internal", "version": "1.0", "trust_entry": "quoted \"text\" and unicode café"}
	if !reflect.DeepEqual(want, a.Metadata) {
		return fmt.Errorf("incorrect projected metadata %s: %v", a.ID, a.Metadata)
	}
	return nil
}

func verifyProductionGraphSource(ctx context.Context, ch *db.CH, n int, stamp time.Time) error {
	out, err := asset.NewCHRepo(ch).ListAllForSync(ctx, graphstore.SyncProjection())
	if err != nil {
		return err
	}
	if out.Truncated || len(out.Assets) != n {
		return fmt.Errorf("production source count %d/truncated=%t want %d", len(out.Assets), out.Truncated, n)
	}
	for i, a := range out.Assets {
		if a.ID != fmt.Sprintf("graph-load-%09d", i) || len(a.Tags) != 0 {
			return fmt.Errorf("production order/projection mismatch at %d", i)
		}
		if err := verifyGraphSourceAsset(a, i, stamp, true); err != nil {
			return err
		}
	}
	return nil
}
