//go:build integration

package correlate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// This component cohort runs every registered rule and real source/publication
// adapters. It populates cross-account EC2 roles, DNS and IAM permissions; it is
// not a native graph build, API collector or every-rule capacity certificate.
func TestBoundedCorrelationCosts(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated performance fixture only")
	}
	n, err := strconv.Atoi(os.Getenv("PERF_ENVELOPE_ASSETS"))
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, 5000)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	admin, err := db.NewCH(ctx, os.Getenv("PERF_CLICKHOUSE_URL"), 2)
	require.NoError(t, err)
	defer admin.Close()
	app, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 2)
	require.NoError(t, err)
	defer app.Close()
	controls, err := perfassurance.BootstrapWorker(ctx, app, admin, 1280, perfassurance.WorkerDatabaseQueries{
		Session: `SELECT name,value FROM system.settings WHERE name IN ('max_threads','max_memory_usage','max_execution_time','max_block_size','enable_shared_storage_snapshot_in_query')`,
		Server:  `SELECT name,value FROM system.server_settings WHERE name IN ('max_server_memory_usage','max_concurrent_queries')`,
	})
	require.NoError(t, err)
	trace, stop := startStagedCostTrace(t, ctx)
	defer stop()
	stamp := time.Now().UTC().Truncate(time.Second)
	for _, table := range []string{"assets", "graph_edges", "asset_finding_risk", "asset_annotations"} {
		require.NoError(t, admin.Exec(ctx, "TRUNCATE TABLE "+table))
		require.NoError(t, admin.Exec(ctx, "SYSTEM STOP MERGES "+table))
	}
	inventory := asset.NewService(asset.NewCHRepo(app))
	anchors := boundedCostAnchors(stamp)
	require.NoError(t, inventory.Ingest(ctx, anchors, nil))
	for revision := 1; revision <= 2; revision++ {
		require.NoError(t, admin.Exec(ctx, boundedCostSeed, revision, stamp, n))
	}
	limits, err := StagedViewLimitsFromEnv(os.Getenv)
	require.NoError(t, err)
	access := perfassurance.QueryLogAccess{
		Flush:  func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") },
		Select: `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds,query_id`,
	}
	report := map[string]any{"source": os.Getenv("PERF_COMMIT"), "controls": controls, "limits": limits,
		"logical_compute_assets": n, "anchor_assets": len(anchors), "physical_assets": 2*n + len(anchors),
		"scope": "all registered rules; populated EC2 role, IAM permission and cross-account DNS families; real CH source and publication, no native graph or concurrent ingestion"}
	var samples []perfassurance.QuerySample
	var stats []StagedViewStats
	defer func() {
		report["passed"], report["samples"], report["staged_passes"] = !t.Failed(), samples, stats
		b, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "bounded-correlation.json"), b, 0600))
	}()
	for repeat := range 3 {
		order := []string{"legacy", "bounded"}
		if repeat%2 != 0 {
			order = []string{"bounded", "legacy"}
		}
		for _, variant := range order {
			// One refused control is enough; an aborted legacy pass is never
			// reported as a latency success against completed analysis.
			if variant == "legacy" && n+len(anchors) >= correlationLimit && repeat > 0 {
				continue
			}
			require.NoError(t, admin.Exec(ctx, "TRUNCATE TABLE graph_edges"))
			observer := &boundedCostObserver{}
			service := NewService(NewCHRepo(app), inventory, allRules).WithViewMetrics(observer)
			if variant == "bounded" {
				service.WithStagedViews(limits)
			}
			name := fmt.Sprintf("bounded-correlation:%s:%d", variant, repeat)
			var cpu *os.File
			if variant == "bounded" && repeat == 0 {
				cpu, err = os.Create(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "bounded.cpu"))
				require.NoError(t, err)
				require.NoError(t, pprof.StartCPUProfile(cpu))
			}
			trace.phase.Store(name)
			sample, runErr := perfassurance.Measure(ctx, admin, access, name, func(ctx context.Context) error {
				_, e := service.Correlate(ctx)
				return e
			})
			trace.phase.Store("verify:" + name)
			if cpu != nil {
				pprof.StopCPUProfile()
				require.NoError(t, cpu.Close())
			}
			if runErr != nil {
				sample.Error = runErr.Error()
			}
			samples = append(samples, sample)
			if variant == "bounded" {
				stats = append(stats, observer.stats)
			}
			if variant == "legacy" && n+len(anchors) >= correlationLimit {
				require.ErrorIs(t, runErr, ErrViewTruncated)
				require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
					var count uint64
					if !rows.Next() {
						return fmt.Errorf("missing edge count")
					}
					if e := rows.Scan(&count); e != nil {
						return e
					}
					if count != 0 {
						return fmt.Errorf("refused source published %d edges", count)
					}
					return nil
				}, "SELECT count() FROM graph_edges"))
				continue
			}
			require.NoError(t, runErr)
			require.NoError(t, verifyBoundedCostEdges(ctx, admin, n))
			sourceQueries, publicationQueries := 0, 0
			for _, query := range sample.Queries {
				if strings.Contains(query.SQL, "argMax(tuple(") && strings.Contains(query.SQL, "assets") {
					sourceQueries++
				}
				if strings.HasPrefix(query.SQL, "INSERT INTO graph_edges") {
					publicationQueries++
				}
			}
			require.Equal(t, 1, sourceQueries, "one terminal source record; publication queries are additional work")
			// These fixed-width edges fit the writer's byte ceiling. A replay
			// page that exceeds its row ceiling creates an avoidable second insert.
			require.Equal(t, (2*n+2600+dbutil.CHWriteMaxRows-1)/dbutil.CHWriteMaxRows, publicationQueries)
			if variant == "bounded" {
				require.True(t, observer.stats.SourceComplete)
				require.True(t, observer.stats.PublicationComplete)
				require.Equal(t, n+len(anchors), observer.stats.SourceRows)
				require.Equal(t, 1, observer.stats.SourceQueries)
				require.LessOrEqual(t, observer.stats.IndexChargeBytes, limits.IndexBytes)
				require.LessOrEqual(t, observer.stats.SpoolBytes+observer.stats.OutputBytes, limits.DiskBytes)
			}
		}
	}
}

type boundedCostObserver struct{ stats StagedViewStats }

func (*boundedCostObserver) ObserveCorrelateView(int, int)         {}
func (o *boundedCostObserver) ObserveStagedView(s StagedViewStats) { o.stats = s }

func boundedRole(i int) string { return fmt.Sprintf("arn:aws:iam::999999999999:role/bounded-%03d", i) }
func boundedVM(i int) string   { return fmt.Sprintf("bounded-vm-%09d", i) }

func boundedCostAnchors(stamp time.Time) []asset.Asset {
	var rows []asset.Asset
	for i := range 100 {
		role := principalWithPolicy(boundedRole(i), "iam_role", "999999999999",
			`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
		role.LastSeen, role.DiscoveredAt = stamp, stamp
		rows = append(rows, role, asset.Asset{ID: fmt.Sprintf("bounded-dns-%03d", i), Type: "dns_record", AccountID: "dns-account",
			LastSeen: stamp, DiscoveredAt: stamp, Metadata: map[string]string{"values": fmt.Sprintf("10.42.0.%d", i+1)}})
	}
	return rows
}

// Independently check every persisted tuple and property, with a bit per
// expected tuple. This avoids materializing a second million-row edge graph.
func verifyBoundedCostEdges(ctx context.Context, ch *db.CH, n int) error {
	seen := make([]bool, 2*n+2600)
	count := 0
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var edge asset.Edge
			var encoded string
			if err := rows.Scan(&edge.SrcID, &edge.SrcType, &edge.DstID, &edge.DstType, &edge.EdgeType, &encoded); err != nil {
				return err
			}
			if err := json.Unmarshal([]byte(encoded), &edge.Properties); err != nil {
				return err
			}
			slot, want, err := boundedExpectedEdge(edge, n)
			if err != nil {
				return err
			}
			if seen[slot] || !reflect.DeepEqual(want, edge) {
				return fmt.Errorf("duplicate or mismatched edge: %+v", edge)
			}
			seen[slot] = true
			count++
		}
		return rows.Err()
	}, "SELECT src_id,src_type,dst_id,dst_type,edge_type,properties FROM graph_edges FINAL")
	if err != nil {
		return err
	}
	if count != len(seen) {
		return fmt.Errorf("persisted edges %d, expected %d", count, len(seen))
	}
	return nil
}

func boundedExpectedEdge(edge asset.Edge, n int) (int, asset.Edge, error) {
	parse := func(s, prefix string, limit int) (int, error) {
		if !strings.HasPrefix(s, prefix) {
			return 0, fmt.Errorf("bad fixture ID %q", s)
		}
		i, e := strconv.Atoi(strings.TrimPrefix(s, prefix))
		if e != nil || i < 0 || i >= limit {
			return 0, fmt.Errorf("fixture index %q", s)
		}
		return i, nil
	}
	switch edge.EdgeType {
	case EdgeHasRole:
		i, err := parse(edge.SrcID, "bounded-vm-", n)
		return i, asset.Edge{SrcID: boundedVM(i), SrcType: "ec2_instance", DstID: boundedRole(i % 100), DstType: "iam_role", EdgeType: EdgeHasRole,
			Properties: map[string]string{"origin": edgeOrigin, "rule": "ec2_instance_profile"}}, err
	case EdgeDNSPointsTo:
		i, err := parse(edge.DstID, "bounded-vm-", 2500)
		if err != nil {
			return 0, asset.Edge{}, err
		}
		record := fmt.Sprintf("bounded-dns-%03d", i%100)
		return n + i, asset.Edge{SrcID: record, SrcType: "dns_record", DstID: boundedVM(i), DstType: "ec2_instance", EdgeType: EdgeDNSPointsTo,
			Properties: map[string]string{"origin": edgeOrigin, "rule": "dns_points_to", "matched_value": fmt.Sprintf("10.42.0.%d", i%100+1)}}, nil
	case EdgeAllowsAction:
		i, err := parse(edge.SrcID, "arn:aws:iam::999999999999:role/bounded-", 100)
		if err != nil {
			return 0, asset.Edge{}, err
		}
		want := asset.Edge{SrcID: boundedRole(i), SrcType: "iam_role", DstID: "inline:" + boundedRole(i) + ":inline", DstType: "iam_policy", EdgeType: EdgeAllowsAction,
			Properties: map[string]string{"origin": edgeOrigin, "rule": "iam_effective_permissions", "category": "s3-read", "managed": "false", "policy_name": "inline"}}
		return n + 2500 + i, want, nil
	case EdgeExposedToInternet:
		i, err := parse(edge.SrcID, "bounded-vm-", n)
		want := asset.Edge{SrcID: boundedVM(i), SrcType: "ec2_instance", DstID: InternetNodeID, DstType: "internet", EdgeType: EdgeExposedToInternet,
			Properties: map[string]string{"origin": edgeOrigin, "rule": "internet_reachability", "via": "aws_sg_unknown",
				asset.EdgePropPublicAccess: asset.PublicAccessPossible, "security_group": "", "ports": "all", "exposure_basis": basisRouteUnknown, "address_family": "ipv4"}}
		return n + 2600 + i, want, err
	default:
		return 0, asset.Edge{}, errors.New("unexpected edge family: " + edge.EdgeType)
	}
}

const boundedCostSeed = `INSERT INTO assets
 (id,name,type,provider,account_id,public_ip,tags,metadata,discovered_at,first_discovered_at,last_seen,synced_at)
 WITH ? AS revision,toDateTime64(?,9) AS stamp
 SELECT concat('bounded-vm-',leftPad(toString(number),9,'0')),concat('compute-',toString(number),'-v',toString(revision)),
 'ec2_instance','aws',concat('account-',toString(number%500)),concat('10.42.0.',toString(number%100+1)),
 map('environment','prod','unused',repeat('x',128)),
 toJSONString(map('iam_role_arn',concat('arn:aws:iam::999999999999:role/bounded-',leftPad(toString(if(revision=1,(number+1)%100,number%100)),3,'0')),
 'payload',repeat(hex(SHA256(toString(number))),if(number%100=0,256,4)))),
 stamp-INTERVAL 1 DAY,stamp-INTERVAL 1 DAY,stamp,stamp+toIntervalSecond(revision)
 FROM numbers(?) SETTINGS max_block_size=512`
