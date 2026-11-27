//go:build integration

package finding

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

const seedDashboardFixture = `INSERT INTO findings (id,source,type,severity,title,description,resource_id,check_id,remediation,detected_at,last_observed_at,synced_at)
 SELECT concat('query-f-',toString(number)),if(number%100=1,'sample','noise'),'exposure','high',concat('check-',toString(number%250)),
 repeat(hex(SHA256(toString(number))),256),concat('resource-',toString(number%1000)),concat(if(number%100=1,'sample-','noise-'),'check-',toString(number%250)),
 'fix',now()-toIntervalSecond(number%1000),now(),now64(9) FROM numbers(?) SETTINGS max_block_size=512`
const seedDashboardEnrichment = `INSERT INTO finding_enrichment (id,score,score_band,known_exploited,enriched_at,owner_team,owner_source,environment)
 SELECT concat('query-f-',toString(number)),toUInt8(number%100),'monitor',toUInt8(number%7=0),now64(3),'team','tag','prod'
 FROM numbers(?)`

func baselineDashboardSummary(ctx context.Context, ch *db.CH, query string, args ...any) (Summary, error) {
	out := newSummary()
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var severity, band, owner, env string
			var n uint64
			if err := rows.Scan(&severity, &band, &owner, &env, &n); err != nil {
				return err
			}
			out.add(Severity(severity), band, owner, env, int(n))
		}
		return rows.Err()
	}, query, args...)
	return out, err
}

func baselineDashboardClusters(ctx context.Context, ch *db.CH, query string, args ...any) ([]Cluster, int, error) {
	var out []Cluster
	var total uint64
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var c Cluster
			var severity string
			var kev uint8
			var instances, resources uint64
			if err := rows.Scan(&c.CheckID, &c.Title, &severity, &c.Source, &c.Remediation, &c.MaxScore, &c.WorstBand, &instances, &resources, &kev, &c.LastDetected, &total); err != nil {
				return err
			}
			c.Severity = Severity(severity)
			c.Instances = int(instances)
			c.Resources = int(resources)
			c.KnownExploited = kev != 0
			out = append(out, c)
		}
		return rows.Err()
	}, query, args...)
	return out, int(total), err
}
func sortDashboardClusters(rows []Cluster) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].CheckID < rows[j].CheckID })
}

func TestDashboardQueryCosts(t *testing.T) {
	if os.Getenv("PERF_QUERY_ISOLATED") != "1" {
		t.Skip("run scripts/benchmark-queries.sh")
	}
	n, err := strconv.Atoi(os.Getenv("PERF_QUERY_ROWS"))
	require.NoError(t, err)
	ctx := t.Context()
	ch, err := perfassurance.OpenQueryStore(ctx, os.Getenv("PERF_CLICKHOUSE_URL"))
	require.NoError(t, err)
	defer ch.Close()
	queryLog := perfassurance.QueryLogAccess{
		Flush: func(ctx context.Context) error { return ch.Exec(ctx, "SYSTEM FLUSH LOGS") },
		Select: `SELECT query, query_duration_ms, read_rows, read_bytes, memory_usage, exception, Settings['max_threads'], Settings['max_block_size'], ProfileEvents
 FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart') ORDER BY event_time_microseconds, query_id`,
	}
	r := perfassurance.QueryReport{Rows: n, Plans: map[string][]string{}}
	defer func() {
		r.Passed = !t.Failed()
		require.NoError(t, perfassurance.SaveQueryReport(os.Getenv("PERF_QUERY_DIR"), "dashboard", r))
	}()
	require.NoError(t, ch.Exec(ctx, seedDashboardFixture, n))
	require.NoError(t, ch.Exec(ctx, seedDashboardEnrichment, n*10))
	budget := perfassurance.QueryBudget{Queries: 1, ReadRows: uint64(n * 30), ReadBytes: uint64(n * 1024), MemoryBytes: 32<<20 + uint64(n)*2048}
	repo := NewCHRepo(ch)
	var wantRisk []ResourceRisk
	for i := 0; i < min(n, 1000); i++ {
		wantRisk = append(wantRisk, ResourceRisk{ResourceID: fmt.Sprintf("resource-%d", i), Risk: Risk{Count: n / 1000, MaxScore: uint8(i % 100), WorstBand: "monitor"}})
	}
	sort.Slice(wantRisk, func(i, j int) bool {
		a, b := wantRisk[i], wantRisk[j]
		if a.MaxScore != b.MaxScore {
			return a.MaxScore > b.MaxScore
		}
		return a.ResourceID > b.ResourceID
	})
	wantRisk = wantRisk[:min(100, len(wantRisk))]
	r.Plans["riskiest-resources"], err = perfassurance.Explain(ctx, ch, riskiestResources, 100)
	require.NoError(t, err)
	for repeat := 0; repeat < 3; repeat++ {
		sample, err := perfassurance.Measure(ctx, ch, queryLog, fmt.Sprintf("riskiest-resources-%d", repeat), func(ctx context.Context) error {
			got, err := repo.RiskiestResources(ctx, 100)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(wantRisk, got) {
				return fmt.Errorf("independent risk rollup mismatch")
			}
			return nil
		})
		r.Samples = append(r.Samples, sample)
		require.NoError(t, err)
		require.NoError(t, budget.Check(sample))
	}

	for _, source := range []string{"", "sample"} {
		where := ""
		var args []any
		if source != "" {
			where = "WHERE source = ?"
			args = append(args, source)
		}
		summaryQ := fmt.Sprintf(baselineSummaryOpenFindings, where)
		clusterQ := fmt.Sprintf(baselineClustersByCheck, where)
		clusterArgs := append(append([]any{}, args...), clusterLimit)
		want, err := baselineDashboardSummary(ctx, ch, summaryQ, args...)
		require.NoError(t, err)
		expected := n
		if source != "" {
			expected = n / 100
		}
		require.Equal(t, expected, want.Total)
		require.Equal(t, expected, want.BySeverity[SeverityHigh])
		require.Equal(t, expected, want.ByOwner["team"])
		wantClusters, total, err := baselineDashboardClusters(ctx, ch, clusterQ, clusterArgs...)
		require.NoError(t, err)
		sortDashboardClusters(wantClusters)
		count := 0
		for _, c := range wantClusters {
			count += c.Instances
		}
		require.Equal(t, expected, count)
		for _, kind := range []string{"summary", "clusters"} {
			label := "dashboard-" + kind + "-" + source
			q := summaryQ
			qa := args
			if kind == "clusters" {
				q = clusterQ
				qa = clusterArgs
			}
			r.Plans[label], err = perfassurance.Explain(ctx, ch, q, qa...)
			require.NoError(t, err)
			for repeat := 0; repeat < 3; repeat++ {
				for _, candidate := range []bool{false, true} {
					mode := "baseline"
					if candidate {
						mode = "candidate"
					}
					sample, err := perfassurance.Measure(ctx, ch, queryLog, fmt.Sprintf("%s-%s-%d", label, mode, repeat), func(ctx context.Context) error {
						if kind == "summary" {
							var got Summary
							var err error
							if candidate {
								got, err = repo.Summary(ctx, Filter{Source: source})
							} else {
								got, err = baselineDashboardSummary(ctx, ch, summaryQ, args...)
							}
							if err != nil {
								return err
							}
							if !reflect.DeepEqual(want, got) {
								return fmt.Errorf("summary parity mismatch")
							}
							return nil
						}
						var got []Cluster
						var gotTotal int
						var err error
						if candidate {
							got, gotTotal, err = repo.Clusters(ctx, Filter{Source: source})
						} else {
							got, gotTotal, err = baselineDashboardClusters(ctx, ch, clusterQ, clusterArgs...)
						}
						if err != nil {
							return err
						}
						for i := 1; i < len(got); i++ {
							if got[i].MaxScore > got[i-1].MaxScore || got[i].MaxScore == got[i-1].MaxScore && got[i].Instances > got[i-1].Instances {
								return fmt.Errorf("cluster ranking mismatch")
							}
						}
						sortDashboardClusters(got)
						if gotTotal != total || !reflect.DeepEqual(wantClusters, got) {
							return fmt.Errorf("cluster parity mismatch")
						}
						return nil
					})
					r.Samples = append(r.Samples, sample)
					require.NoError(t, err)
					require.NoError(t, budget.Check(sample))
				}
			}
		}
	}
}
