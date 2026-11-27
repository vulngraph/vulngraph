//go:build integration

package throughput

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/perfassurance"
)

const largeJoinFindings = `INSERT INTO findings
 (id,source,type,severity,title,description,resource_id,check_id,remediation,detected_at,last_observed_at,resolved_at,synced_at)
 SELECT concat('large-f-',toString(number)),if(number%100=1,'sample','noise'),'vulnerability',
 if(?=0,'low',if((number%100)%13=0,'critical','high')),'Large finding',
 repeat(hex(SHA256(toString(number))),if(number%100=0,256,4)),concat('resource-',toString(number%10000)),
 concat('large-check-',toString(number%100)),'fix',toDateTime(?)-toIntervalSecond(number%1000),toDateTime(?),
 if(?=2 AND number%17=0,toDateTime(?),toDateTime(0)),toDateTime64(?,9)
 FROM numbers(?) SETTINGS max_block_size=512`
const largeJoinEnrichment = `INSERT INTO finding_enrichment
 (id,score,score_band,known_exploited,enriched_at,owner_team,owner_source,environment)
 SELECT concat(if(number%19=0,'orphan-large-f-','large-f-'),toString(number)),toUInt8(90+number%10),'high',
 toUInt8(number%7=0),toDateTime64(?,3),concat('team-',toString((number+?)%23)),'tag','prod'
 FROM numbers(?)`
const largeJoinCounts = `SELECT
 (SELECT count() FROM findings FINAL),(SELECT count() FROM findings),
 (SELECT count() FROM finding_enrichment FINAL),(SELECT count() FROM finding_enrichment)`

// Full-table FINAL streams the fixture's stable sort keys. A global uniqExact
// check would itself retain millions of keys and crowd out the measured reads.
const largeJoinInventoryCounts = `SELECT
 (SELECT count() FROM assets FINAL),(SELECT count() FROM graph_edges FINAL),
 (SELECT count() FROM assets),(SELECT count() FROM graph_edges)`
const largeJoinCosts = `SELECT query,query_duration_ms,read_rows,read_bytes,memory_usage,exception,
 Settings['max_threads'],Settings['max_block_size'],ProfileEvents FROM system.query_log
 WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart')
 ORDER BY event_time_microseconds,query_id`

type largeJoinReport struct {
	MaxBaselineMemoryPercent  int                                  `json:"max_baseline_memory_percent,omitempty"`
	CandidateLifecycle        []string                             `json:"candidate_lifecycle,omitempty"`
	ResourceCohort            string                               `json:"resource_cohort"`
	CandidateSettings         map[string]any                       `json:"candidate_settings,omitempty"`
	OperationErrors           map[string]string                    `json:"operation_errors"`
	VerifiedSamples           []string                             `json:"verified_samples"`
	ObservedSettings          map[string]map[string]string         `json:"observed_settings"`
	FailureDrainSeconds       map[string]float64                   `json:"failure_drain_seconds"`
	Experiment                string                               `json:"experiment,omitempty"`
	Plans                     map[string][]string                  `json:"plans"`
	BaselineBudgetFailures    int                                  `json:"baseline_budget_failures"`
	Budgets                   map[string]perfassurance.QueryBudget `json:"cost_budgets"`
	AllocationBudget          uint64                               `json:"operation_allocation_budget_bytes"`
	FixtureVersion            int                                  `json:"fixture_version"`
	Source                    string                               `json:"source"`
	Platform                  string                               `json:"platform"`
	GoVersion                 string                               `json:"go_version"`
	Profile                   profile                              `json:"package_profile"`
	Findings                  uint64                               `json:"logical_findings"`
	Enrichment                uint64                               `json:"logical_enrichment"`
	Versions                  int                                  `json:"finding_enrichment_versions"`
	MembershipVersionFraction string                               `json:"additional_membership_versions"`
	AppConcurrency            int                                  `json:"application_query_concurrency"`
	SeedSeconds               float64                              `json:"seed_seconds"`
	Counts                    rowCounts                            `json:"inventory_counts"`
	InitialCounts             rowCounts                            `json:"inventory_counts_before_extra_versions"`
	Samples                   []perfassurance.QuerySample          `json:"samples"`
	OutputSHA256              map[string]string                    `json:"output_sha256"`
	Passed                    bool                                 `json:"passed"`
}

func largeJoinDataset(name string) (profile, uint64, error) {
	switch name {
	case "smoke":
		p, e := dataset("smoke")
		return p, 1000, e
	case "target":
		p, e := dataset("medium")
		return p, 100000, e
	case "large":
		p, e := dataset("20m")
		return p, 1000000, e
	case "stress-cardinality":
		// Matches the asset/finding/membership cardinalities only. This local
		// cohort does not stand in for the 128 GiB host, aged data or mixed load.
		return profile{Name: name, Workloads: 700000, Images: 35000, Groups: 70000, Packages: 55000, Memberships: 100000000}, 5000000, nil
	default:
		return profile{}, 0, fmt.Errorf("unknown large-join profile %q", name)
	}
}

func seedLargeJoins(ctx context.Context, ch *db.CH, p profile, n uint64, stamp int64, initial *rowCounts) error {
	for _, table := range []string{"assets", "graph_edges", "findings", "finding_enrichment"} {
		if err := ch.Exec(ctx, "SYSTEM STOP MERGES "+table); err != nil {
			return err
		}
	}
	if err := seed(ctx, ch, p, stamp); err != nil {
		return err
	}
	var err error
	*initial, err = boundedLargeJoinCounts(ctx, ch)
	if err != nil {
		return err
	}
	// The existing inventory fixture includes findings for pipeline tests. This
	// isolated cohort supplies its own independently specified finding population.
	for _, table := range []string{"findings", "finding_enrichment"} {
		if err := ch.Exec(ctx, "TRUNCATE TABLE "+table); err != nil {
			return err
		}
	}
	for v := 0; v < 3; v++ {
		at := stamp + int64(v)
		if err := ch.Exec(ctx, largeJoinFindings, v, stamp, at, v, at, at, n); err != nil {
			return fmt.Errorf("finding version %d: %w", v, err)
		}
		if err := ch.Exec(ctx, largeJoinEnrichment, at, v, n*5); err != nil {
			return fmt.Errorf("enrichment version %d: %w", v, err)
		}
		if v == 0 {
			continue
		}
		if err := ch.Exec(ctx, `INSERT INTO assets SELECT * REPLACE(toDateTime64(?,9) AS synced_at)
   FROM assets AS original WHERE original.type='package' AND toUInt64(extract(original.id,'bench-([0-9]+)'))%10=0 AND original.synced_at=toDateTime(?)`, at, stamp); err != nil {
			return err
		}
		if err := ch.Exec(ctx, `INSERT INTO graph_edges SELECT * REPLACE(toDateTime64(?,9) AS synced_at)
   FROM graph_edges AS original WHERE original.edge_type='runs_package' AND toUInt64(substring(original.src_id,7))%10=0 AND original.synced_at=toDateTime(?)`, at, stamp); err != nil {
			return err
		}
	}
	return nil
}

func boundedLargeJoinCounts(ctx context.Context, ch *db.CH) (rowCounts, error) {
	var c rowCounts
	err := ch.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing inventory fixture counts")
		}
		return rows.Scan(&c.Assets, &c.Edges, &c.AssetVersions, &c.EdgeVersions)
	}, largeJoinInventoryCounts)
	return c, err
}

// The oracle is row-wise Go, independent of either database's latest-row joins.
func largeJoinOracle(n uint64, stamp int64, source string) (finding.Summary, []finding.Cluster) {
	summary := finding.Summary{BySeverity: map[finding.Severity]int{}, ByBand: map[string]int{}, ByOwner: map[string]int{}, ByEnvironment: map[string]int{}}
	clusters := map[string]*finding.Cluster{}
	resources := map[string]map[string]bool{}
	for i := uint64(0); i < n; i++ {
		src := "noise"
		if i%100 == 1 {
			src = "sample"
		}
		if i%17 == 0 || (source != "" && src != source) {
			continue
		}
		severity := finding.SeverityHigh
		if (i%100)%13 == 0 {
			severity = finding.SeverityCritical
		}
		owner, env, band := "", "", ""
		score := uint8(0)
		kev := false
		if i%19 != 0 {
			owner = fmt.Sprintf("team-%d", (i+2)%23)
			env = "prod"
			band = "high"
			score = uint8(90 + i%10)
			kev = i%7 == 0
		}
		summary.Total++
		summary.BySeverity[severity]++
		summary.ByOwner[owner]++
		summary.ByEnvironment[env]++
		if band != "" {
			summary.ByBand[band]++
		}
		key := fmt.Sprintf("large-check-%d", i%100)
		c := clusters[key]
		if c == nil {
			c = &finding.Cluster{CheckID: key, Title: "Large finding", Severity: severity, Source: src, Remediation: "fix"}
			clusters[key] = c
			resources[key] = map[string]bool{}
		}
		c.Instances++
		resources[key][fmt.Sprintf("resource-%d", i%10000)] = true
		if score > c.MaxScore {
			c.MaxScore = score
			c.WorstBand = band
		}
		c.KnownExploited = c.KnownExploited || kev
		at := time.Unix(stamp-int64(i%1000), 0).UTC()
		if at.After(c.LastDetected) {
			c.LastDetected = at
		}
	}
	var out []finding.Cluster
	for key, c := range clusters {
		c.Resources = len(resources[key])
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CheckID < out[j].CheckID })
	return summary, out
}

func TestLargeJoinCosts(t *testing.T) {
	if os.Getenv("PERF_LARGE_JOIN_ISOLATED") != "1" {
		t.Skip("run scripts/benchmark-large-joins.sh")
	}
	p, n, err := largeJoinDataset(os.Getenv("PERF_JOIN_PROFILE"))
	require.NoError(t, err)
	ctx := t.Context()
	admin, err := perfassurance.OpenQueryStore(ctx, os.Getenv("PERF_CLICKHOUSE_URL"))
	require.NoError(t, err)
	defer admin.Close()
	adminURL, err := url.Parse(os.Getenv("PERF_CLICKHOUSE_URL"))
	require.NoError(t, err)
	appURL, err := url.Parse(os.Getenv("PERF_APP_CLICKHOUSE_URL"))
	require.NoError(t, err)
	require.Equal(t, adminURL.Host, appURL.Host)
	require.Equal(t, adminURL.Path, appURL.Path)
	app, err := db.NewCH(ctx, appURL.String(), 8)
	require.NoError(t, err)
	defer app.Close()
	report := largeJoinReport{FixtureVersion: 5, Source: os.Getenv("PERF_COMMIT"), Platform: runtime.GOOS + "/" + runtime.GOARCH, GoVersion: runtime.Version(), Profile: p, Findings: n, Enrichment: n * 5, Versions: 3, MembershipVersionFraction: "two extra versions for every tenth image and package", AppConcurrency: 8, OutputSHA256: map[string]string{}, Plans: map[string][]string{}, Experiment: os.Getenv("PERF_JOIN_EXPERIMENT"), OperationErrors: map[string]string{}, ObservedSettings: map[string]map[string]string{}}
	report.FailureDrainSeconds = map[string]float64{}
	report.ResourceCohort = os.Getenv("PERF_JOIN_RESOURCES")
	defer func() {
		report.Passed = !t.Failed()
		data, e := json.MarshalIndent(report, "", "  ")
		require.NoError(t, e)
		require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_QUERY_DIR"), "large-joins.json"), append(data, '\n'), 0o600))
	}()
	if report.Experiment == "latest_rows" && os.Getenv("PERF_JOIN_PROFILE") == "smoke" {
		report.CandidateLifecycle = checkLatestRowLifecycle(t, ctx, admin, app)
	}
	start := time.Now()
	stamp := start.Add(-time.Hour).Unix()
	require.NoError(t, seedLargeJoins(ctx, admin, p, n, stamp, &report.InitialCounts))
	report.SeedSeconds = time.Since(start).Seconds()
	report.Counts, err = boundedLargeJoinCounts(ctx, admin)
	require.NoError(t, err)
	require.Equal(t, p.coreNodes()+p.Packages, report.Counts.Assets)
	require.Equal(t, p.coreEdges()+p.Memberships, report.Counts.Edges)
	require.Equal(t, report.InitialCounts.AssetVersions+2*((p.Packages+9)/10), report.Counts.AssetVersions)
	require.Zero(t, p.Images%10, "membership-version oracle assumes image count divisible by ten")
	require.Equal(t, report.InitialCounts.EdgeVersions+2*((p.Memberships+9)/10), report.Counts.EdgeVersions)
	// Fix costs before the target/large runs; retain failures without relaxing them.
	report.Budgets = map[string]perfassurance.QueryBudget{
		"findings":     {Queries: 1, ReadRows: n * 36, ReadBytes: n * 4096, MemoryBytes: 512 << 20},
		"package-risk": {Queries: 1, ReadRows: 2 * (report.Counts.AssetVersions + report.Counts.EdgeVersions), ReadBytes: 256 * (report.Counts.AssetVersions + report.Counts.EdgeVersions), MemoryBytes: 512 << 20},
	}
	report.AllocationBudget = 64<<20 + p.Images*1024
	var f, fp, e, ep uint64
	require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
		if !rows.Next() {
			return fmt.Errorf("missing large fixture counts")
		}
		return rows.Scan(&f, &fp, &e, &ep)
	}, largeJoinCounts))
	require.Equal(t, n, f)
	require.Equal(t, n*3, fp)
	require.Equal(t, n*5, e)
	require.Equal(t, n*15, ep)
	logAccess := perfassurance.QueryLogAccess{Flush: func(ctx context.Context) error { return admin.Exec(ctx, "SYSTEM FLUSH LOGS") }, Select: largeJoinCosts}
	findingRepo := finding.NewCHRepo(app)
	assetRepo := asset.NewCHRepo(app)
	modes := []string{"baseline"}
	if report.Experiment == "enrichment_keys" || report.Experiment == "ordered" || report.Experiment == "ordered_blocks" || report.Experiment == "latest_rows" {
		modes = append(modes, "candidate")
	} else {
		require.Empty(t, report.Experiment)
	}
	if report.Experiment == "ordered" {
		report.CandidateSettings = map[string]any{"optimize_aggregation_in_order": 1}
	}
	if report.Experiment == "ordered_blocks" {
		// Ordered reads buffer blocks from multiple retained parts. Bound those
		// buffers as well as replacing aggregation hash state with ordered state.
		report.CandidateSettings = map[string]any{"optimize_aggregation_in_order": 1, "max_block_size": 4096}
	}
	if report.Experiment == "latest_rows" && n >= 100000 {
		// At target cardinality, query state dominates startup allocation noise.
		// Reject restoring the old shape; retain the absolute guard at every size.
		report.MaxBaselineMemoryPercent = 75
	}
	if os.Getenv("PERF_JOIN_MIXED_SECONDS") != "" {
		require.Contains(t, []string{"ordered_blocks", "latest_rows"}, report.Experiment)
		runConcurrentJoins(t, ctx, admin, app, p, n, stamp, report.CandidateSettings, report.Experiment)
		return
	}
	for _, source := range []string{"", "sample"} {
		wantSummary, wantClusters := largeJoinOracle(n, stamp, source)
		for _, kind := range []string{"summary", "clusters"} {
			name := "findings-" + kind + "-" + source
			for repeat := 0; repeat < 3; repeat++ {
				for _, mode := range modes {
					key := name + "-" + mode
					sampleName := fmt.Sprintf("%s-%d", key, repeat)
					sample, runErr := perfassurance.Measure(ctx, admin, logAccess, sampleName, func(ctx context.Context) error {
						// Match the repository's ten-second interactive deadline for the candidate.
						ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
						defer cancel()
						if mode == "candidate" && report.CandidateSettings != nil {
							ctx = app.WithQuerySettings(ctx, report.CandidateSettings)
						}
						var got, want any
						var callErr error
						if kind == "summary" {
							if mode == "candidate" && (report.Experiment == "enrichment_keys" || report.Experiment == "latest_rows") {
								got, callErr = readJoinSummaryCandidate(ctx, app, source, report.Experiment)
							} else if report.Experiment == "" {
								got, callErr = findingRepo.Summary(ctx, finding.Filter{Source: source})
							} else {
								got, callErr = readJoinSummaryCandidate(ctx, app, source, "baseline_rows")
							}
							want = wantSummary
						} else {
							var rows []finding.Cluster
							var total int
							if mode == "candidate" && (report.Experiment == "enrichment_keys" || report.Experiment == "latest_rows") {
								rows, total, callErr = readJoinClustersCandidate(ctx, app, source, report.Experiment)
							} else if report.Experiment == "" {
								rows, total, callErr = findingRepo.Clusters(ctx, finding.Filter{Source: source})
							} else {
								rows, total, callErr = readJoinClustersCandidate(ctx, app, source, "baseline_rows")
							}
							if callErr == nil && total != len(wantClusters) {
								return fmt.Errorf("cluster total %d != %d", total, len(wantClusters))
							}
							sort.Slice(rows, func(i, j int) bool { return rows[i].CheckID < rows[j].CheckID })
							for i := range rows {
								rows[i].LastDetected = rows[i].LastDetected.UTC()
							}
							got, want = rows, wantClusters
						}
						if callErr != nil {
							return callErr
						}
						if !reflect.DeepEqual(want, got) {
							return fmt.Errorf("independent %s output mismatch: got=%v want=%v", key, got, want)
						}
						encoded, e := json.Marshal(got)
						if e != nil {
							return e
						}
						report.OutputSHA256[sampleName] = fmt.Sprintf("%x", sha256.Sum256(encoded))
						return nil
					})
					if runErr != nil {
						drainStart := time.Now()
						if e := finishFailedJoinSample(ctx, admin, logAccess, &sample); e != nil {
							runErr = fmt.Errorf("%v; finish failed request: %w", runErr, e)
						}
						report.FailureDrainSeconds[sample.Name] = time.Since(drainStart).Seconds()
					}
					budgetErr := report.Budgets["findings"].Check(sample)
					if budgetErr == nil && runErr == nil && mode == "candidate" && source == "" && report.MaxBaselineMemoryPercent != 0 {
						baseline := report.Samples[len(report.Samples)-1]
						if _, failed := report.OperationErrors[baseline.Name]; !failed {
							var before, after uint64
							for _, q := range baseline.Queries {
								before = max(before, q.Memory)
							}
							for _, q := range sample.Queries {
								after = max(after, q.Memory)
							}
							if before == 0 || after*100 > before*uint64(report.MaxBaselineMemoryPercent) {
								budgetErr = fmt.Errorf("latest-row memory %d exceeds %d%% of baseline %d", after, report.MaxBaselineMemoryPercent, before)
							}
						}
					}
					if budgetErr == nil && sample.AllocatedBytes > report.AllocationBudget {
						budgetErr = fmt.Errorf("operation allocation %d > %d", sample.AllocatedBytes, report.AllocationBudget)
					}
					if runErr != nil {
						report.OperationErrors[sample.Name] = runErr.Error()
						t.Errorf("%s: %v", key, runErr)
					} else {
						report.VerifiedSamples = append(report.VerifiedSamples, sample.Name)
					}
					if budgetErr != nil {
						sample.BudgetError = budgetErr.Error()
						if mode == "baseline" && report.Experiment != "" {
							report.BaselineBudgetFailures++
						} else {
							t.Errorf("%s: %v", key, budgetErr)
						}
					}
					report.Samples = append(report.Samples, sample)
					require.NoError(t, admin.Select(ctx, func(rows driver.Rows) error {
						for rows.Next() {
							var settings map[string]string
							if e := rows.Scan(&settings); e != nil {
								return e
							}
							report.ObservedSettings[sample.Name] = settings
						}
						return rows.Err()
					}, `SELECT Settings FROM system.query_log WHERE log_comment=? AND type IN ('QueryFinish','ExceptionWhileProcessing','ExceptionBeforeStart')`, sample.Name))
					if mode == "candidate" && runErr == nil {
						for setting, value := range report.CandidateSettings {
							require.Equal(t, fmt.Sprint(value), report.ObservedSettings[sample.Name][setting], "candidate setting %s", setting)
						}
					}
					if _, ok := report.Plans[key]; !ok && len(sample.Queries) > 0 {
						planCtx := ctx
						if mode == "candidate" && report.CandidateSettings != nil {
							planCtx = admin.WithQuerySettings(ctx, report.CandidateSettings)
						}
						plan, e := perfassurance.Explain(planCtx, admin, sample.Queries[0].SQL)
						if e != nil {
							t.Errorf("explain %s: %v", key, e)
						} else {
							report.Plans[key] = plan
						}
					}
				}
			}
		}
	}

	for repeat := 0; repeat < 3; repeat++ {
		sample, err := perfassurance.Measure(ctx, admin, logAccess, fmt.Sprintf("correlation-package-risk-%d", repeat), func(ctx context.Context) error {
			got, err := assetRepo.PackageRiskByRunner(ctx)
			if err != nil {
				return err
			}
			if uint64(len(got)) != p.Images {
				return fmt.Errorf("runner count %d != %d", len(got), p.Images)
			}
			for i := uint64(0); i < p.Images; i++ {
				if got[fmt.Sprintf("image-%d", i)] != 80 {
					return fmt.Errorf("wrong package risk for image %d", i)
				}
			}
			encoded, err := json.Marshal(got)
			if err != nil {
				return err
			}
			report.OutputSHA256["correlation-package-risk"] = fmt.Sprintf("%x", sha256.Sum256(encoded))
			return nil
		})
		if err == nil {
			err = report.Budgets["package-risk"].Check(sample)
		}
		if err == nil && sample.AllocatedBytes > report.AllocationBudget {
			err = fmt.Errorf("operation allocation %d > %d", sample.AllocatedBytes, report.AllocationBudget)
		}
		if err != nil {
			sample.BudgetError = err.Error()
			t.Errorf("package risk: %v", err)
		}
		report.Samples = append(report.Samples, sample)
	}
}
