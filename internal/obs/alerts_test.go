package obs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// rulesPath is the alert-rule file the chart renders into the VMRule CR.
const rulesPath = "../../deploy/helm-chart/graph/alerts/rules.yaml"

// vmrulePath is the template that renders it.
const vmrulePath = "../../deploy/helm-chart/graph/templates/vmrule.yaml"

type alertRuleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Expr        string            `yaml:"expr"`
			For         string            `yaml:"for"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

// emittableMetricNames returns every series name this package can put on the
// wire, gathered from a registry that has been made to emit all of them: every
// live-gauge source wired with one row, and every Observe* helper called once.
//
// Gathering, rather than reading the Desc list, is the point. A CounterVec with
// no children describes itself but exports nothing, so a name taken from
// Describe can still be a name no scrape ever sees.
func emittableMetricNames(t *testing.T) map[string]bool {
	t.Helper()

	m := New()
	m.RegisterSources(Sources{
		QueueDepth: func(context.Context) []QueueStat { return []QueueStat{{Queue: "q", State: "available", N: 1}} },
		Connectors: func(context.Context) []ConnectorStat { return []ConnectorStat{{Name: "c"}} },
		AssetStaleness: func(context.Context) []AssetStalenessStat {
			return []AssetStalenessStat{{Provider: "aws", Total: 2, Stale: 1}}
		},
		ConnectorCoverage: func(context.Context) []ConnectorCoverageStat {
			return []ConnectorCoverageStat{{Provider: "aws", Dimension: "account_id", Seen: 2, Configured: 1}}
		},
		Unenriched: func(context.Context) []UnenrichedStat { return []UnenrichedStat{{Severity: "critical", N: 1}} },
		Unclassified: func(context.Context) []UnclassifiedStat {
			return []UnclassifiedStat{{Source: "cspm", Blank: 1, Classified: 1}}
		},
		CheckQuality: func(context.Context) []CheckQualityStat {
			return []CheckQualityStat{{CheckID: "c1", Source: "cspm", JunkRate: 0.5, Measurable: true}}
		},
		SourceActivity: func(context.Context) []SourceActivityStat {
			return []SourceActivityStat{{Source: "nuclei", LastActivityUnix: 1720000000}}
		},
		OSVScanStaleness: func(context.Context) []OSVScanStalenessStat {
			return []OSVScanStalenessStat{{TotalPackages: 2, NeverScanned: 1, OldestScannedAt: 1720000000}}
		},
		ImageScanCoverage: func(context.Context) []ImageScanCoverageStat {
			return []ImageScanCoverageStat{{
				TrackedDigests: 2, NeverScanned: 1, CoveredRecent: 1, OldestScannedAt: 1720000000,
			}}
		},
		FindingAge: func(context.Context) []FindingAgeStat {
			return []FindingAgeStat{{Preserved: 1, Missing: 0, OldestSeconds: 1}}
		},
		Migration: func(context.Context) []MigrationStat {
			return []MigrationStat{{DB: "postgres", Applied: 1, Target: 1, Pending: false}}
		},
		QueueOldestAvailable: func(context.Context) []QueueAgeStat {
			return []QueueAgeStat{{Queue: "q", OldestAvailableSeconds: 1}}
		},
		Graph: func() GraphStats {
			reach := true
			return GraphStats{
				Nodes: 1, NodeBudget: 250000, LastBuiltUnix: 1720000000, ReachComplete: &reach,
				TruncatedEdgeTypes: []string{"dns_points_to"},
				ReachRateReachable: 1, ReachRateTotal: 2,
				EdgeTypeParity: []EdgeTypeParityStat{{EdgeType: "has_role", Fetched: 1, Loaded: 1}},
				NodeTableRows:  map[string]int64{"Package": 131073}, NodeGroupRows: 131072,
			}
		},
	})
	m.ObserveJob("sync", "SyncWorker", "ok", 0.1)
	m.ObserveRebuild(1)
	m.ObserveFeedRefresh("kev", 1720000000)
	m.ObserveAdjudication("agreed", 1)
	m.ObserveConsistencyViolation("inv1_identity_zero_hop", 1)
	m.ObserveSweep("dangling", "scanned", 1)
	m.ObserveSweepResolved("dangling", 1720000000)
	m.ObserveLadybugSync("full", 400)
	m.ObserveLadybugSync("noop", 1)
	m.ObserveLadybugPhase("copy", 53)
	m.ObserveCorrelateSweep("full", "ok")
	m.ObserveCorrelateFullSuccess(1720000000)
	m.ObserveCorrelateView(490258, 600000)
	m.ObserveScopeCompletions("aws-1", []ScopeCompletion{{Scope: "eu-west-1/ec2:instances", Count: 3}}, 1720000000)
	m.ObserveDeletionCandidates("aws-1", 4, false)
	m.ObserveGraphTierFallthrough("seed")
	m.ObserveCostCollect("permission_denied")
	m.ObserveCostCollectSuccess("aws-1", 1720000000, 120)
	m.ObserveNotifyDelivery("chan-1", "slack", "finding", "ok")

	families, err := m.Registry().Gather()
	require.NoError(t, err)

	names := map[string]bool{}
	for _, f := range families {
		name := f.GetName()
		names[name] = true
		// Histograms are queried by their derived series, never the base name.
		if f.GetType() == dto.MetricType_HISTOGRAM {
			for _, suffix := range []string{"_bucket", "_sum", "_count"} {
				names[name+suffix] = true
			}
		}
	}
	return names
}

// metricRef matches a graph_-prefixed identifier in a PromQL expression. Every
// series this platform emits carries that namespace prefix, so anything else in
// an expression is a function, a label or a literal and is not ours to check.
var metricRef = regexp.MustCompile(`graph_[a-z0-9_]+`)

func loadAlertRules(t *testing.T) alertRuleFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(rulesPath))
	require.NoError(t, err, "alert rules must be readable from the obs package")
	var f alertRuleFile
	require.NoError(t, yaml.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Groups)
	return f
}

// TestAlertRulesReferenceOnlyEmittableMetrics binds the alert rules to the
// metrics this package emits. An alert on a metric name that does not exist is accepted by
// vmalert, evaluates to an empty vector forever, and never fires or complains —
// which is indistinguishable from a healthy system. Renaming a metric in
// metrics.go without updating the rules fails here instead of silently.
func TestAlertRulesReferenceOnlyEmittableMetrics(t *testing.T) {
	emittable := emittableMetricNames(t)
	seen := map[string]bool{}

	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			for _, ref := range metricRef.FindAllString(r.Expr, -1) {
				seen[ref] = true
				require.Truef(t, emittable[ref],
					"alert %s references %q, which no code path in internal/obs emits — it would never fire",
					r.Alert, ref)
			}
		}
	}
	require.NotEmpty(t, seen, "the rules must actually reference graph_ metrics")
}

// Metric-name references may also appear in an annotation's prose, where a typo
// misleads whoever is woken up. Cheap to check, so checked.
func TestAlertAnnotationsNameRealMetrics(t *testing.T) {
	emittable := emittableMetricNames(t)
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			for _, text := range r.Annotations {
				for _, ref := range metricRef.FindAllString(text, -1) {
					require.Truef(t, emittable[ref],
						"alert %s names %q in an annotation, which is not a metric this binary emits", r.Alert, ref)
				}
			}
		}
	}
}

// Every rule must be complete enough to act on: a severity for routing, a
// duration so a single bad scrape cannot page, and prose saying what broke.
func TestAlertRulesAreWellFormed(t *testing.T) {
	names := map[string]bool{}
	for _, g := range loadAlertRules(t).Groups {
		require.NotEmpty(t, g.Name)
		for _, r := range g.Rules {
			require.NotEmpty(t, r.Alert, "group %s has an unnamed rule", g.Name)
			require.False(t, names[r.Alert], "duplicate alert name %s", r.Alert)
			names[r.Alert] = true
			require.NotEmpty(t, r.Expr, "%s has no expression", r.Alert)
			require.NotEmpty(t, r.For, "%s has no for: — one bad scrape would page", r.Alert)
			require.Containsf(t, []string{"critical", "warning"}, r.Labels["severity"],
				"%s must carry a routable severity", r.Alert)
			// Routing labels are the operator's (alerts.labels, merged into
			// every rule by templates/vmrule.yaml). A rule that sets one of
			// its own overrides that value for itself alone.
			for k := range r.Labels {
				require.Equalf(t, "severity", k,
					"%s sets label %q; routing labels come from alerts.labels, so one here overrides the operator's routing for this rule only", r.Alert, k)
			}
			require.NotEmpty(t, r.Annotations["summary"], "%s has no summary", r.Alert)
			require.NotEmpty(t, r.Annotations["description"], "%s has no description", r.Alert)
			require.Containsf(t, r.Expr, `namespace="__NAMESPACE__"`,
				"%s must scope to the release namespace placeholder the chart substitutes", r.Alert)
		}
	}
	require.NotEmpty(t, names)
}

// Alertmanager routes on the FIRED alert's own labels, never on the VMRule
// CR's Kubernetes metadata, which vmalert does not propagate. So the routing
// labels an operator sets (alerts.labels) must be merged into every rule's
// labels, or each alert falls through to the default receiver.
func TestAlertRoutingLabelsReachEveryRule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(vmrulePath))
	require.NoError(t, err)
	tpl := string(raw)
	require.Contains(t, tpl, "range $k, $v := .Values.alerts.labels")
	require.Contains(t, tpl, `{{- $_ := set . "labels" (merge (dict) (.labels | default dict) $alertLabels) }}`,
		"every rule's labels must take alerts.labels")
	require.Contains(t, tpl, "toYaml $rules", "the CR must carry the rules with the merged labels")
	require.NotContains(t, tpl, `.Files.Get "alerts/rules.yaml" | replace "__NAMESPACE__" .Release.Namespace | nindent`,
		"the rules file is emitted raw, without the merged labels")
}

// criticalAlertsAllowlist is the deliberate-exception list the rules.yaml
// header comment describes: alert names permitted to carry severity:critical
// despite the file's default. See TestNoRuleIsCriticalWithoutJustification.
//
// GraphServeNotReady / GraphWorkerOrScannerNotReady are total user-facing
// outages, not internal pipeline-health signals, which is the on-call
// exception the rules.yaml header carves out.
var criticalAlertsAllowlist = map[string]bool{
	"GraphServeNotReady":           true,
	"GraphWorkerOrScannerNotReady": true,
}

// TestNoRuleIsCriticalWithoutJustification keeps every rule at severity:warning
// unless allowlisted: severity:critical typically routes to an on-call channel,
// which is noisy for an internal pipeline-health signal and worse for a flapping
// alert. This stops a new rule from defaulting to critical without a
// deliberate, allowlisted reason.
func TestNoRuleIsCriticalWithoutJustification(t *testing.T) {
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Labels["severity"] == "critical" {
				require.Truef(t, criticalAlertsAllowlist[r.Alert],
					"%s is severity:critical, which typically routes to an on-call channel — "+
						"add it to criticalAlertsAllowlist with a reason "+
						"if that is deliberate, otherwise use warning", r.Alert)
			}
		}
	}
}

// The rules file header is what an operator reads to wire Alertmanager routes,
// so its severity paragraph must name exactly the rules that are critical.
func TestRulesHeaderNamesEveryCriticalRule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(rulesPath))
	require.NoError(t, err)
	header, _, ok := strings.Cut(string(raw), "\ngroups:\n")
	require.True(t, ok, "rules.yaml has no top-level groups: key")
	_, para, ok := strings.Cut(header, "# Severity convention:")
	require.True(t, ok, "the rules.yaml header has no severity convention paragraph")
	para, _, _ = strings.Cut(para, "\n#\n")

	named := map[string]bool{}
	for _, name := range regexp.MustCompile(`\bGraph[A-Za-z]+\b`).FindAllString(para, -1) {
		named[name] = true
	}
	critical := map[string]bool{}
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Labels["severity"] == "critical" {
				critical[r.Alert] = true
			}
		}
	}
	require.NotEmpty(t, critical)
	require.Equal(t, critical, named,
		"the rules.yaml severity convention must name every severity:critical rule and no other")
}

// The label-mismatch alarm must not sum label_mismatch together with
// endpoint_absent, which is permanent expected attrition — doing so fires on
// every build and means nothing.
func TestEdgeParityAlertExcludesEndpointAbsent(t *testing.T) {
	var expr string
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Alert == "GraphLadybugEdgeLabelMismatch" {
				expr = r.Expr
			}
		}
	}
	require.NotEmpty(t, expr, "GraphLadybugEdgeLabelMismatch must exist")
	require.Contains(t, expr, `outcome="label_mismatch"`)
	require.NotContains(t, expr, "endpoint_absent")
}

// The dangling-endpoint alarm must read the worker's verdict, not the raw
// counter. The budget is declared per edge type in internal/graphschema
// (DanglingBudget) — an expression that re-derives the threshold in PromQL is
// a second copy of a declared number. The worker publishes
// graph_ladybug_edge_dangling_over_budget already evaluated.
//
// It must also never read endpoint_expired: that outcome is edges to
// ephemeral resources that no longer exist, which is expected attrition and
// would fire on every build.
func TestDanglingBudgetAlertReadsTheWorkerVerdict(t *testing.T) {
	var expr string
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Alert == "GraphLadybugEdgeDanglingOverBudget" {
				expr = r.Expr
			}
		}
	}
	require.NotEmpty(t, expr, "GraphLadybugEdgeDanglingOverBudget must exist")
	require.Contains(t, expr, "graph_ladybug_edge_dangling_over_budget",
		"the declared budget lives in internal/graphschema — the rule must read the verdict, not re-derive the threshold")
	require.NotContains(t, expr, "endpoint_expired",
		"an expired ephemeral endpoint is a corpse edge, not a loss; alarming on it fires on every build forever")
}

// The expired-share step alarm must, symmetrically, read the worker's verdict
// on the step rather than re-deriving it in PromQL — the step budget lives in
// internal/graphschema (ExpiredShareStepBudget). It must also never alarm on a
// level (an absolute outcome="endpoint_expired" comparison): that level is
// legitimately near 100% for some edge types by design, so a level-based
// expression would fire permanently.
func TestExpiredShareStepAlertReadsTheWorkerVerdict(t *testing.T) {
	var expr string
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Alert == "GraphLadybugEdgeExpiredShareStepChange" {
				expr = r.Expr
			}
		}
	}
	require.NotEmpty(t, expr, "GraphLadybugEdgeExpiredShareStepChange must exist")
	require.Contains(t, expr, "graph_ladybug_edge_expired_share_step_change",
		"the declared step budget lives in internal/graphschema — the rule must read the worker's verdict, not re-derive it")
	require.NotContains(t, expr, "endpoint_expired",
		"a level comparison on endpoint_expired is the permanently-firing shape this alert replaces")
}

// nuclei is excluded from the must-fix coverage alert:
// its blank ratio is near 100% by design, so including it would fire permanently
// and bury every source whose coverage gap is real.
func TestMustFixCoverageAlertExcludesNuclei(t *testing.T) {
	var expr string
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Alert == "GraphMustFixClassAllBlank" {
				expr = r.Expr
			}
		}
	}
	require.NotEmpty(t, expr, "GraphMustFixClassAllBlank must exist")
	require.Equal(t, strings.Count(expr, "graph_findings_must_fix_class"),
		strings.Count(expr, `source!="nuclei"`),
		"every must_fix_class selector in this rule must exclude nuclei")
}

// TestCheckJunkRateAlertExcludesGuardDuty: aws_guardduty findings have no
// coded "fixed" path anywhere in this codebase, so the junk ratio is
// mathematically guaranteed to sit near 1.0 forever, independent of real
// detection quality — same shape as nuclei's exclusion above.
func TestCheckJunkRateAlertExcludesGuardDuty(t *testing.T) {
	var expr string
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Alert == "GraphCheckJunkRateHigh" {
				expr = r.Expr
			}
		}
	}
	require.NotEmpty(t, expr, "GraphCheckJunkRateHigh must exist")
	require.Equal(t, strings.Count(expr, "graph_check_junk_rate")+strings.Count(expr, "graph_check_quality_measurable"),
		strings.Count(expr, `source!="aws_guardduty"`),
		"every junk-rate/measurable selector in this rule must exclude aws_guardduty")
}

// TestCheckJunkRateAlertExcludesEveryNoFixedPathSource excludes every source
// that shares aws_guardduty's structural gap: no coded "fixed" resolution
// path anywhere in this codebase, so its junk rate is mathematically
// guaranteed to eventually hit this alert's threshold regardless of real
// detection quality. iac_terraform and the GHAS sources are intentionally NOT
// in this list: they have a real fixed-path and must stay measured.
func TestCheckJunkRateAlertExcludesEveryNoFixedPathSource(t *testing.T) {
	var expr string
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if r.Alert == "GraphCheckJunkRateHigh" {
				expr = r.Expr
			}
		}
	}
	require.NotEmpty(t, expr, "GraphCheckJunkRateHigh must exist")
	for _, source := range []string{"gcp_scc", "iac", "nuclei", "ci_access"} {
		require.Equal(t, 2, strings.Count(expr, `source!="`+source+`"`),
			"both the junk-rate and measurable selectors must exclude %q, a source with no coded fixed-path", source)
	}
	require.NotContains(t, expr, `source!="iac_terraform"`,
		"iac_terraform has a real fixed-path (sync_lifecycle.go) and must stay measured, unlike plain iac")
	require.NotContains(t, expr, `source!="ghas_`,
		"GHAS findings close as fixed or manual when GitHub closes the alert, so they must stay measured")
}

// A metric nothing alerts on is a metric nobody reads. This does not demand a
// rule per series — several are denominators or context for another rule — but
// it does demand that each is deliberately one or the other, so that adding a
// gauge and forgetting to consume it cannot pass review silently.
func TestEveryEmittedMetricIsAlertedOnOrConsciouslyNot(t *testing.T) {
	// Metrics that exist to be read next to an alert, not to fire one.
	contextOnly := map[string]bool{
		// Latency detail with no agreed SLO; the outcome, not the shape, is alerted.
		"graph_job_duration_seconds":                    true,
		"graph_job_duration_seconds_bucket":             true,
		"graph_job_duration_seconds_sum":                true,
		"graph_job_duration_seconds_count":              true,
		"graph_ladybug_rebuild_duration_seconds":        true, // GraphLadybugRebuildStalled alerts the outcome
		"graph_ladybug_rebuild_duration_seconds_bucket": true,
		"graph_ladybug_rebuild_duration_seconds_sum":    true,
		"graph_ladybug_rebuild_duration_seconds_count":  true,
		// The phase decomposition of the same rebuild. Deliberately not alerted: the
		// per-phase shape has no SLO, and the outcome is already alerted on the
		// total by GraphLadybugRebuildStalled. This exists so "the rebuild got
		// slower" can be answered without a code read.
		"graph_ladybug_rebuild_phase_seconds":        true,
		"graph_ladybug_rebuild_phase_seconds_bucket": true,
		"graph_ladybug_rebuild_phase_seconds_sum":    true,
		"graph_ladybug_rebuild_phase_seconds_count":  true,
		// A six-figure aggregate in which one edge type losing every row is
		// invisible — that is why graph_ladybug_edge_type_rows exists and is what
		// GraphLadybugEdgeLabelMismatch/StoppedLoading read instead. edges_loaded is
		// NOT here: a collapse of the total is visible in the aggregate, and
		// GraphLadybugEdgeVolumeCollapse reads it.
		"graph_ladybug_edges_dropped": true,
		// Read next to GraphLadybugPublishRefused, which fires on the counter. This gauge
		// answers "is it refusing right now or did it refuse once last week", which a
		// lifetime counter cannot — it is the diagnostic, not the trigger.
		"graph_ladybug_last_publish_refusal_timestamp_seconds": true,
		// The signed magnitude behind GraphLadybugEdgeExpiredShareStepChange, which
		// fires on the paired boolean gauge (graph_ladybug_edge_expired_share_step_change).
		// This is the diagnostic a human reads once that alert fires, not a trigger
		// itself — a magnitude has no single alertable sign or threshold on its own.
		"graph_ladybug_edge_expired_share_step_delta": true,
		// Denominators and diagnostics read next to the rule that fires.
		"graph_check_resolutions":                     true,
		"graph_metrics_source_age_seconds":            true,
		"graph_sweep_last_resolved_timestamp_seconds": true, // GraphSweepScansButNeverResolves says it with increase()
		// Denominator for the OSV coverage pair, and the never-scanned count it
		// explains. Not alerted directly: it shares the irreducible-floor shape
		// with graph_image_scan_never_scanned below, so a bare threshold fires
		// permanently. GraphOSVScanCoverageStale carries the alertable half.
		"graph_osv_scan_total_packages": true,
		"graph_osv_scan_never_scanned":  true,
		// Denominator for the image-scan coverage pair, and the never-scanned
		// count it explains. Deliberately not alerted on: never_scanned has a
		// large irreducible floor (pull-denied/keychain-less images), so any
		// absolute threshold fires permanently and no ratio baseline is agreed
		// yet. GraphImageScanDark and GraphImageScanCoverageStale carry the
		// alertable half.
		"graph_image_scan_tracked_digests": true,
		"graph_image_scan_never_scanned":   true,
		// No agreed hit-ratio SLO exists yet for planFor's LLM-skip rate. Read
		// next to reasoning cost/latency until one exists.
		"graph_reasoncache_lookups_total": true,
		// The observe-only deletion signal (metrics_deletion.go). Deliberately
		// not alerted on: on early sweeps the partial-completeness candidate
		// count reads high on large cloud connectors, which is the current,
		// expected state while the platform cannot yet forget anything. A rule
		// lands with enforce mode, not before it.
		"graph_sync_deletion_candidates":                   true,
		"graph_sync_scope_enumerated_assets":               true,
		"graph_sync_scope_last_complete_timestamp_seconds": true,
		// Deliberately not alerted: a nonzero rate is the expected steady state
		// (Ladybug is a filtered projection, so an ID-keyed lookup of a pruned asset
		// legitimately falls through to ClickHouse), and there is no total-lookups
		// denominator to turn it into a ratio. Its value is the opposite
		// direction — a flat zero on graph-serve means the emptiness check isn't
		// being reached, which is a regression to read here, not page on.
		"graph_explore_tier_empty_fallthrough_total": true,
		// The per-connector diagnostic read next to GraphCostCollectionDark and
		// GraphCostCollectStoresNothing, which fire on graph_cost_collect_total. A
		// gauge that is absent until the first success cannot carry the alert
		// itself — absent() over many connector label sets says "never worked"
		// for the whole fleet from one missing series. This answers "which
		// account last collected, and when".
		"graph_cost_last_success_timestamp_seconds": true,
		// graph_finding_age_preserved and graph_finding_age_oldest_seconds are
		// trend/diagnostic reads with no threshold groundable today: Preserved
		// only becomes nonzero once a ClickHouse background merge collapses old
		// row versions, with no measured cadence to size an "inert" threshold
		// against; OldestSeconds legitimately starts nonzero for sources with
		// upstream history and is meant to be read as a trend. graph_finding_age_missing
		// is NOT here — it has an unconditional expected value of 0, so a bare
		// >0 is a real invariant (GraphFindingAgeMissing).
		"graph_finding_age_preserved":      true,
		"graph_finding_age_oldest_seconds": true,
		// graph_migration_applied_version/graph_migration_target_version are the
		// raw diagnostic pair behind GraphMigrationPending, which alerts on the
		// derived graph_migration_pending boolean instead — kept as their own
		// series so "which version is this db on" survives a change to the
		// alert's comparison logic.
		"graph_migration_applied_version": true,
		"graph_migration_target_version":  true,
		// The per-table counts and the node-group size behind
		// GraphLadybugMultiHopMayBeIncomplete, which fires on the derived boolean.
		"graph_ladybug_node_table_rows": true,
		"graph_ladybug_node_group_rows": true,
	}

	referenced := map[string]bool{}
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			for _, ref := range metricRef.FindAllString(r.Expr, -1) {
				referenced[ref] = true
			}
		}
	}

	var orphans []string
	for name := range emittableMetricNames(t) {
		if !strings.HasPrefix(name, "graph_") || referenced[name] || contextOnly[name] {
			continue
		}
		orphans = append(orphans, name)
	}
	sort.Strings(orphans)
	require.Emptyf(t, orphans,
		"these metrics are emitted but neither alerted on nor listed as context-only: %v", orphans)
}

// workerOnlyMetricNames are graph_* series this binary emits from exactly one
// place: the worker process (cmd/graph/worker.go, worker_metrics.go's
// registerMetricsSources, and the periodic jobs registered only by
// jobs.NewClient there). This is the registry
// TestAlertRulesWrapInstantVectorsAgainstRestartGap is built from — membership
// is determined by reading who calls RegisterSources/ObserveXxx/SetXxx, never
// by grepping an alert's own label selector text, which a differently-spelled
// selector (or none at all) can dodge.
//
// Deliberately excluded, and why:
//   - graph_ladybug_node_count / graph_ladybug_node_budget /
//     graph_ladybug_last_built_timestamp_seconds: serve.go's own RegisterSources
//     call wires a Graph source too (Nodes/NodeBudget/LastBuiltUnix only), so
//     these are genuinely multi-component, not worker-exclusive — a worker
//     restart does not blank them, serve's own copy keeps reporting.
//   - graph_ladybug_sync_total / graph_ladybug_rebuild_duration_seconds* /
//     graph_ladybug_rebuild_phase_seconds*: svc.WithSyncMetrics(metrics) is
//     called from BOTH cmd/graph/worker.go and cmd/graph/serve.go.
//   - graph_connector_stale / graph_river_queue_depth: Connectors/QueueDepth
//     sources are registered in BOTH worker_metrics.go and serve.go.
//   - graph_cost_collect_total / graph_cost_last_success_timestamp_seconds /
//     graph_cost_snapshot_rows_written_total: the cost-collect loop lives in
//     cmd/graph/serve.go, not the worker — SERVE-only, not worker/scanner.
//   - graph_explore_tier_empty_fallthrough_total: ObserveGraphTierFallthrough
//     is only ever called from internal/app/explore's tiered/fallback repos,
//     which serve.go wires — SERVE-only.
//   - graph_job_runs_total / graph_job_duration_seconds: ObserveJob runs from
//     BOTH worker.go's and scanner.go's River client middleware.
//   - graph_metrics_source_up / graph_metrics_source_age_seconds: emitted by
//     whichever pod's liveCollector actually read a given named source, and
//     both worker and serve populate distinct source names — multi-component
//     by construction, verified rather than assumed (GraphMetricsSourceFailing
//     is already max_over_time-wrapped regardless, so this has no effect on
//     it either way).
var workerOnlyMetricNames = map[string]bool{
	// registerMetricsSources (cmd/graph/worker_metrics.go) — wired only from
	// cmd/graph/worker.go.
	"graph_asset_total":                                 true,
	"graph_asset_stale":                                 true,
	"graph_connector_coverage_seen":                     true,
	"graph_connector_coverage_configured":               true,
	"graph_findings_unenriched":                         true,
	"graph_findings_must_fix_class":                     true,
	"graph_check_junk_rate":                             true,
	"graph_check_resolutions":                           true,
	"graph_check_quality_measurable":                    true,
	"graph_finding_age_preserved":                       true,
	"graph_finding_age_missing":                         true,
	"graph_finding_age_oldest_seconds":                  true,
	"graph_osv_scan_total_packages":                     true,
	"graph_osv_scan_never_scanned":                      true,
	"graph_osv_scan_oldest_scanned_timestamp_seconds":   true,
	"graph_image_scan_tracked_digests":                  true,
	"graph_image_scan_never_scanned":                    true,
	"graph_image_scan_covered_recent":                   true,
	"graph_image_scan_oldest_scanned_timestamp_seconds": true,
	"graph_source_last_activity_timestamp_seconds":      true,

	// Graph() fields the worker's callback populates from graphstore.Service,
	// gated in liveCollector.Collect (metrics.go) behind `g.ReachComplete !=
	// nil` or a non-empty g.EdgeTypeParity/TruncatedEdgeTypes — serve's own
	// Graph() callback never sets any of these (see the exclusion note above),
	// so they are absent entirely from serve's series, not merely zero.
	"graph_ladybug_reach_edges_untruncated":                true,
	"graph_ladybug_edge_fetch_complete":                    true,
	"graph_ladybug_asset_fetch_complete":                   true,
	"graph_ladybug_publish_refused_total":                  true,
	"graph_ladybug_publish_degraded_accepted_total":        true,
	"graph_ladybug_last_publish_refusal_timestamp_seconds": true,
	"graph_ladybug_edge_cap_hit":                           true,
	"graph_ladybug_edges_loaded":                           true,
	"graph_ladybug_edges_dropped":                          true,
	"graph_ladybug_identity_zero_hop":                      true,
	"graph_ladybug_edge_type_rows":                         true,
	"graph_ladybug_edge_dangling_over_budget":              true,
	"graph_ladybug_edge_expired_share_step_change":         true,
	"graph_ladybug_edge_expired_share_step_delta":          true,
	"graph_ladybug_reachability_rate":                      true,

	// Inline Observe*/Set* calls wired only from worker-side code: periodic
	// jobs registered by jobs.NewClient in worker.go (internal/jobs/adjudicate.go,
	// correlate.go, dangling_obs.go, sync_lifecycle.go, obs.go's feed-refresh
	// middleware), correlate.Service (wired only in worker.go), and the
	// consistency gate / forget-enforcing switch worker.go sets at boot.
	"graph_feed_last_success_timestamp_seconds":           true,
	"graph_adjudicator_outcomes_total":                    true,
	"graph_enrich_consistency_violations_total":           true,
	"graph_sweep_outcomes_total":                          true,
	"graph_sweep_last_resolved_timestamp_seconds":         true,
	"graph_correlate_sweeps_total":                        true,
	"graph_correlate_last_full_success_timestamp_seconds": true,
	"graph_correlate_view_rows":                           true,
	"graph_correlate_view_limit":                          true,
	"graph_check_evaluable_ratio":                         true,
	"graph_check_applicable_assets":                       true,
	"graph_sync_scope_last_complete_timestamp_seconds":    true,
	"graph_sync_scope_enumerated_assets":                  true,
	"graph_sync_deletion_candidates":                      true,
	"graph_forget_shadow_candidates":                      true,
	"graph_forget_would_forget":                           true,
	"graph_forget_refusals_total":                         true,
	"graph_forget_tombstones_written_total":               true,
	"graph_forget_enforcing":                              true,
	"graph_reasoncache_lookups_total":                     true,
}

// scannerOnlyMetricNames is the scanner-pod counterpart of
// workerOnlyMetricNames. It is empty today, deliberately, not an oversight:
// cmd/graph/scanner.go never calls Metrics.RegisterSources, so it has no live
// gauge Source of its own. Kept declared, rather than deleted, so the
// scanner's first live gauge Source has an obvious place to register instead
// of silently missing this guard.
var scannerOnlyMetricNames = map[string]bool{}

// ladybugColdStartGatedMetrics is the subset of workerOnlyMetricNames that
// liveCollector.Collect (metrics.go) does not emit at all until the worker's
// first Ladybug build completes after a restart — gated behind `g.ReachComplete
// != nil` or a non-empty g.EdgeTypeParity/TruncatedEdgeTypes. That gap can run
// well past an ordinary restart window under cold-start ClickHouse pressure.
// A max_over_time/min_over_time window shorter than the worst case doesn't
// bridge the gap, it just moves the failure from "pending clock resets to
// zero" to "window closes empty" — the same bug with an extra step. See
// TestLadybugColdStartGatedAlertsUseWidenedWindow.
//
// graph_ladybug_node_count/node_budget/last_built_timestamp_seconds are
// deliberately not here: Collect emits them unconditionally on every scrape,
// so their only restart exposure is the ordinary pod-down window, which the
// file's 10m default already covers.
var ladybugColdStartGatedMetrics = map[string]bool{
	"graph_ladybug_reach_edges_untruncated":        true,
	"graph_ladybug_edge_fetch_complete":            true,
	"graph_ladybug_asset_fetch_complete":           true,
	"graph_ladybug_identity_zero_hop":              true,
	"graph_ladybug_reachability_rate":              true,
	"graph_ladybug_edges_loaded":                   true,
	"graph_ladybug_edge_type_rows":                 true,
	"graph_ladybug_edge_dangling_over_budget":      true,
	"graph_ladybug_edge_expired_share_step_change": true,
	"graph_ladybug_edge_cap_hit":                   true,
}

// wrapExemptAlerts lists rules deliberately excluded from
// TestAlertRulesWrapInstantVectorsAgainstRestartGap, each with a one-line
// reason. An entry here must be a reviewed decision, not a place to park an
// alert someone forgot to wrap — see the test's own doc comment for what it
// enforces and why.
//
// Kept deliberately short: an alert that is exempt only because it is
// counter-based, already wrapped, has for: < 30m, or references no
// worker/scanner-only metric at all is already skipped by the test's own
// control flow and needs no entry here — an entry that duplicates a
// condition the code already checks is dead config (CLAUDE.md).
var wrapExemptAlerts = map[string]string{
	// absent()-based: the scrape gap IS the condition these alerts exist to
	// catch, so wrapping it away would defeat their entire purpose. Each
	// references a worker-only metric with for: >= 30m and no max_over_time/
	// min_over_time anywhere in its expr, so — unlike GraphCorrelateFullSweepStale
	// above — the test cannot pass without these four entries.
	"GraphSourceActivityMetricAbsent":  "absent()-based; a scrape gap is exactly what this alert detects",
	"GraphIntelFeedNeverRefreshed":     "absent()-based; a scrape gap is exactly what this alert detects",
	"GraphSCCFeedNeverRefreshed":       "absent()-based; a scrape gap is exactly what this alert detects",
	"GraphDomainMonitorNeverRefreshed": "absent()-based; a scrape gap is exactly what this alert detects",
}

var counterBasedExpr = regexp.MustCompile(`\b(rate|increase)\(`)

// parsePromDuration parses a for: value using Prometheus's duration syntax,
// which extends Go's time.ParseDuration with d (day), w (week) and y (365
// days) units that the stdlib parser rejects outright. No rule in rules.yaml
// uses one of those suffixes today (grep confirms), but a future rule that
// does would otherwise fail this guard with a parse error that has nothing
// to do with the restart-gap condition it is meant to check — worth fixing
// now rather than leaving as a trap for whoever adds the first one.
func parsePromDuration(s string) (time.Duration, error) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, nil
	}
	if s == "" {
		return 0, fmt.Errorf("parsePromDuration: empty duration")
	}
	unit, ok := map[byte]time.Duration{
		'd': 24 * time.Hour,
		'w': 7 * 24 * time.Hour,
		'y': 365 * 24 * time.Hour,
	}[s[len(s)-1]]
	if !ok {
		return 0, fmt.Errorf("parsePromDuration: %q has no unit time.ParseDuration or this helper recognises", s)
	}
	n, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if err != nil {
		return 0, fmt.Errorf("parsePromDuration: %q: %w", s, err)
	}
	return time.Duration(n * float64(unit)), nil
}

// restartGapMetrics returns every workerOnlyMetricNames/scannerOnlyMetricNames
// series expr actually references, by tokenizing metric names out of the
// expression text (reusing metricRef, the same word-boundary match
// TestAlertRulesReferenceOnlyEmittableMetrics already trusts) rather than
// pattern-matching a label selector's literal spelling: single quotes, spaces
// around `=`, `=~`, or no selector at all all produce the identical
// metric-name token, so none of them can dodge this check the way they would
// dodge a component="worker" regex.
func restartGapMetrics(expr string) []string {
	var found []string
	for _, ref := range metricRef.FindAllString(expr, -1) {
		if workerOnlyMetricNames[ref] || scannerOnlyMetricNames[ref] {
			found = append(found, ref)
		}
	}
	return found
}

// TestAlertRulesWrapInstantVectorsAgainstRestartGap guards the restart-gap
// bug class: graph-worker is replicas:1/maxSurge:0 and graph-scanner uses a
// Recreate strategy, so every deploy of either pod is a genuine total
// metrics-scrape gap for every metric only that pod emits
// (workerOnlyMetricNames/scannerOnlyMetricNames). An instant-vector
// comparison with for: >= 30m has no memory across that gap — Prometheus
// resets the pending clock to zero the moment the series vanishes for even
// one evaluation — so the alert silently never fires across a routine
// deploy. max_over_time/min_over_time bridges it.
//
// This does not apply to rate()/increase()-based expressions (a missed
// scrape just costs one sample in the window, the counter itself has no
// pending-clock-reset exposure), to absent()-based ones (the gap IS the
// condition being detected), or to a metric multiple components emit (a
// restart of one does not blank the series, because another component's copy
// keeps reporting) — see workerOnlyMetricNames' own exclusion notes for that
// last class. What remains, plus a short list of other deliberate
// exceptions, lives in wrapExemptAlerts with a reason each — add to it, don't
// loosen this test, when a genuinely new exception shows up.
func TestAlertRulesWrapInstantVectorsAgainstRestartGap(t *testing.T) {
	checked := 0
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			if reason, exempt := wrapExemptAlerts[r.Alert]; exempt {
				require.NotEmptyf(t, reason, "%s has an empty exemption reason", r.Alert)
				continue
			}
			if len(restartGapMetrics(r.Expr)) == 0 {
				continue
			}
			d, err := parsePromDuration(r.For)
			require.NoErrorf(t, err, "%s has a for: this test cannot parse: %q", r.Alert, r.For)
			if d < 30*time.Minute {
				continue
			}
			if counterBasedExpr.MatchString(r.Expr) {
				continue
			}
			checked++
			require.Truef(t,
				strings.Contains(r.Expr, "max_over_time(") || strings.Contains(r.Expr, "min_over_time("),
				"%s reads a graph_* worker/scanner-only metric with for: %s but its instant-vector "+
					"comparison is not wrapped in max_over_time/min_over_time — a worker/scanner restart's "+
					"scrape gap will silently reset its pending clock to zero and it will never fire across "+
					"a routine deploy. Wrap it (see GraphCheckJunkRateHigh for the pattern), or add it to "+
					"wrapExemptAlerts with a reason if the gap genuinely cannot affect it.",
				r.Alert, r.For)
		}
	}
	require.NotZerof(t, checked, "this guard should be exercising at least one rule; did loadAlertRules change shape?")
}

// windowRef pulls the range-selector duration out of a max_over_time/
// min_over_time call body — e.g. "10m" out of "graph_x{...}[10m]" or
// "graph_x{...}[7d] offset 6h". A subquery selector ("[6h:1m]") deliberately
// does not match: the colon is not \w, and no metric this test cares about is
// read through a subquery.
var windowRef = regexp.MustCompile(`\[(\w+)\]`)

// overTimeCall is one max_over_time(...)/min_over_time(...) invocation found
// in an expression: the full parenthesised body, and the range-selector
// window inside it (empty if none matched).
type overTimeCall struct {
	body   string
	window string
}

// overTimeCalls finds every max_over_time(...)/min_over_time(...) call in a
// PromQL expression by counting parens from each function's opening `(` to
// its matching `)`, rather than a regex — the body can itself contain nested
// parens (label matchers, arithmetic), which a single non-recursive regex
// cannot balance correctly, and Go's regexp (RE2) cannot express recursion at
// all.
func overTimeCalls(expr string) []overTimeCall {
	var calls []overTimeCall
	for _, fn := range []string{"max_over_time(", "min_over_time("} {
		pos := 0
		for {
			idx := strings.Index(expr[pos:], fn)
			if idx < 0 {
				break
			}
			open := pos + idx + len(fn) - 1
			depth := 1
			end := -1
			for i := open + 1; i < len(expr); i++ {
				switch expr[i] {
				case '(':
					depth++
				case ')':
					depth--
					if depth == 0 {
						end = i
					}
				}
				if end >= 0 {
					break
				}
			}
			if end < 0 {
				break // unbalanced — TestAlertRulesAreWellFormed/YAML parsing would already have surfaced this
			}
			body := expr[open+1 : end]
			window := ""
			if m := windowRef.FindStringSubmatch(body); m != nil {
				window = m[1]
			}
			calls = append(calls, overTimeCall{body: body, window: window})
			pos = end + 1
		}
	}
	return calls
}

// TestLadybugColdStartGatedAlertsUseWidenedWindow checks that
// graph_ladybug_edge_type_rows and its siblings in ladybugColdStartGatedMetrics —
// which stay absent until the worker's first Ladybug build completes after a
// restart, not just for the ordinary scrape gap — are read inside a
// max_over_time/min_over_time window wide enough to bridge that longer gap
// (see ladybugColdStartGatedMetrics' own doc comment).
func TestLadybugColdStartGatedAlertsUseWidenedWindow(t *testing.T) {
	checked := 0
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			for _, call := range overTimeCalls(r.Expr) {
				gated := false
				for name := range ladybugColdStartGatedMetrics {
					if strings.Contains(call.body, name) {
						gated = true
						break
					}
				}
				if !gated {
					continue
				}
				checked++
				require.NotEmptyf(t, call.window, "%s: a ladybug cold-start-gated metric is read inside "+
					"max_over_time/min_over_time with no parseable [window]", r.Alert)
				d, err := parsePromDuration(call.window)
				require.NoErrorf(t, err, "%s: window %q does not parse", r.Alert, call.window)
				require.GreaterOrEqualf(t, d, 30*time.Minute, "%s reads a cold-start-gated ladybug metric "+
					"(absent until the first Ladybug build after a worker restart — see ladybugColdStartGatedMetrics) inside "+
					"a %s window, which does not bridge that gap; widen it to at least 30m", r.Alert, call.window)
			}
		}
	}
	require.NotZerof(t, checked, "this guard should be exercising at least one ladybug cold-start alert; did rules.yaml change shape?")
}

// externalMetricRef matches a bare Prometheus-style identifier (letters,
// digits, underscore, not starting with a digit) that is NOT graph_-prefixed —
// i.e. every external metric name (kube-state-metrics, cAdvisor, the Go/process
// collector) an expression can reference. PromQL keywords/functions collide
// with this shape (by, on, offset, rate, ...), so callers must intersect the
// result with an explicit expected-names set rather than trust it standalone.
var externalMetricRef = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*\b`)

// knownExternalMetrics is the explicit, commented allowlist of non-graph_
// series this file's rules depend on. metricRef (above) only matches
// graph_-prefixed names, so TestAlertRulesReferenceOnlyEmittableMetrics has
// always been blind to these — a scrape-config change that stops shipping
// kube-state-metrics, or a typo in one of these names, would silently
// evaluate to an empty vector forever, the exact failure mode
// TestAlertRulesReferenceOnlyEmittableMetrics exists to catch for graph_*
// metrics. This test extends the same guarantee to the external ones: any
// identifier that looks like a metric name (PromQL keywords/functions are
// excluded below) and is not graph_-prefixed must be in this list.
var knownExternalMetrics = map[string]string{
	// kube-state-metrics.
	"kube_deployment_status_replicas_ready": "kube-state-metrics — GraphServeNotReady/GraphWorkerOrScannerNotReady",
	"kube_deployment_spec_replicas":         "kube-state-metrics — GraphServeNotReady/GraphWorkerOrScannerNotReady",
	// cAdvisor.
	"container_memory_working_set_bytes": "cAdvisor — GraphWorkerMemoryPeakNearLimit",
	"container_spec_memory_limit_bytes":  "cAdvisor — GraphWorkerMemoryPeakNearLimit",
}

// promqlKeywords are the PromQL operator/function/keyword identifiers that
// externalMetricRef's bare-identifier match also catches. Not an attempt at a
// complete PromQL grammar — only the ones actually appearing in rules.yaml
// today; a new expression introducing one not listed here fails loudly
// instead of silently passing as an unrecognised "external metric".
var promqlKeywords = map[string]bool{
	"by": true, "without": true, "on": true, "ignoring": true,
	"group_left": true, "group_right": true, "and": true, "or": true, "unless": true,
	"offset": true, "bool": true,
	"max": true, "min": true, "sum": true, "avg": true, "count": true, "topk": true, "bottomk": true,
	"rate": true, "irate": true, "increase": true, "absent": true, "time": true,
	"max_over_time": true, "min_over_time": true, "avg_over_time": true,
	"vector": true, "scalar": true, "clamp_min": true, "clamp_max": true, "abs": true,
}

// TestAlertRulesReferenceOnlyKnownExternalMetrics is the non-graph_
// counterpart of TestAlertRulesReferenceOnlyEmittableMetrics — metricRef's
// `graph_[a-z0-9_]+` pattern is blind to every kube-state-metrics/cAdvisor/
// process-collector name the availability and memory alerts depend on, so a
// typo or a renamed label in one of THOSE would pass every existing check
// silently. Any bare identifier in an expr that is not graph_-prefixed, not a
// label name/value, and not a recognised PromQL keyword must be in
// knownExternalMetrics.
func TestAlertRulesReferenceOnlyKnownExternalMetrics(t *testing.T) {
	// Label keys/values inside {...} selectors are not metric names — strip
	// every brace-delimited selector before scanning for bare identifiers, the
	// same reason metricRef only ever looks at expr text outside of labels
	// would matter if it also matched keywords like "namespace" or "warning".
	stripSelectors := regexp.MustCompile(`\{[^}]*\}`)
	seen := map[string]bool{}
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			cleaned := stripSelectors.ReplaceAllString(r.Expr, " ")
			for _, ref := range externalMetricRef.FindAllString(cleaned, -1) {
				if strings.HasPrefix(ref, "graph_") {
					continue
				}
				if promqlKeywords[ref] {
					continue
				}
				// Number-like or single-letter loop variables from label lists
				// (e.g. "namespace", "queue") also appear as bare `by (...)`
				// arguments — but those are legitimate label names, which this
				// allowlist is not meant to police; only flag names actually
				// used as a metric (immediately followed by `(` for a function
				// is excluded above via promqlKeywords, and label lists were
				// already stripped by dropping the by(...) contents below).
				seen[ref] = true
			}
		}
	}
	// by (...)/without (...) argument lists are labels, not metrics, but survive
	// stripSelectors (they use parens, not braces) and externalMetricRef's bare
	// scan. Remove them the same way: anything immediately inside "by (" or
	// "without (" up to the matching close.
	byArgs := regexp.MustCompile(`(?:by|without)\s*\(([^)]*)\)`)
	labelNames := map[string]bool{}
	for _, g := range loadAlertRules(t).Groups {
		for _, r := range g.Rules {
			for _, m := range byArgs.FindAllStringSubmatch(r.Expr, -1) {
				for _, name := range strings.Split(m[1], ",") {
					labelNames[strings.TrimSpace(name)] = true
				}
			}
		}
	}

	var unknown []string
	for ref := range seen {
		if labelNames[ref] {
			continue
		}
		if _, ok := knownExternalMetrics[ref]; ok {
			continue
		}
		unknown = append(unknown, ref)
	}
	sort.Strings(unknown)
	require.Emptyf(t, unknown,
		"these look like external (non-graph_) metric names referenced in rules.yaml but are not in knownExternalMetrics — "+
			"add them with a source/consumer comment, or they were typo'd/renamed silently: %v", unknown)

	// And the reverse: every allowlisted name must actually still be used,
	// or the allowlist itself has gone stale.
	for name := range knownExternalMetrics {
		require.Truef(t, seen[name],
			"knownExternalMetrics[%q] is no longer referenced by any rule — remove it or the allowlist is lying about what this file depends on", name)
	}
}
