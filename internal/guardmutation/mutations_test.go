package guardmutation

// The mutation catalogue and the inventory check that keeps it honest.
//
// This file is deliberately NOT build-tagged: TestEveryDiscoveredGuardIsMutatedOrExempt
// runs in the normal unit suite, so adding a structural guard without deciding
// how it will be verified fails CI immediately, even when the (slow) mutation
// job is not run. The driver that actually applies these mutations lives in
// harness_test.go behind the `guardmutation` tag.
//
// The catalogue is a table of exact old/new strings rather than patch files or
// a build-tag-gated alternate implementation: the working tree stays the
// single source of truth, the harness requires each Old string to occur
// exactly once, and drift shows up as a loud harness error naming the
// mutation rather than a silent skip or a `git apply` failure. A table also
// stays readable in a diff, which matters because each row is an assertion
// about what a guard is FOR.
//
// Mutating a *_test.go file is legitimate — and marked — when the thing the
// guard protects IS a hand-maintained list that lives in the test (allRules).
// Everything else mutates production source.

// Mutation reintroduces the bug one guard exists to prevent.
type Mutation struct {
	// Guard is the test function that must fail once this mutation is applied.
	Guard string
	// Pkg is the package pattern to run it in.
	Pkg string
	// File is repo-relative.
	File string
	// Old must occur EXACTLY ONCE in File; New replaces it.
	Old string
	New string
	// Why states the bug being reintroduced, in the guard's own terms.
	Why string
	// MutatesTest marks a mutation that edits the guard's own test file,
	// because the artefact the guard protects is a list declared there.
	MutatesTest bool
}

// mutations is the catalogue. One row per guard; two guards may share a
// mutation when the same defect is what both exist to catch, and each row is
// still applied and verified independently.
var mutations = []Mutation{
	// ── compose stack ───────────────────────────────────────────────────
	{
		Guard: "TestComposeSecretsAreGeneratedAndScoped", Pkg: "./cmd/graph",
		File: "deploy/docker-compose/docker-compose.yml",
		Old:  "        source: secrets-postgres\n        target: /secrets\n",
		New:  "        source: secrets-app\n        target: /secrets\n",
		Why: "the postgres container reads the app's secrets volume, so a compromised datastore holds " +
			"the credential encryption key — each container must see only the file generated for it",
	},
	// ── goroutine safety ────────────────────────────────────────────────
	{
		Guard: "TestNoUnrecoveredGoroutines_RepoWide", Pkg: "./internal/obs",
		File: "internal/intel/osv/osv.go",
		Old: "\t\tgo func() {\n" +
			"\t\t\tdefer wg.Done()\n",
		New: "\t\tgo func() {\n" +
			"\t\t\t_ = id\n" +
			"\t\t\tdefer wg.Done()\n",
		Why: "a statement before the leading run of defers leaves the recover unregistered " +
			"for the code that runs first — the exact shape of the eight github fan-outs this guard closed",
	},
	{
		Guard: "TestNoUnrecoveredGoroutines", Pkg: "./cmd/graph",
		File: "cmd/graph/serve.go",
		Old:  "\tgo func() {\n\t\tdefer func() {\n\t\t\tif r := recover(); r != nil {\n\t\t\t\tlog.FromContext(ctx).Error().Any(\"panic\", r).Msg(\"cost collect loop: panic\")",
		New:  "\tgo func() {\n\t\t_ = ctx\n\t\tdefer func() {\n\t\t\tif r := recover(); r != nil {\n\t\t\t\tlog.FromContext(ctx).Error().Any(\"panic\", r).Msg(\"cost collect loop: panic\")",
		Why:  "cmd/graph's stricter form: the recover must be the FIRST statement, so a panic in the statement above it kills the pod",
	},

	// ── cost-collection observability ───────────────────────────────────
	{
		Guard: "TestCostCollectLoopHasNoSilentExit", Pkg: "./cmd/graph",
		File: "cmd/graph/serve_costcollect.go",
		Old: "\t\t\tmetrics.ObserveCostCollect(\"connector_list_error\")\n" +
			"\t\t\tlog.FromContext(ctx).Error().Err(err).Msg(\"cost collect: connector list failed; no cost data will be collected this cycle\")\n",
		New: "\t\t\tlog.FromContext(ctx).Error().Err(err).Msg(\"cost collect: connector list failed; no cost data will be collected this cycle\")\n",
		Why: "dropping the metric from an early return keeps this integration dark: cost data is silently " +
			"empty when the role lacks ce:GetCostAndUsage while the UI renders \"No cost anomalies\", " +
			"because a bare return leaves no counter and no log to contradict it",
	},
	{
		Guard: "TestCostCollectLoopLogsEveryOutcome", Pkg: "./cmd/graph",
		File: "cmd/graph/serve_costcollect.go",
		Old:  "\t\t\t\t\tStr(\"required_permission\", costdata.RequiredIAMPermission).\n",
		New:  "",
		Why: "a denial logged without naming ce:GetCostAndUsage is not actionable — the permission is granted " +
			"nowhere in the repo, so the operator cannot derive the fix from \"AccessDenied\" alone",
	},

	// ── ClickHouse memory headroom ──────────────────────────────────────
	{
		Guard: "TestScanAssetsBoundsAggregationMemory", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/repo.go",
		Old: "\tctx = r.ch.WithQuerySettings(ctx, map[string]any{\n" +
			"\t\t\"max_bytes_before_external_group_by\": loadViewSpillBytes,\n" +
			"\t})\n",
		New: "\t_ = ctx\n",
		Why: "deleting the spill setting is the natural 'simplify this' edit — the query passes every " +
			"test and every small-corpus run without it, and only on a large corpus does the unbounded " +
			"GROUP BY exceed the server memory limit and get killed",
	},
	{
		Guard: "TestCHCacheCeilingsLeaveRoomForQueries", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/values.yaml",
		Old:  "markCacheBytes: \"536870912\"         # 512Mi — primary marks; highest-value cache",
		New:  "markCacheBytes: \"2147483648\"         # 512Mi — primary marks; highest-value cache",
		Why: "raising the mark-cache ceiling without raising maxServerMemoryBytes to match is the " +
			"shape of ClickHouse's own upstream defaults (5 GiB mark cache, which knows nothing " +
			"about max_server_memory_usage) — the caches are charged to the same tracker as " +
			"queries, so an unbudgeted cache ceiling leaves a shrinking, unpredictable share for " +
			"SELECTs and kills even small queries with no symptom pointing at the cache",
	},

	// ── coverage derivation (docs/COVERAGE.md) ──────────────────────────
	{
		Guard: "TestProviderScopeCoversEveryDeclaredProvider", Pkg: "./internal/app/coverage",
		File: "internal/app/coverage/domain.go",
		Old:  "\t{Provider: \"azure\", Weighted: false,",
		New:  "\t{Provider: \"azurex\", Weighted: false,",
		Why: "ProviderScopes is the one hand-declared list in the coverage package; an asset.Provider that " +
			"nobody classified silently drops a whole cloud out of the generated coverage document",
	},
	{
		Guard: "TestLineageStagesReferenceTheRegistries", Pkg: "./internal/app/coverage",
		File: "internal/app/coverage/domain.go",
		Old:  "Kind: StageEdgeSrc, EdgeType: \"depends_on\"",
		New:  "Kind: StageEdgeSrc, EdgeType: \"depends_upon\"",
		Why: "a lineage stage naming an edge type that graphschema no longer declares measures nothing and " +
			"renders a confident zero — the failure this document exists to end",
	},
	{
		Guard: "TestScoringSeedsAreRegisteredNonReachTypes", Pkg: "./internal/app/coverage",
		File: "internal/app/coverage/domain.go",
		Old:  "var ScoringSeedEdgeTypes = []string{\"exposed_to_internet\"}",
		New:  "var ScoringSeedEdgeTypes = []string{\"can_assume\"}",
		Why: "a seed that is actually a Reach movement edge makes the graph axis assert on the wrong thing: " +
			"every type with a lateral edge would read as reachable by the internet-hops BFS",
	},
	{
		Guard: "TestEvidenceRuleAnswersOnlyForChecksThatProduceTheCategory", Pkg: "./internal/app/coverage",
		File: "internal/app/coverage/service.go",
		Old:  "= i.evidenceRule(c.Source, c.Type)",
		New:  "= i.evidenceRule(\"cspm\", \"misconfiguration\")",
		Why: "answering the evidence axis with some other concern's checks is the defect the check_id join closed: " +
			"six categories carry github_repo among their resource types, and all six were told to emit branch_protection — " +
			"branch protection has nothing to do with unreadable Terraform state",
	},
	{
		Guard: "TestSuppressorKeysAreNotEvidenceGaps", Pkg: "./internal/app/coverage",
		File: "internal/app/coverage/evidencekeys.go",
		Old: "\t\tif !c.Evaluable(probe) {\n" +
			"\t\t\treturn true // some value of the absent key would have fired it\n" +
			"\t\t}\n\t}\n\treturn false",
		New: "\t\tif !c.Evaluable(probe) {\n" +
			"\t\t\treturn true // some value of the absent key would have fired it\n" +
			"\t\t}\n\t}\n\treturn true",
		Why: "treating every required key as evidence-bearing reports a SUPPRESSOR's absence as missing data and " +
			"advises the collector to emit it — ns_psa_enforce is absent on every pod by design, and emitting it " +
			"would switch three k8s checks OFF where they fire today",
	},

	{
		Guard: "TestUnfirablePredicateExemptsNoKey", Pkg: "./internal/app/coverage",
		File: "internal/app/coverage/evidencekeys.go",
		Old:  "\tif !firable(c, assetType) {",
		New:  "\tif false {",
		Why: "without the firability gate, a predicate that cannot fire on a probe at all — because it also reads a " +
			"structural asset field, or compares against a constant keyscan could not lift into ProbeValues — has every " +
			"key silently classified as a suppressor. That excuses checks such as aws-lambda-public-access " +
			"even when no collected asset carries their key: a real gap turned invisible",
	},

	// ── asset inventory liveness ────────────────────────────────────────
	{
		Guard: "TestAssetReadersApplyLiveness", Pkg: "./internal/app/asset",
		File: "internal/app/asset/repo.go",
		Old:  "\tWHERE ` + inventoryReadCond + `\n\tGROUP BY GROUPING SETS",
		New:  "\tGROUP BY GROUPING SETS",
		Why: "a UI-facing asset read without the liveness gate reports the cemetery as inventory — asset rows are " +
			"not deleted until their 180-day TTL, only left un-restamped. The Assets page then reports several times more assets " +
			"than the graph, built from the same table WITH the gate, holds",
	},
	{
		Guard: "TestAssetReadersApplyLiveness", Pkg: "./internal/app/asset",
		File: "internal/app/asset/drift.go",
		Old:  "WHERE first_discovered_at >= now() - INTERVAL ? SECOND\n  AND ` + inventoryReadCond + `\n",
		New:  "WHERE first_discovered_at >= now() - INTERVAL ? SECOND\n",
		Why:  "an asset reader outside repo.go without the gate: the drift feed reports dead pods and IaC declarations as new assets",
	},
	{
		Guard: "TestAssetReadersApplyLiveness", Pkg: "./internal/app/asset",
		File: "internal/app/asset/drift.go",
		Old:  "  AND e.synced_at >= now() - INTERVAL ? SECOND\n  AND ` + inventoryReadCond + `\n",
		New:  "  AND e.synced_at >= now() - INTERVAL ? SECOND\n",
		Why:  "a reader that reaches assets through JOIN, not FROM, without the gate: the drift feed reports dead pods and IaC declarations as new exposures",
	},
	{
		Guard: "TestAssetReadersApplyLiveness", Pkg: "./internal/app/asset",
		File: "internal/app/asset/drift.go",
		Old:  "    argMax(toUInt8(` + inventoryReadCond + `), synced_at) AS inventory,\n",
		New:  "    toUInt8(1) AS inventory,\n",
		Why:  "the Postgres-backed drift feed (the one serve uses) marks every asset as inventory, so dead pods and IaC declarations are listed",
	},
	{
		Guard: "TestNonInventoryTypesCoversEveryDeclaredProducer", Pkg: "./internal/app/asset",
		File: "internal/app/asset/repo.go",
		Old:  "\t\"declared_image_build\",\n\t\"declared_k8s_workload\",",
		New:  "\t\"declared_k8s_workload\",",
		Why: "an IaC declaration type missing from NonInventoryTypes is counted as a resource we own AND " +
			"double-counts the real resource it declares — declared_image_build and declared_cloud_identity " +
			"were exactly that gap, parsed YAML/TF declarations shown as the Assets page's blank-provider pill",
	},

	// ── router, correlate load view, periodic registry ──────────────────
	{
		Guard: "TestLoadViewProjectsAllReadMetadataKeys", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/repo.go",
		Old:  "\"network\", \"network_tags\", \"nic_nsgs\", \"nsg_ids\",",
		New:  "\"network\", \"network_tags\", \"nsg_ids\",",
		Why:  "a key the Azure NSG rule reads drops out of the load view's projection, so every VM reads nic_nsgs as \"\" and loses its NSG edges",
	},
	{
		Guard: "TestCorrelationTypesHasNoUnusedTypes", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/repo.go",
		Old:  "\t\"iam_role\",\n",
		New:  "\t\"iam_role\", \"mutation_unused_type\",\n",
		Why:  "the view loads a type no rule reads, and every sweep pays to fetch and decode it for nothing",
	},
	{
		Guard: "TestAdminGatedRoutes_ParsesTheRouter", Pkg: "./internal/httpsrv",
		File: "internal/httpsrv/server.go",
		Old:  "\"POST /api/findings/{id}/suppress\", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Suppress.Suppress)))",
		New:  "\"POST /api/findings/{id}/suppress\", authH.RequireAuth(h.Suppress.Suppress))",
		Why:  "a write route loses its admin gate and drops out of the derived set the 403 integration test walks",
	},
	{
		Guard: "TestEveryPeriodicIsASingleton", Pkg: "./internal/jobs",
		File: "internal/jobs/osv.go",
		Old:  "return periodicSingletonOpts(queueEnrich, 3)",
		New:  "return river.InsertOpts{Queue: queueEnrich}",
		Why:  "every leader election stacks another copy of refresh_osv, and River's 25 default attempts hold the slot for days",
	},

	// ── check evaluability ──────────────────────────────────────────────
	{
		Guard: "TestNoCheckFiresOnEmptyMetadata", Pkg: "./internal/checks",
		File: "internal/checks/hygiene.go",
		Old:  "return observedNone(a, \"association_id\") &&\n\t\t\tobservedNone(a, \"instance_id\") &&\n\t\t\tobservedNone(a, \"network_interface_id\")",
		New:  "return a.Metadata[\"association_id\"] == \"\" &&\n\t\t\ta.Metadata[\"instance_id\"] == \"\" &&\n\t\t\ta.Metadata[\"network_interface_id\"] == \"\"",
		Why:  "an Elastic IP whose collector read nothing would be reported as unassociated",
	},
	{
		Guard: "TestUnresolvedComparandsHaveTableProbes", Pkg: "./internal/checks",
		File: "internal/checks/aws_app_integration.go",
		Old:  "\t\treturn a.Metadata[\"public_access\"] == asset.PublicAccessConfirmed\n\t},\n\tTableProbes: []string{asset.PublicAccessConfirmed},\n}",
		New:  "\t\treturn a.Metadata[\"public_access\"] == asset.PublicAccessConfirmed\n\t},\n}",
		Why:  "an EventBridge bus whose policy could not be read leaves public_access out, and the public-bus finding closes as fixed",
	},

	// ── alert rules (internal/obs/alerts_test.go) ───────────────────────
	{
		Guard: "TestAlertRulesAreWellFormed", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "          severity: warning\n        annotations:\n          summary: \"graph: {{ $value }} {{ $labels.edge_type }} relationships silently dropped (type mismatch)\"",
		New:  "          severity: warning\n          team: security\n        annotations:\n          summary: \"graph: {{ $value }} {{ $labels.edge_type }} relationships silently dropped (type mismatch)\"",
		Why:  "a rule hardcodes a routing label, so the operator's alerts.labels value for it is ignored and that one alert routes somewhere else",
	},
	{
		Guard: "TestAlertRoutingLabelsReachEveryRule", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/templates/vmrule.yaml",
		Old:  "{{- $_ := set . \"labels\" (merge (dict) (.labels | default dict) $alertLabels) }}\n",
		New:  "{{- $_ := set . \"labels\" (.labels | default dict) }}\n",
		Why:  "alerts.labels never reaches the fired alerts, so every alert falls through to Alertmanager's default receiver",
	},
	{
		Guard: "TestAlertRulesReferenceOnlyEmittableMetrics", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "(max_over_time(graph_ladybug_edge_dangling_over_budget{namespace",
		New:  "(max_over_time(graph_ladybug_edge_dangling_over_budget_total{namespace",
		Why:  "an alert on a metric name nothing emits evaluates to an empty vector forever and never fires, which reads as healthy",
	},
	{
		Guard: "TestAlertAnnotationsNameRealMetrics", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "(graph_ladybug_edge_expired_share_step_delta shows the signed change)",
		New:  "(graph_ladybug_edge_expired_share_step_deltas shows the signed change)",
		Why:  "an annotation that names a metric which does not exist sends the person paged to a query that returns nothing",
	},
	{
		Guard: "TestEveryEmittedMetricIsAlertedOnOrConsciouslyNot", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "max_over_time(graph_ladybug_edge_dangling_over_budget{namespace=\"__NAMESPACE__\", component=\"worker\"}[30m])) > 0",
		New:  "max_over_time(graph_ladybug_edge_type_rows{namespace=\"__NAMESPACE__\", component=\"worker\", outcome=\"label_mismatch\"}[30m])) > 0",
		Why:  "the worker's dangling-budget verdict would be emitted with no rule reading it and no contextOnly entry saying why",
	},
	{
		Guard: "TestEdgeParityAlertExcludesEndpointAbsent", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "component=\"worker\", outcome=\"label_mismatch\"}[30m])) > 0\n        for: 30m",
		New:  "component=\"worker\", outcome=~\"label_mismatch|endpoint_absent\"}[30m])) > 0\n        for: 30m",
		Why:  "summing endpoint_absent (permanent expected attrition) into the label-mismatch alarm makes it fire on every build",
	},
	{
		Guard: "TestMustFixCoverageAlertExcludesNuclei", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "source!=\"nuclei\", state=\"blank\"}[10m]))",
		New:  "state=\"blank\"}[10m]))",
		Why:  "nuclei's blank ratio is near 100% by design, so counting it fires the must-fix coverage alert permanently",
	},
	{
		Guard: "TestRulesHeaderNamesEveryCriticalRule", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "except the two\n# outage rules, GraphServeNotReady and GraphWorkerOrScannerNotReady, which are\n",
		New:  "except the one\n# outage rule, GraphServeNotReady, which is\n",
		Why:  "an operator wiring Alertmanager routes from the header leaves a critical rule off the on-call route",
	},
	{
		Guard: "TestNoAbsentFeedAlertTargetsAFeedOffByDefault", Pkg: "./internal/jobs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "feed=\"epss\"})\n        for: 26h",
		New:  "feed=\"epss\"})\n          or absent(graph_feed_last_success_timestamp_seconds{namespace=\"__NAMESPACE__\", component=\"worker\", feed=\"scc\"})\n        for: 26h",
		Why:  "the always-rendered never-refreshed alert waits for the SCC feed, which runs only with config.sccOrgId set, so it fires forever on every install without SCC",
	},
	{
		Guard: "TestEveryGraphContainerFollowsPullPolicy", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/deployment-serve.yaml",
		Old:  "          imagePullPolicy: {{ .Values.image.pullPolicy }}\n          args: [\"migrate\"]",
		New:  "          args: [\"migrate\"]",
		Why:  "with pullPolicy Always on a moving tag, migrate runs the node's cached build while serve pulls the new one, so new serve code starts on an unmigrated schema",
	},

	// ── graph edge freshness / registry ─────────────────────────────────
	{
		Guard: "TestDanglingBudgetAlertReadsTheWorkerVerdict", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "max_over_time(graph_ladybug_edge_dangling_over_budget{namespace=\"__NAMESPACE__\", component=\"worker\"}[30m])) > 0",
		New:  "max_over_time(graph_ladybug_edge_type_rows{namespace=\"__NAMESPACE__\", component=\"worker\", outcome=\"endpoint_expired\"}[30m])) > 0",
		Why: "alarming on endpoint_expired is the permanently-firing alarm this rule set already had to un-break once: " +
			"absent rows are dominated by edges to pods dead past the liveness cut, " +
			"and re-deriving the per-type budget in PromQL puts a second copy of a declared graphschema number in a dashboard",
	},
	{
		Guard: "TestExpiredShareStepAlertReadsTheWorkerVerdict", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "max_over_time(graph_ladybug_edge_expired_share_step_change{namespace=\"__NAMESPACE__\", component=\"worker\"}[30m])) > 0",
		New:  "max_over_time(graph_ladybug_edge_type_rows{namespace=\"__NAMESPACE__\", component=\"worker\", outcome=\"endpoint_expired\"}[30m])) > 0",
		Why: "alarming on a LEVEL of endpoint_expired instead of the worker's step-change verdict is exactly the " +
			"permanently-firing shape this alert exists to avoid — endpoint_expired sits near 100% of some edge " +
			"types' drops by design, and re-deriving the per-type step budget in PromQL puts a second copy of a " +
			"declared graphschema number (ExpiredShareStepBudget) in a dashboard",
	},
	{
		Guard: "TestAlertRulesWrapInstantVectorsAgainstRestartGap", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "max by (namespace, edge_type) (max_over_time(graph_ladybug_edge_type_rows{namespace=\"__NAMESPACE__\", component=\"worker\", outcome=\"label_mismatch\"}[30m])) > 0",
		New:  "max by (namespace, edge_type) (graph_ladybug_edge_type_rows{namespace=\"__NAMESPACE__\", component=\"worker\", outcome=\"label_mismatch\"}) > 0",
		Why: "an unwrapped instant-vector comparison on a component=\"worker\" gauge with for: >= 30m has its pending " +
			"clock silently reset by every routine graph-worker redeploy (replicas:1, maxSurge:0 — a genuine total " +
			"scrape gap), the same class an earlier fix only partially closed",
	},
	{
		Guard: "TestLadybugColdStartGatedAlertsUseWidenedWindow", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "max_over_time(graph_ladybug_identity_zero_hop{namespace=\"__NAMESPACE__\", component=\"worker\"}[30m])) > 0",
		New:  "max_over_time(graph_ladybug_identity_zero_hop{namespace=\"__NAMESPACE__\", component=\"worker\"}[10m])) > 0",
		Why: "graph_ladybug_identity_zero_hop is absent, not zero, until the worker's first Ladybug build completes " +
			"after a restart, which can take tens of minutes on a cold start under ClickHouse pressure. Narrowing the " +
			"window back to the file's 10m default doesn't bridge that gap, it just moves the restart-gap bug " +
			"this whole change exists to fix from \"pending clock resets\" to \"window closes empty\"",
	},
	{
		Guard: "TestGraphEdgesReadersApplyFreshness", Pkg: "./internal/graphschema",
		File: "internal/app/finding/risk.go",
		Old:  "WHERE e.edge_type = 'runs_package' AND ` + graphschema.EdgeFreshnessCond + `\n",
		New:  "WHERE e.edge_type = 'runs_package'\n",
		Why: "a graph_edges reader that drops the freshness filter resurrects topology that no longer exists " +
			"(edges are never deleted, only left un-restamped until TTL)",
	},
	{
		Guard: "TestRegistryConsistency", Pkg: "./internal/graphschema",
		File: "internal/graphschema/graphschema.go",
		Old:  "{Name: \"ContainsData\", From: NodeAsset, To: NodeDataClass, Loaded: true,",
		New:  "{Name: \"ContainsData\", From: NodeAsset, To: NodeDataClass, Loaded: false,",
		Why:  "a synced edge type feeding an unloaded rel with no DropReason is the silent drop the registry gate exists to make impossible",
	},
	{
		Guard: "TestRegistryConsistency", Pkg: "./internal/graphschema",
		File: "internal/graphschema/graphschema.go",
		Old:  "{Type: \"can_assume\", Rel: \"CanAssume\", Tier: TierCritical, Reach: true, Weight: 0.8, Dir: DirBoth,",
		New:  "{Type: \"can_assume\", Rel: \"CanAssume\", Tier: TierCritical, Reach: true, Weight: 0.8, Dir: DirForward,",
		Why: "can_assume is a capability edge: risk score is blast radius, so the principal must inherit the " +
			"privilege of the role it can assume. Declaring it forward credits the admin role at the END of a " +
			"privesc chain and leaves the weakly-held role at the start — the remediation target — unelevated",
	},
	{
		Guard: "TestBFSRiskDoesNotFlowBackwards", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/bfs.go",
		Old: "\t\tswitch graphschema.DirectionFor(e.EdgeType) {\n" +
			"\t\tcase graphschema.DirForward:\n",
		New: "\t\tswitch graphschema.DirBoth {\n" +
			"\t\tcase graphschema.DirForward:\n",
		Why: "indexing both ends of every edge is the shipped defect: an asset inherited risk from principals and " +
			"resources that cannot reach it (a role raised the instances attached to it, an account hub handed its " +
			"worst asset's score to every sibling), and the post-BFS score drives enrich → must-fix → respond",
	},
	{
		// Same mutation as the row above, verified separately: this guard derives
		// the expected adjacency for every registered type from DirectionFor, so it
		// catches a buildAdjIndex that stops honouring the registry — but NOT a
		// broken DirectionFor, since both sides would move together. The row above,
		// which hardcodes can_assume, is the half that covers that.
		Guard: "TestBuildAdjIndexHonoursRegistryDirections", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/bfs.go",
		Old: "\t\tswitch graphschema.DirectionFor(e.EdgeType) {\n" +
			"\t\tcase graphschema.DirForward:\n",
		New: "\t\tswitch graphschema.DirBoth {\n" +
			"\t\tcase graphschema.DirForward:\n",
		Why: "the index must stay derived from the registry: a declared direction that buildAdjIndex ignores is " +
			"the declare-once-derive-everywhere principle failing in the one consumer whose output feeds automated action",
	},
	{
		Guard: "TestReachAndInheritTypesAreCritical", Pkg: "./internal/graphschema",
		File: "internal/graphschema/graphschema.go",
		Old:  "{Type: \"runs_image\", Rel: \"RunsImage\", Tier: TierCritical, Inherit: true,",
		New:  "{Type: \"runs_image\", Rel: \"RunsImage\", Tier: TierBulk, Inherit: true,",
		Why: "an Inherit type in the capped bulk tier is starved to zero rows by the shared 500k LIMIT after ORDER BY edge_type — " +
			"exactly the earlier defect that emptied inheritAdj and disabled every containment demotion",
	},
	{
		Guard: "TestRegistryDerivationsMatchLegacy", Pkg: "./internal/app/graphstore",
		File: "internal/graphschema/graphschema.go",
		Old:  "{Type: \"runs_container\", Rel: \"RunsContainer\", Tier: TierCritical, Inherit: true,",
		New:  "{Type: \"runs_container\", Rel: \"RunsContainer\", Tier: TierBulk, Inherit: true,",
		Why:  "a registry edit that changes what Ladybug loads/traverses must break the conscious pin, not slide through",
	},
	// The label-promotion class guard, and the guard on ITS input. The class has
	// recurred repeatedly, including with the class guard already in the tree,
	// because the guard only checks the triples it is handed. So both
	// halves are catalogued: the assertion, and the completeness of its input.
	{
		Guard: "TestProducerEdgeLabelsMatchRelTables", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/repo.go",
		// One tab, not two: the reroute chain moved from inside buildEdgeRows loop
		// into relTableForEdge when the streaming CSV writer needed to share it.
		Old: "\t} else if e.EdgeType == \"federated_access\" && NodeLabelFor(e.SrcType) == NodeAsset {\n",
		New: "\t} else if e.EdgeType == \"federated_access\" && NodeLabelFor(e.SrcType) == \"NeverMatches\" {\n",
		Why: "removing a reroute sends a producer's rows to a rel table whose declared endpoints do not match the " +
			"labels those asset types promote to — Ladybug discards every one with no error, no warning and no metric",
	},
	{
		Guard: "TestProducerEdgesCoverEveryLoadedEdgeType", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/producer_label_test.go",
		Old: "\t{\"member_of\", \"human_identity\", \"sso_group\", \"collect/okta/okta.go:127\"},\n" +
			"\t{\"member_of\", \"sso_group\", \"sso_group\", \"collect/okta/okta.go:202\"},\n",
		New: "",
		Why: "an edge type absent from producerEdges is never label-checked at all — the hole that lets the class " +
			"recur with the class guard already in place",
		MutatesTest: true,
	},
	{
		Guard: "TestExportJSONIsFresh", Pkg: "./internal/graphschema",
		File: "frontend/src/generated/graph-schema.json",
		Old:  "\"runs_image\"",
		New:  "\"runs_imagez\"",
		Why:  "the committed frontend derivation drifting from the registry — a frontend reading a stale edge-type set, silently",
	},
	{
		Guard: "TestExportBandsJSONIsFresh", Pkg: "./internal/app/enrich",
		File: "frontend/src/generated/score-bands.json",
		Old:  "\"min_score\": 50",
		New:  "\"min_score\": 31",
		Why:  "the frontend's band boundaries drifting from enrich's thresholds — a finding the server bands monitor shown and filtered as medium",
	},

	// ── CSPM benchmark matrix (ADR 090) ─────────────────────────────────
	{
		Guard: "TestCoverageDocIsCurrent", Pkg: "./internal/checks/coveragedoc",
		File: "docs/cspm-coverage.md",
		Old:  "| CIS Kubernetes Benchmark | 2.0.1 |",
		New:  "| CIS Kubernetes Benchmark | 2.0.0 |",
		Why:  "the published coverage document drifting from the matrices it claims to render",
	},
	// ── reasoning eval golden sets (ADR 038) ────────────────────────────
	{
		Guard: "TestGoldenSetSizesMatchDocs", Pkg: "./internal/reason",
		File: "docs/capabilities.md",
		Old:  "The adjudicator set (8 cases)",
		New:  "The adjudicator set (10 cases)",
		Why:  "the docs stating a golden set larger than the one the code runs, the only quantitative claim it makes about LLM judgement",
	},
	// ── benchmark freshness and framework rollup (ADR 092, 093) ─────────
	{
		Guard: "TestMatricesMatchUpstreamSnapshot", Pkg: "./internal/checks/benchmarks",
		File: "internal/checks/benchmarks/testdata/sources/acknowledged.yaml",
		Old:  "    \"5.10.4\": \"In kube-bench gke-1.9.0 only. The matrix pins CIS GKE 2.0.0 (IDs from Tenable's audit listing, ADR 090), which kube-bench does not publish yet.\"\n",
		New:  "",
		Why:  "an upstream control the matrix has no row for going unexplained — coverage drift hiding instead of failing CI",
	},
	{
		Guard: "TestFrameworkFilesAreCanonical", Pkg: "./internal/checks/frameworks",
		File: "internal/checks/frameworks/iso_27001_2022.yaml",
		Old:  "{id: \"A.5.1\", title:",
		New:  "{id: \"A.5.1\",  title:",
		Why:  "a hand edit to a generated mapping file that the next regeneration would silently revert",
	},
	{
		Guard: "TestRollupRequirement", Pkg: "./internal/app/compliance",
		File: "internal/app/compliance/service_requirements.go",
		Old:  "st.UnjoinedSourceChecks > 0 || evaluated == 0:",
		New:  "st.UnjoinedSourceChecks > 0:",
		Why:  "a requirement with nothing evaluated (no inventory) reading as passing — absence of findings over nothing looked at counted as compliance",
	},
	{
		Guard: "TestCSVSafe", Pkg: "./internal/app/compliance",
		File: "internal/app/compliance/handler.go",
		Old:  "strings.ContainsRune(\"=+-@\\t\\r\", rune(s[0]))",
		New:  "strings.ContainsRune(\"=@\", rune(s[0]))",
		Why:  "an auditor CSV cell starting with + - tab or CR evaluated as a formula when opened in a spreadsheet",
	},
	{
		Guard: "TestRollupPartialMappingIsNeverPassing", Pkg: "./internal/app/compliance",
		File: "internal/app/compliance/service_requirements.go",
		Old:  "len(st.UnevaluatedChecks) > 0 || st.UnjoinedSourceChecks > 0 ||",
		New:  "len(st.UnevaluatedChecks) > 0 ||",
		Why:  "a requirement passing on the fraction of its source evidence graph happens to have controls for",
	},
	{
		Guard: "TestFrameworkRollupPartialEvidenceIsUnknown", Pkg: "./internal/app/compliance",
		File: "internal/app/compliance/service_requirements.go",
		Old:  "\t\tif !chk.Evaluable(a) {\n\t\t\treturn evUnevaluated\n\t\t}\n\t\tev = evEvaluated",
		New:  "\t\tif chk.Evaluable(a) {\n\t\t\treturn evEvaluated\n\t\t}\n\t\tev = evUnevaluated",
		Why:  "one evaluable sample vouching for live assets of the same type that were never observed",
	},
	{
		Guard: "TestBenchmarkMatricesAreWellFormed", Pkg: "./internal/checks",
		File: "internal/checks/benchmarks/cis_aws_foundations_v7.0.0.yaml",
		Old:  "check_ids: [aws-ec2-no-iam-role]",
		New:  "check_ids: [aws-ec2-no-iam-rolez]",
		Why:  "a control claiming coverage from a check ID the registry does not have — a renamed check leaving coverage nothing provides",
	},
	{
		Guard: "TestCISControlsAgreeWithBenchmarkMatrix", Pkg: "./internal/app/compliance",
		File: "internal/app/compliance/domain.go",
		Old:  "\"CIS-AWS-4.1\": fwExposureNoCIS",
		New:  "\"CIS-AWS-4.1\": fwExposure",
		Why:  "a compliance control rolling up under CIS for a check (EC2 public IP) that no CIS AWS recommendation is evidenced by",
	},

	// ── reachability: the exposure tier ─────────────────────────────────
	//
	// Two guards, two opposite failure modes, one property. `possible` grades how
	// well an exposure is PROVEN; previously it decided whether the
	// exposed_to_internet edge was written at all, so every serverless entry point
	// whose collector cannot prove unauthenticated access sat at infinite distance
	// from the internet with its whole downstream subtree. The fix has to keep
	// pulling in both directions at once: the edge must exist (or the BFS is blind
	// again) and it must not read as observed exposure (or every unproven cloud function
	// starts asserting one).
	{
		Guard: "TestInternetHopsSeedTier", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/reach.go",
		Old:  "const possibleSeedDepth = 1",
		New:  "const possibleSeedDepth = 0",
		Why: "collapsing the tiers at the seed: an unproven, authorizer-gated entry point gets the same +18 " +
			"direct-exposure weight as an observed open path, which floods the page band with inference",
	},
	// The fidelity gate. Both guards exist to catch the SAME defect — a gate
	// that notices a degraded load set and publishes it anyway — from the two sides it
	// can regress from, so they share one mutation, which the harness applies and
	// verifies once per guard. Deleting the return is not a hypothetical shape: it is
	// what asset.AllEdgesForSync once did (set BulkPassFailed, log a warning,
	// carry on) when ClickHouse ran out of memory, publishing a graph missing a
	// large share of its edges and nodes while graph_ladybug_reach_complete read 1.
	{
		Guard: "TestSyncFromSources_AbandonsADegradedRebuild", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/service_sync.go",
		Old:  "\t\treturn fmt.Errorf(\"SyncFromSources: %w: %s\", ErrRebuildRefused, verdict.Reason)\n",
		New:  "\t\t_ = verdict.Reason // logged and continued\n",
		Why: "the gate degrades to a log line: the refusal branch falls through and the candidate is built, " +
			"swapped in and snapshotted, which is the failure itself — off-side build plus atomic swap is " +
			"only a safety property if something actually throws the candidate away",
	},
	{
		Guard: "TestFidelityGateAbandonsBeforeAnySideEffect", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/service_sync.go",
		Old:  "\t\treturn fmt.Errorf(\"SyncFromSources: %w: %s\", ErrRebuildRefused, verdict.Reason)\n",
		New:  "\t\t_ = verdict.Reason // logged and continued\n",
		Why: "same defect from the source side: with no return, every publishing side effect below the gate " +
			"runs on a load set the gate just rejected, and the correlate job reports success",
	},
	{
		Guard: "TestNodeRowsExposedIsConfirmedOnly", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/node_rows.go",
		Old: "\t\tif e.Properties[asset.EdgePropPublicAccess] == asset.PublicAccessPossible {\n" +
			"\t\t\tcontinue\n\t\t}\n",
		New: "",
		Why: "the possible tier asserting observed exposure: `exposed` labels the node in the UI, gates " +
			"toxic_combo, and is the independent witness the adjudicator corroborates a demotion against",
	},
	{
		Guard: "TestInternetReachability_ManagedPublic", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/domain.go",
		Old: "\t\t\t// since nothing counts an edge that was never created.\n" +
			"\t\t\tif a.Metadata[\"public\"] == \"true\" {",
		New: "\t\t\t// since nothing counts an edge that was never created.\n" +
			"\t\t\tif a.Metadata[\"public_access\"] == asset.PublicAccessPossible {\n\t\t\t\tbreak\n\t\t\t}\n\t\t\tif a.Metadata[\"public\"] == \"true\" {",
		Why: "restoring the original defect — a scoring tier governing graph construction, so a real share of " +
			"api_gateway, lambda_function and cloud_function assets get no BFS seed and the loss is invisible downstream",
	},
	{
		Guard: "TestInternetReachability_AWSDualStackPerFamily", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/secgroups.go",
		Old:  "if !cidrset.Cover(cidrset.Parse(r.CIDRs), world) || !checks.PortAddressed(r.Protocol) {",
		New:  "if !cidrset.CoversWorld(r.CIDRs) || !checks.PortAddressed(r.Protocol) {",
		Why:  "a rule open only to ::/0 marks an instance's IPv4 address confirmed internet-exposed",
	},
	{
		Guard: "TestSecurityGroupAllows_SelfReferenceIsASelfLoop", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/secgroups.go",
		Old:  "\t\t\t\tif ref == \"\" {\n",
		New:  "\t\t\t\tif ref == \"\" || ref == sg.ID {\n",
		Why:  "a self-referencing rule, the one rule that lets an SG's members reach each other, is dropped",
	},
	{
		Guard: "TestInternetReachability_AzureUnreadNSGOrSKU", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/azure_nsg.go",
		Old:  "\tcase \"standard\", \"standardv2\":\n",
		New:  "\tcase \"standard\", \"standardv2\", \"\":\n",
		Why:  "a public NIC with no NSG and an unread public IP SKU reads as closed rather than possibly exposed",
	},
	{
		Guard: "TestInternetReachability_AzureUnreadNSGOrSKU", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/azure_nsg.go",
		Old:  "\t\tif !ok {\n\t\t\tunknown = true\n",
		New:  "\t\tif !ok {\n",
		Why:  "an NSG missing from the view reads as absent, so what the read NSGs leave open is reported as confirmed",
	},

	// ── collect: the deletion signal's completeness claim ───────────────
	{
		Guard: "TestCompletedEnumerationsHaveASingleWriter", Pkg: "./internal/collect",
		File: "internal/collect/aws/aws.go",
		Old:  "\t\tresult.MarkComplete(region+\"/\"+family, types, n)",
		New: "\t\tresult.CompletedEnumerations = append(result.CompletedEnumerations,\n" +
			"\t\t\tcollect.ScopeEnumeration{Scope: region + \"/\" + family, Types: types, Count: n})",
		Why: "a hand-rolled append bypasses MarkComplete's validation, so an empty scope key or an unenumerated " +
			"type can be recorded as proven coverage — the one input a future enforce mode would delete real inventory on",
	},

	// ── correlate: the load/scan seam ───────────────────────────────────
	{
		Guard: "TestCorrelationTypesCoverEveryRuleAndGraphSwitch", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/repo.go",
		Old:  "\t\"aws_scp_set\",\n",
		New:  "",
		Why: "a type NewGraph indexes but correlationTypes never loads: the index is always empty and nothing errors — " +
			"how the org-level cap was silently never applied",
	},
	{
		Guard: "TestRulesDeclareTheTypesTheyReadFromTheGraph", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/iam_permissions.go",
		Old:  "return []string{\"iam_role\", \"iam_user\", \"gcp_service_account\", \"aws_scp_set\"}",
		New:  "return []string{\"iam_role\", \"iam_user\", \"gcp_service_account\"}",
		Why:  "a rule that READS a type through the Graph without DECLARING it gets an empty index on every PartialCorrelate and silently drops that cap",
	},
	{
		Guard: "TestAllRulesListIsComplete", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/correlation_types_test.go",
		Old:  "\tHumanIdentityFederation{},\n",
		New:  "",
		Why: "allRules is the hand-maintained list every other correlate guard is built on; " +
			"an omission makes those guards pass vacuously",
		MutatesTest: true,
	},
	{
		Guard: "TestCorrelateScanOrderMatchesSelectOrder", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/repo.go",
		Old: "\targMax(name, synced_at), argMax(type, synced_at), argMax(account_id, synced_at),\n" +
			"\targMax(public_ip, synced_at), argMax(private_ip, synced_at), argMax(domain, synced_at), argMax(tags, synced_at),\n" +
			"\t` + projectMetadataExpr + `\n\tFROM assets\n\tWHERE type IN (%s)",
		New: "\targMax(type, synced_at), argMax(name, synced_at), argMax(account_id, synced_at),\n" +
			"\targMax(public_ip, synced_at), argMax(private_ip, synced_at), argMax(domain, synced_at), argMax(tags, synced_at),\n" +
			"\t` + projectMetadataExpr + `\n\tFROM assets\n\tWHERE type IN (%s)",
		Why: "Scan is positional: transposing two same-typed columns compiles and leaves every asset's Name holding its Type",
	},
	{
		Guard: "TestCorrelateQueriesShareTheSameColumnList", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/repo.go",
		Old:  "\t` + projectMetadataExpr + `\n\tFROM assets\n\tWHERE id IN (%s)\n\tGROUP BY id`",
		New:  "\t` + projectMetadataExpr + `, argMax(region, synced_at)\n\tFROM assets\n\tWHERE id IN (%s)\n\tGROUP BY id`",
		Why:  "a column added to one of the two queries that share scanAssets is a runtime scan mismatch, not a compile error",
	},

	// ── River job routing ───────────────────────────────────────────────
	{
		Guard: "TestChartScheduleEnvCheckCoversPeriodicConfig", Pkg: "./internal/jobs",
		File: "scripts/check-chart-schedule-env.sh",
		Old:  " INTEL_OSV_DISABLED ",
		New:  " ",
		Why:  "a feed switch missing from the CI env check can be set on one leader-electable pod only, so the feed runs or not by which pod leads",
	},
	{
		Guard: "TestAllJobArgsMatchesDeclaredKinds", Pkg: "./internal/jobs",
		File: "internal/jobs/routing.go",
		Old:  "\t\tOptimizeAssetsArgs{},\n",
		New:  "",
		Why:  "allJobArgs drives the real routing table; a kind missing from it drops out of the routing AND out of every queue guard",
	},
	{
		Guard: "TestEveryJobRoutesToARegisteredQueue", Pkg: "./internal/jobs",
		File: "internal/jobs/optimize.go",
		Old:  "\t\tQueue: queueMaintain,\n",
		New:  "\t\tQueue: \"\",\n",
		Why:  "an empty Queue lands on River's unregistered `default` lane: the job reads as scheduled and nothing ever runs it",
	},
	{
		Guard: "TestEveryKindIsConsumedBySomePod", Pkg: "./internal/jobs",
		File: "internal/jobs/optimize.go",
		Old:  "\t\tQueue: queueMaintain,\n",
		New:  "\t\tQueue: \"\",\n",
		Why:  "the mirror property: a kind no pod consumes strands `available` forever",
	},
	{
		Guard: "TestEachPodOnlyConsumesQueuesItCanWork",
		Pkg:   "./internal/jobs",
		File:  "internal/jobs/diskscan.go",
		Old:   "\t\tQueue:       queueDiskScan,\n",
		New:   "\t\tQueue:       queueEnrich,\n",
		Why:   "River fetches by QUEUE alone: a pod consuming a lane that carries a kind it cannot work locks those jobs and errors them at MaxAttempts 1 instead of leaving them for the pod that can",
	},
	{
		Guard: "TestEveryQueueDeclaresItsConcurrency", Pkg: "./internal/jobs",
		File: "internal/jobs/routing.go",
		Old:  "\tqueueGraph:      graphWorkers,\n",
		New:  "",
		Why:  "an unlisted queue silently takes consumedQueues' fallback of one worker — how splitting a lane changes concurrency nobody chose",
	},
	{
		Guard: "TestHeavyScanLanesAreSerial", Pkg: "./internal/jobs",
		File: "internal/jobs/routing.go",
		Old:  "\tqueueContentScan: heavyScanWorkers,\n",
		New:  "\tqueueContentScan: 4,\n",
		Why:  "a heavy-scan lane above one worker multiplies the memory-bound worker pod's concurrent scan budget past its memory limit",
	},
	{
		Guard: "TestEveryJobKindHasAProducer", Pkg: "./internal/jobs",
		File: "internal/jobs/periodic.go",
		Old:  "\t\t\t\treturn OptimizeAssetsArgs{}, scheduledOn(",
		New:  "\t\t\t\targs := OptimizeAssetsArgs{}\n\t\t\t\treturn args, scheduledOn(",
		Why: "a registered worker with no producer: the code compiles, the queue is consumed, river_job never sees a row, " +
			"and the capability reads as shipped",
	},
	{
		Guard: "TestWorkerWiresEveryJobsDep",
		Pkg:   "./internal/jobs",
		File:  "cmd/graph/worker.go",
		Old:   "\t\tDriftAnalysis:  driftAnalysis,\n",
		New:   "",
		Why:   "a Deps field the binary forgets to pass silently disables the worker gated on it — Deps.Profiles was exactly this",
	},
	{
		Guard: "TestOnlyScoreWritersCallRecordDirectly", Pkg: "./internal/jobs",
		File: "internal/jobs/scc.go",
		Old:  "if err := w.findings.RecordObserved(ctx, found); err != nil {",
		New:  "if err := w.findings.Record(ctx, found); err != nil {",
		Why: "a producer that calls Record instead of RecordObserved bypasses carry-forward-enrichment and clobbers " +
			"score/must_fix_class/enriched_at on any re-observation of an existing finding — the exact defect that " +
			"generalizing RecordObserved's carry-forward was meant to close off by construction",
	},
	{
		Guard: "TestAllJobKindsRescuable", Pkg: "./internal/jobs",
		File: "internal/jobs/rescue.go",
		Old:  "\t\trescueEntry[OptimizeAssetsArgs](&OptimizeAssetsWorker{}),\n",
		New:  "",
		Why:  "a kind with no rescue-only registration is permanently DISCARDED by any leader pod that does not work it",
	},

	// ── enrich logic versioning ─────────────────────────────────────────
	{
		Guard: "TestLogicVersionDrivesTheFingerprintPrefix", Pkg: "./internal/app/enrichcache",
		File: "internal/app/enrichcache/fingerprint.go",
		Old:  "\tb.WriteString(LogicVersion)\n\tb.WriteByte('\\n')\n\twriteFingerprintBody(&b, in)",
		New:  "\twriteFingerprintBody(&b, in)",
		Why:  "if Fingerprint stops prefixing with LogicVersion, bumping the version invalidates nothing and the gate keeps serving stale scores",
	},

	// ── must-fix class contract ─────────────────────────────────────────
	{
		Guard: "TestAdjudicationBacklogSQLMirrorsNeedsAdjudication", Pkg: "./internal/app/belief",
		File: "internal/app/belief/repo.go",
		Old:  "AND fe.must_fix_class IN ('', 'elevated', 'routine')",
		New:  "AND fe.must_fix_class IN ('', 'elevated')",
		Why: "an adjudicatable must-fix class missing from the backlog cursor's IN list makes the sweep select " +
			"nothing while the Go gate still says adjudicate — how `routine` (the majority class) would have " +
			"silently emptied the adjudicator's whole population",
	},
	{
		Guard: "TestNoInlineCtxErrCancellationChecks", Pkg: "./internal/app/belief",
		File: "internal/app/belief/sweep.go",
		Old:  "\t\tif isContextCancellation(ctx) {\n\t\t\tres.Deferred += len(sorted) - i\n",
		New:  "\t\tif ctx.Err() != nil {\n\t\t\tres.Deferred += len(sorted) - i\n",
		Why: "a call site checks cancellation inline again, free to drift from the helper " +
			"TestIsContextCancellation pins",
	},
	{
		Guard: "TestEveryCitedTestExists", Pkg: "./internal/guardmutation",
		File: "internal/app/graphstore/sync_phases.go",
		Old:  "unattributed time, which\n// warnIfUnattributed reports.\n",
		New:  "unattributed time, which\n// TestSyncPhasesPartitionTheRebuild bounds.\n",
		Why:  "a comment cites a guard test that does not exist, so a reader believes an invariant is enforced when nothing checks it",
	},
	{
		Guard: "TestConsistencyGateNeverClearsMustFixClass", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/consistency.go",
		Old:  "\t\tres.MustFixClass = MustFixRoutine\n\t\tres.MustFixReason = \"no urgency evidence: the reachability evidence was a category error",
		New:  "\t\tres.MustFixClass = \"\"\n\t\tres.MustFixReason = \"\" // \"no urgency evidence: the reachability evidence was a category error",
		Why: "a gate that CLEARS must_fix_class puts enriched findings back into the \"\" bucket that now means only " +
			"\"never enriched\", re-creating the ambiguity MustFixRoutine exists to remove and poisoning the " +
			"obs.descUnclassified gauge that is supposed to prove it worked",
	},

	// ── HTTP contract ───────────────────────────────────────────────────
	{
		Guard: "TestSpecCoversAllRoutes", Pkg: "./internal/httpsrv",
		File: "internal/httpsrv/server.go",
		Old:  "\tmux.HandleFunc(\"GET /api/assets\", authH.RequireAuth(h.Asset.List))\n",
		New: "\tmux.HandleFunc(\"GET /api/assets\", authH.RequireAuth(h.Asset.List))\n" +
			"\tmux.HandleFunc(\"GET /api/zz-guard-probe\", authH.RequireAuth(h.Asset.List))\n",
		Why: "a route registered but absent from openapi/ — the gap that let ~35 operations escape the contract",
	},

	// ── AWS account-wide settings and identity posture (CSPM round A) ───
	{
		Guard: "TestS3PublicBucketFourFlagTiers", Pkg: "./internal/checks",
		File: "internal/checks/cis.go",
		Old:  `return a.Metadata["public"] == "true" || a.Metadata["bpa_all_enabled"] == "false"`,
		New:  `return a.Metadata["public"] == "true"`,
		Why:  "a bucket whose two neutralizing Block Public Access flags are on but the other two are off reads as compliant, which CIS 3.1.4 and FSBP S3.8 fail",
	},
	{
		Guard: "TestCollectS3Buckets_BPAAllEnabled", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/s3.go",
		Old:  "\tcase own.observed && acct.observed:\n",
		New:  "\tcase own.observed:\n",
		Why:  "an unreadable account-level block may still be a full one, so writing bpa_all_enabled=false from the bucket's settings alone manufactures a finding out of a permission gap",
	},
	{
		Guard: "TestTrailRollupSettings", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/account_settings.go",
		Old:  "\t\tcase \"\":\n\t\t\tunknown = true\n",
		New:  "\t\tcase \"\":\n",
		Why:  "a multi-region trail whose logging status was unreadable would read as not logging, raising 'no CloudTrail' on an account that has one",
	},
	{
		Guard: "TestRoleFullAdminStepsAside", Pkg: "./internal/checks",
		File: "internal/checks/aws_iam_policies.go",
		Old:  " && !dormantAdminRole(a) && !overprivilegedAdminRole(a)",
		New:  " && !dormantAdminRole(a)",
		Why:  "an admin role with Access Advisor evidence would be reported twice, by aws-iam-overprivileged-role and aws-iam-role-full-admin, for one root cause",
	},
	{
		Guard: "TestDateChecksAreUnevaluableWithoutTheirDates", Pkg: "./internal/checks",
		File: "internal/checks/aws_iam_policies.go",
		Old:  "\tAssetType:   \"iam_user\",\n\tTableProbes: dateProbes,\n",
		New:  "\tAssetType:   \"iam_user\",\n",
		Why:  "with no date probe, an unreadable credential report makes the root-use check look evaluated and clean, closing an open root-use finding as fixed",
	},
	{
		Guard: "TestReadRegionSettings", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/region_settings.go",
		Old:  "\tif len(meta) == 0 {\n",
		New:  "\tif len(meta) < 0 {\n",
		Why:  "a region where every settings read was denied must be a skipped collector, or a region-deny SCP stops being recognised and the region's failures stop flagging the sweep",
	},
	{
		Guard: "TestRegionLedgerSettle", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_offered.go",
		Old:  "\tif l.coreOK {\n",
		New:  "\tif true {\n",
		Why:  "an NXDOMAIN from a region whose core EC2 read failed (DNS firewall, allowlisting proxy) would withdraw the service as not offered and the sweep would report complete",
	},
	{
		Guard: "TestRegionLoopSettlesThroughLedger", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/aws.go",
		Old:  "denied, failures := ledger.settle(len(tasks), regionFailures, tally)\n",
		New:  "denied, failures := regionDenied(len(tasks), regionFailures), regionFailures\n",
		Why:  "the region loop would judge regions by raw task count again, so not-offered services either hide a deny-SCP region or are never withdrawn",
	},
	{
		Guard: "TestEndpointNotFound", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_offered.go",
		Old:  "return errors.As(err, &dnsErr) && dnsErr.IsNotFound &&\n\t\tstrings.EqualFold(strings.TrimSuffix(dnsErr.Name, \".\"), host)",
		New:  "return errors.As(err, &dnsErr) && dnsErr.IsNotFound && strings.EqualFold(\"\", \"\")",
		Why:  "any NXDOMAIN in the error chain — a proxy's own name, a FIPS host that does not exist — would read as the service not being offered",
	},
	{
		Guard: "TestRegionalServiceTasks", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_services.go",
		Old:  "svc.regionLimited && !overridden && endpointNotFound(",
		New:  "svc.regionLimited && (overridden || !overridden) && endpointNotFound(",
		Why:  "with a custom, FIPS or dual-stack endpoint the standard host was never dialled, yet its NXDOMAIN would withdraw the service as not offered",
	},
	{
		Guard: "TestRegionalServiceTasks", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_services.go",
		Old:  "if svc.family != \"\" && !partial {",
		New:  "if svc.family != \"\" {",
		Why:  "a run whose sub-listing failed would mark its family complete, so absent resources read as deleted",
	},
	{
		Guard: "TestRegionalServiceTasks", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_services.go",
		Old:  "case err != nil && svc.regionLimited && !overridden && endpointNotFound(err, svc.host(region)):",
		New:  "case err != nil && !overridden && endpointNotFound(err, svc.host(region)):",
		Why:  "a DNS firewall's NXDOMAIN on an everywhere-service (KMS, RDS, DynamoDB) would withdraw it as not offered: a clean, empty region instead of a partial sweep",
	},
	{
		Guard: "TestEverywhereServicesAreNeverRegionLimited", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_catalogue.go",
		Old:  "{name: \"kms\", host: kmsHost,",
		New:  "{name: \"kms\", regionLimited: true, host: kmsHost,",
		Why:  "KMS runs in every commercial region; marking it region-limited lets a DNS firewall's NXDOMAIN read as no keys",
	},
	{
		Guard: "TestRegionLedgerSettle", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_offered.go",
		Old:  "offered := tasks - len(l.candidates) - l.unprovenTasks",
		New:  "offered := tasks - len(l.candidates)",
		Why:  "an unproven capability task (glue ml transforms) would keep a deny-SCP region from reading as denied, so its sweeps go partial forever",
	},
	{
		Guard: "TestRegionLedgerSettle", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/regional_offered.go",
		Old:  "\t\tlog.FromContext(ctx).Warn().Str(\"region\", region).Str(\"service\", c.what).Str(\"host\", host).",
		New:  "\t\tlog.FromContext(ctx).Debug().Str(\"region\", region).Str(\"service\", c.what).Str(\"host\", host).",
		Why:  "a withdrawn service would be silent at the default level, indistinguishable from a clean read",
	},
	{
		Guard: "TestSyncWorkerCarriesSuppressions", Pkg: "./internal/jobs",
		File: "internal/jobs/sync.go",
		Old:  "\t\t\tcarrySuppressions(ctx, w.suppressions, found)\n",
		New:  "",
		Why:  "a check split (aws-s3-public-bucket into public read/write) would resolve the suppressed finding and open an unsuppressed one, so an accepted exception comes back at full severity",
	},
	{
		Guard: "TestNoCollectorJudgesNXDOMAIN", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/notoffered.go",
		Old:  "\t\"errors\"\n\t\"net/http\"\n\n\tawshttp \"github.com/aws/aws-sdk-go-v2/aws/transport/http\"\n)\n",
		New:  "\t\"errors\"\n\t\"net\"\n\t\"net/http\"\n\n\tawshttp \"github.com/aws/aws-sdk-go-v2/aws/transport/http\"\n)\n\nfunc serviceNotOffered(err error) bool {\n\tvar dnsErr *net.DNSError\n\treturn errors.As(err, &dnsErr) && dnsErr.IsNotFound\n}\n",
		Why:  "a collector-level NXDOMAIN shortcut comes back beside the region ledger: a DNS firewall's answer reads as an empty account and resolves every stored finding",
	},
	{
		Guard: "TestAPIGatewayAccessLoggingGradesTheStage", Pkg: "./internal/checks",
		File: "internal/checks/aws_logging.go",
		Old:  "\tAssetType:   \"api_gateway_stage\",\n\t// access_log_destination",
		New:  "\tAssetType:   \"api_gateway\",\n\t// access_log_destination",
		Why:  "the access-log check would grade the API, where the network collector writes no stage key, so APIGateway.9 and CIS 4.10 never fire",
	},
	{
		Guard: "TestChecksNeverFireOnAbsentData", Pkg: "./internal/checks",
		File: "internal/checks/aws_logging.go",
		Old:  "return a.Metadata[\"logging_flow\"] == \"false\" && a.Metadata[\"logging_alert\"] == \"false\" && a.Metadata[\"logging_tls\"] == \"false\"",
		New:  "return a.Metadata[\"logging_flow\"] == \"false\"",
		Why:  "a firewall delivering alert logs would be reported as logging nothing because it has no flow log",
	},
	{
		Guard: "TestPolicyPublicGrants", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/s3_exposure.go",
		Old:  "return awspolicy.HasCondition(s.Condition) && !awspolicy.RestrictsCaller(s.Condition)",
		New:  "return awspolicy.HasCondition(s.Condition)",
		Why:  "a VPC- or organisation-scoped GetObject beside a public GetBucketAcl would be stamped public_read=true and graded Critical",
	},
	{
		Guard: "TestReadSecurityContact", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/account_settings.go",
		Old:  "if awsErrCode(err) == \"ResourceNotFoundException\" {",
		New:  "if err != nil {",
		Why:  "an AccessDenied on account:GetAlternateContact would be recorded as 'no security contact', a finding minted from a missing permission",
	},
	{
		Guard: "TestSageMakerNotebookVPCAndInternetFireOnce", Pkg: "./internal/checks",
		File: "internal/checks/aws_sagemaker.go",
		Old:  "return a.Metadata[\"direct_internet_access\"] == \"true\" && a.Metadata[\"subnet_id\"] != \"\"",
		New:  "return a.Metadata[\"direct_internet_access\"] == \"true\"",
		Why:  "a notebook outside any VPC (always direct internet) is reported by both the no-VPC and the direct-internet check — one root cause, two findings",
	},
	{
		Guard: "TestSageMakerMonitoringJobEncryptionScope", Pkg: "./internal/checks",
		File: "internal/checks/aws_sagemaker.go",
		Old:  "return err == nil && n >= 2",
		New:  "return err != nil || n >= 2",
		Why:  "a model-bias job definition whose instance count was never read is graded as multi-instance and fires SageMaker.15 on missing data",
	},
	{
		Guard: "TestStampSageMakerNotebookVPC", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/sagemaker.go",
		Old:  "if isDefault, ok := defaultVPC[vpcBySubnet[a.Metadata[\"subnet_id\"]]]; ok {",
		New:  "if isDefault := defaultVPC[vpcBySubnet[a.Metadata[\"subnet_id\"]]]; true {",
		Why:  "a notebook whose subnet or VPC is missing from the sweep would carry in_default_vpc=\"\" — an invented observation instead of unknown",
	},
	{
		Guard: "TestReadAgentCore", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/agentcore.go",
		Old:  "if g.AuthorizerType != \"\" {",
		New:  "if true {",
		Why:  "a gateway listed without an authorizer type would record an empty authorizer — the field the no-inbound-auth check grades — instead of leaving it unknown",
	},
	{
		Guard: "TestCFNStackChecksGradeRootStacksOnly", Pkg: "./internal/checks",
		File: "internal/checks/aws_app_integration.go",
		Old:  "return a.Metadata[\"nested\"] == \"false\" && a.Metadata[\"termination_protection\"] == \"false\"",
		New:  "return a.Metadata[\"termination_protection\"] == \"false\"",
		Why:  "every nested stack repeats its root stack's missing termination protection — a setting it cannot change — one root cause reported once per nested stack",
	},
	{
		Guard: "TestReadConnectInstances", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/connect.go",
		Old:  "return \"\", errNoFlowLogsAttribute",
		New:  "return \"false\", nil",
		Why:  "an attribute listing that never names CONTACTFLOW_LOGS would be recorded as flow logging off, a finding minted from data the API did not return",
	},
	{
		Guard: "TestReadMQBrokers", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/mq.go",
		Old:  "if b.EngineType == mqtypes.EngineTypeActivemq {",
		New:  "if b.EngineType != mqtypes.EngineType(\"\") {",
		Why:  "RabbitMQ brokers, which have no audit log at all, would be graded as ActiveMQ brokers with audit logging off",
	},
	{
		Guard: "TestParallelToolCallsKeepOrderAndRespectSerial", Pkg: "./internal/llm/toolloop",
		File: "internal/llm/toolloop/toolloop.go",
		Old:  "isSerial := func(tc llm.ToolCall) bool { return serial != nil && serial.Serial(tc.Name) }",
		New:  "isSerial := func(tc llm.ToolCall) bool { return serial != nil && serial.Serial(tc.Name) && false }",
		Why:  "a live tool would run beside other calls, so its gate check and audit row could interleave out of the order the model asked",
	},
	{
		Guard: "TestWrapUpNudgesAndRefusesFurtherTools", Pkg: "./internal/llm/toolloop",
		File: "internal/llm/toolloop/toolloop.go",
		Old:  "\t\tif tr.WrappedUp {\n\t\t\t// Answer every call so the conversation stays well formed, run none.",
		New:  "\t\tif tr.WrappedUp && false {\n\t\t\t// Answer every call so the conversation stays well formed, run none.",
		Why:  "the model is told to stop calling tools but its calls still run, so the wrap-up spends the budget it exists to save",
	},
	{
		Guard: "TestBudgetedSettings", Pkg: "./internal/db",
		File: "internal/db/clickhouse.go",
		Old:  "if cur, ok := seconds(settings[\"max_execution_time\"]); !ok || cur <= 0 || cur > b.MaxExecutionTime {",
		New:  "if cur, ok := seconds(settings[\"max_execution_time\"]); !ok || cur <= 0 || cur > b.MaxExecutionTime || true {",
		Why:  "an LLM tool budget would overwrite a caller's tighter max_execution_time, loosening a bound the query was tuned to",
	},
	{
		Guard: "TestReadEMRUnknownAndUnused", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/emr.go",
		Old:  "\tif len(clusters) > 0 {\n",
		New:  "\tif true {\n",
		Why:  "a region with no EMR cluster would still get an emr_settings asset, raising a block-public-access finding for a service nobody uses",
	},
	{
		Guard: "TestReadAppSync", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/appsync.go",
		Old:  "case errors.As(err, &notFound):",
		New:  "case errors.As(err, &notFound) || err != nil:",
		Why:  "a denied appsync:GetApiCache would be recorded as 'no cache', reading an unread cache as one with nothing to encrypt",
	},
	{
		Guard: "TestReadCodeBuildProjects", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/codebuild.go",
		Old:  "if v.Type != \"\" && v.Type != cbtypes.EnvironmentVariableTypePlaintext {",
		New:  "if v.Type == \"never\" {",
		Why:  "an AWS key name resolved from Parameter Store or Secrets Manager would be reported as a plaintext credential in the project",
	},
	{
		Guard: "TestCognitoUserPoolNoMFA", Pkg: "./internal/checks",
		File: "internal/checks/aws_codebuild_cognito.go",
		Old:  " && a.Metadata[\"password_only_sign_in\"] == \"true\"",
		New:  "",
		Why:  "a pool that signs users in with a passwordless factor would be reported for password-only MFA, outside the control's scope",
	},
	{
		Guard: "TestCollectECSResources_LatestTaskDefinitions", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/ecs_registry.go",
		Old:  "\tif sw.serviceTaskDefs[arn] {\n\t\treturn nil\n\t}\n",
		New:  "",
		Why:  "a task-definition revision a service runs is emitted again as an ecs_task_definition, so one privileged container is reported twice",
	},
	{
		Guard: "TestCollectECRRepos_LifecyclePolicy", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/services.go",
		Old:  "\treturn false, false\n}",
		New:  "\treturn false, true\n}",
		Why:  "an AccessDenied on ecr:GetLifecyclePolicy would be recorded as 'no lifecycle policy' on every repository",
	},
	{
		Guard: "TestEKSNodegroupUnsupportedVersionStepsAsideForCluster", Pkg: "./internal/checks",
		File: "internal/checks/aws_container_inventory.go",
		Old:  " && !eksPastStandardSupport(a.Metadata[\"cluster_version\"], now)",
		New:  "",
		Why:  "every node group of a cluster past support is reported beside the cluster's own finding — one upgrade, many findings",
	},
	{
		Guard: "TestECSTaskSetPublicIPStepsAsideForService", Pkg: "./internal/checks",
		File: "internal/checks/aws_container_inventory.go",
		Old:  "return a.Metadata[\"task_sets_public_ip\"] != \"\" && a.Metadata[\"assign_public_ip\"] != \"ENABLED\"",
		New:  "return a.Metadata[\"task_sets_public_ip\"] != \"\"",
		Why:  "a service assigning public IPs is reported by the service check and again by the task-set check for one exposure",
	},
	{
		Guard: "TestSecretRotationOverdueByNextRotationDate", Pkg: "./internal/checks",
		File: "internal/checks/aws_data_services.go",
		Old:  "ok && since > secretRotationGraceDays {",
		New:  "ok && since >= 0 {",
		Why:  "a rotation still inside its window on the scheduled day reads as a failed rotation",
	},
	{
		Guard: "TestReadCloudFrontStampsOriginAndViewerFacts", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudfront_origins.go",
		Old:  "case http.StatusForbidden, http.StatusMovedPermanently:\n\t\treturn bucketExistsUnowned",
		New:  "case http.StatusForbidden, http.StatusMovedPermanently:\n\t\treturn bucketMissing",
		Why:  "a bucket that exists (HeadBucket 403) would be reported as a dangling, claimable CloudFront origin",
	},
	{
		Guard: "TestReadCloudFrontForeignOriginBucket", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudfront.go",
		Old:  "case err != nil:\n\t\t\tbuckets[name] = bucketUnknown",
		New:  "case err != nil:\n\t\t\tbuckets[name] = bucketPresent",
		Why:  "an unreadable bucket list would vouch for every 403 origin bucket as the account's own, hiding a bucket another account holds",
	},
	{
		Guard: "TestCloudFrontLoggingSources", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudfront.go",
		Old:  "\tcase v2Read:",
		New:  "\tdefault:",
		Why:  "a distribution whose standard-logging v2 deliveries could not be read would be recorded as not logging",
	},
	{
		Guard: "TestReadWAFv2", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/waf.go",
		Old:  "rules, err := wafv2Rules(ctx, client, a.Type, scope, s)",
		New:  "rules, _ := wafv2Rules(ctx, client, a.Type, scope, s)\n\t\t\tvar err error",
		Why:  "a web ACL whose GetWebACL failed would be stamped rule_count=0 and reported as an empty ACL",
	},
	{
		Guard: "TestReadMacie", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/region_detection.go",
		Old:  "\t\tstrings.Contains(apiErr.ErrorMessage(), \"Macie is not enabled\")\n",
		New:  "\t\ttrue\n",
		Why:  "a role missing macie2:GetMacieSession gets the same AccessDeniedException code as a region without Macie; without the message test every region reads as Macie disabled",
	},
	{
		Guard: "TestReadSecurityHubAndAccessAnalyzer", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/region_detection.go",
		Old:  "\tcase awsErrCode(err) == \"InvalidAccessException\":\n",
		New:  "\tcase err != nil:\n",
		Why:  "a denied securityhub:DescribeHub would be recorded as Security Hub disabled in every region",
	},
	{
		Guard: "TestReadConfig", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/region_detection.go",
		Old:  "\t\tif awssdk.ToString(out.ConfigurationRecorders[i].ServicePrincipal) == \"\" {\n",
		New:  "\t\tif true {\n",
		Why:  "Security Hub's internal service-linked recorder would pass for the account's own AWS Config recorder, hiding a region with no configuration history",
	},
	{
		Guard: "TestReadGuardDutyDetector", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/guardduty_detector.go",
		Old:  "\tif !enabled {\n\t\treturn nil\n\t}\n",
		New:  "",
		Why:  "a suspended detector would carry its protection-plan keys, so one disabled GuardDuty becomes a finding per plan as well",
	},
	{
		Guard: "TestTrailSelectorRollup", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudtrail_selectors.go",
		Old:  "\t\tif ok || !unread {\n",
		New:  "\t\tif ok || unread || !unread {\n",
		Why:  "a trail whose selectors or logging status were unread would settle the account as recording no management or S3 data events",
	},
	{
		Guard: "TestEventSelectorMeta", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudtrail_selectors.go",
		Old:  "\"AWS::S3::Object\" && coversAllBuckets(dr.Values) {",
		New:  "\"AWS::S3::Object\" {",
		Why:  "a data-event selector scoped to one bucket would count as logging S3 objects for every bucket, passing CIS 4.8/4.9",
	},
	{
		Guard: "TestCISAlarmSettings_TrailQualification", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudwatch_alarms.go",
		Old:  "\t\tif !ok || acct != accountID {\n",
		New:  "\t\tif !ok || acct == \"\" {\n",
		Why:  "an organization trail's log group in the management account would be searched from a member account, find no filters, and raise fifteen missing-alarm findings that member cannot fix",
	},
	{
		Guard: "TestCISAlarmSettings_Chain", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudwatch_alarms.go",
		Old:  "strings.HasPrefix(arn, \"arn:\")",
		New:  "arn != \"\"",
		Why:  "a topic whose only subscription is PendingConfirmation notifies nobody, yet would satisfy the alarm chain",
	},
	{
		Guard: "TestCISAlarmPatterns_Semantics", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/cloudwatch_alarms.go",
		Old:  "\t\tif t != want && !slices.Contains(c.allowed, t) {\n",
		New:  "\t\tif t != want && t.field == \"\" {\n",
		Why:  "a CIS alarm filter narrowed by an extra AND-ed condition, or with its event names chained by &&, would pass although it never alerts on most of the events",
	},
	{
		Guard: "TestAnnotateFlowLogs", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/vpc_flowlogs.go",
		Old:  "(fl.TrafficType == ec2types.TrafficTypeAll || fl.TrafficType == ec2types.TrafficTypeReject)",
		New:  "fl.TrafficType != \"\"",
		Why:  "an ACCEPT-only flow log misses the rejected traffic CIS 4.7 / EC2.6 exist to record, and would pass",
	},
	{
		Guard: "TestVPCFlowLogsDisabled_SkipsOnlyIdleDefaultVPCs", Pkg: "./internal/checks",
		File: "internal/checks/aws_logging.go",
		Old:  "a.Metadata[\"in_use\"] != \"false\"",
		New:  "a.Metadata[\"in_use\"] == \"true\"",
		Why:  "a default VPC whose network interfaces could not be read would be assumed idle and silently skipped",
	},

	// ── check registry / scoring ────────────────────────────────────────
	{
		Guard: "TestHygieneCeilingChecksAreRegistered", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_hygiene_ceiling.go",
		Old:  "\t\"aws-iam-user-no-mfa\":            ",
		New:  "\t\"aws-iam-user-no-mfa-collapsed\":  \"probe\",\n\t\"aws-iam-user-no-mfa\":            ",
		Why:  "a ceiling keyed on a check ID that no longer exists is silently inert while the survivor inherits its population",
	},
	{
		Guard: "TestChecksNeverFireOnAbsentData", Pkg: "./internal/checks",
		File: "internal/checks/cspm_expanded.go",
		Old:  "return err == nil && n < rdsMinBackupRetentionDays &&",
		New:  "return (err != nil || n < rdsMinBackupRetentionDays) &&",
		Why:  "reading a MISSING metadata key as a violation manufactures findings across the estate the moment a collector loses a permission",
	},
	{
		Guard: "TestSGWorldOpenChecksFireOncePerGroup", Pkg: "./internal/checks",
		File: "internal/checks/aws_compute_network.go",
		Old:  "if !slices.Contains(adminPorts, p) && !slices.Contains(databasePorts, p) {",
		New:  "if !slices.Contains(databasePorts, p) {",
		Why:  "a world-open SSH rule is reported by the admin-port check AND the high-risk-port check — one exposure, two findings",
	},
	{
		Guard: "TestNACLWorldOpenAdminPort_RuleOrder", Pkg: "./internal/checks",
		File: "internal/checks/aws_vpc_edge.go",
		Old:  "if cidrset.Cover(*side, world) {",
		New:  "if side == &allowed && cidrset.Cover(*side, world) {",
		Why:  "a lower-numbered world deny no longer decides first, so an ACL that blocks SSH before allowing it is reported as world-open",
	},
	{
		Guard: "TestCoversWorld", Pkg: "./internal/cidrset",
		File: "internal/cidrset/cidrset.go",
		Old:  "return Cover(ps, lo) && Cover(ps, hi)",
		New:  "return Cover(ps, lo) || Cover(ps, hi)",
		Why:  "half the internet reads as all of it, so a 0.0.0.0/1 rule is reported world-open and a split deny is credited with blocking everyone",
	},
	{
		Guard: "TestNSGAllowsWorldPort_DenyMustCoverTheAllowsDestination", Pkg: "./internal/checks",
		File: "internal/checks/azure.go",
		Old:  "case NSGDestinationsCover(denies, r.NSGDestination):",
		New:  "case len(denies) > 0:",
		Why:  "a Deny on one subnet is credited with closing an Allow to every destination, so SSH open to the rest of the network reads as closed",
	},
	{
		Guard: "TestTrust_AllowConditionNarrowsOnlyWhenItPinsTheCaller", Pkg: "./internal/app/ciem",
		File: "internal/app/ciem/trust.go",
		Old:  "publicHere = !awspolicy.RestrictsCaller(a.Condition) && len(confinedHere) == 0",
		New:  "publicHere = !awspolicy.HasCondition(a.Condition) && len(confinedHere) == 0",
		Why:  "any Condition on a wildcard trust reads as narrowing, so a TLS- or MFA-only gate clears the Critical public-trust finding and caps the role as cross-account",
	},
	{
		Guard: "TestCollectVPCs_EndpointServices", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/network.go",
		Old:  "services, err := vpcEndpointServices(ctx, client, region)\n\tif err != nil {",
		New:  "services, err := vpcEndpointServices(ctx, client, region)\n\tif err != nil && services != nil {",
		Why:  "a denied DescribeVpcEndpoints stamps every VPC with no endpoints, minting a missing-endpoint finding per VPC from a missing permission",
	},
	{
		Guard: "TestReadVPNConnections", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/vpn.go",
		Old:  "if len(vpn.VgwTelemetry) > 0 {",
		New:  "if vpn.VgwTelemetry != nil || true {",
		Why:  "a connection described without tunnel telemetry reads as zero tunnels down — healthy — instead of unknown",
	},
	{
		Guard: "TestELBListenerChecksDoNotOverlap", Pkg: "./internal/checks",
		File: "internal/checks/aws_elb.go",
		Old:  "return lbType(a, lbTypeClassic, lbTypeNetwork) && len(listedValues(a, \"plaintext_listeners\")) > 0",
		New:  "return len(listedValues(a, \"plaintext_listeners\")) > 0",
		Why:  "an ALB's port-80 HTTPS redirect is reported as a plaintext listener, and a forwarding HTTP listener gets two findings for one root cause",
	},
	{
		Guard: "TestELBDesyncAndInvalidHeaderStepAside", Pkg: "./internal/checks",
		File: "internal/checks/aws_elb.go",
		Old:  "return lbType(a, lbTypeApplication) && a.Metadata[\"drop_invalid_header_fields\"] == \"false\" &&\n\t\t\tdesyncDefended(a.Metadata[\"desync_mitigation_mode\"])",
		New:  "return lbType(a, lbTypeApplication) && a.Metadata[\"drop_invalid_header_fields\"] == \"false\"",
		Why:  "a monitor-mode ALB is reported twice for one HTTP-desync root cause, and an unread desync mode no longer holds the finding open",
	},
	{
		Guard: "TestCollectLoadBalancers_FailedReadsOmitTheirKeys", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/elb_detail.go",
		Old:  "\t\t\tredirectKnown = false\n",
		New:  "",
		Why:  "a denied elbv2:DescribeRules is written as 'no HTTP listener lacks a redirect', closing ELB.1 findings as fixed",
	},
	{
		Guard: "TestRedirectsToHTTPS", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/elb_detail.go",
		Old:  "\t\tcase elbv2types.ActionTypeEnumForward:\n\t\t\treturn false\n",
		New:  "",
		Why:  "an HTTP listener with a redirect default but a forwarding rule serves the app in clear text and still passes ELB.1",
	},
	{
		Guard: "TestAPIGatewayPublicEndpointStepsAsideForUnauthenticatedRoutes", Pkg: "./internal/checks",
		File: "internal/checks/cspm_serverless.go",
		Old:  "return a.Metadata[\"public\"] == \"true\" && !unauthenticatedRoutes(a)",
		New:  "return a.Metadata[\"public\"] == \"true\"",
		Why:  "an HTTP API with unauthenticated routes is reported twice — reachable (Medium) and unauthenticated (High) — for one root cause",
	},
	{
		Guard: "TestReadAPIGatewayV2", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/apigatewayv2.go",
		Old:  "return nil, 0, fmt.Errorf(\"unauthorizedRoutes: %w\", err)",
		New:  "return nil, 0, nil",
		Why:  "a denied GetRoutes is recorded as 'no unauthenticated routes', closing the High finding as fixed on a missing permission",
	},
	{
		Guard: "TestReadSSMDocuments", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/ssm_documents.go",
		Old:  "accounts = append(accounts, out.AccountIds...)\n\t\tif out.NextToken == nil {",
		New:  "accounts = append(accounts, out.AccountIds...)\n\t\tif true {",
		Why:  "a document shared with 'all' on a later permission page reads as private — a public document with no finding",
	},
	{
		Guard: "TestEKSPublicEndpointHonoursRestrictedCIDRs", Pkg: "./internal/checks",
		File: "internal/checks/breadth.go",
		Old:  "return a.Metadata[\"endpoint_public_access\"] == \"true\" && csvHasWorldCIDR(a.Metadata[\"public_access_cidrs\"])",
		New:  "return a.Metadata[\"endpoint_public_access\"] == \"true\" || csvHasWorldCIDR(a.Metadata[\"public_access_cidrs\"])",
		Why:  "an EKS endpoint restricted to corporate CIDRs — the remediation the check recommends — keeps firing as world-exposed",
	},
	{
		Guard: "TestECRScanningDisabledHonoursRegistryScanning", Pkg: "./internal/checks",
		File: "internal/checks/breadth.go",
		Old:  "if a.Metadata[\"registry_scan_rule\"] != \"none\" {",
		New:  "if a.Metadata[\"registry_scan_rule\"] == \"ignored\" {",
		Why:  "repositories scanned by a registry-level (enhanced/Inspector) rule are reported as never scanned",
	},
	{
		Guard: "TestRDSInstanceChecksSkipClusterMembers", Pkg: "./internal/checks",
		File: "internal/checks/cspm_expanded.go",
		Old:  "return !observedNone(a, \"db_cluster_id\") || strings.HasPrefix(a.Metadata[\"engine\"], \"aurora\")",
		New:  "return strings.HasPrefix(a.Metadata[\"engine\"], \"aurora\")",
		Why:  "Multi-AZ DB cluster members (MultiAZ=false by design) are reported as single-AZ instances, and an unread membership grades as standalone",
	},
	{
		Guard: "TestIMDSChecksExemptDisabledEndpoint", Pkg: "./internal/checks",
		File: "internal/checks/eks_node_registry.go",
		Old:  "return a.Metadata[\"http_tokens\"] == \"optional\" && a.Metadata[\"http_endpoint\"] != \"disabled\"",
		New:  "return a.Metadata[\"http_tokens\"] == \"optional\"",
		Why:  "an instance with the metadata endpoint switched off is reported as IMDSv1-exposed",
	},
	{
		Guard: "TestLambdaDeprecatedRuntimeTable", Pkg: "./internal/checks",
		File: "internal/checks/aws_lifecycle.go",
		Old:  "return ok && !time.Now().Before(d)",
		New:  "return ok && d.Year() > 0",
		Why:  "every listed Lambda runtime fires, including supported ones whose deprecation date is still ahead",
	},
	{
		Guard: "TestCollectECRRepos_RegistryScanning", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/ecr_scanning.go",
		Old:  "if rule.ScanFrequency == ecrtypes.ScanFrequencyManual || rule.ScanFrequency == \"\" {",
		New:  "if rule.ScanFrequency == \"\" {",
		Why:  "a MANUAL registry rule (which scans nothing automatically) is read as scanning the repository",
	},
	{
		Guard: "TestChecksNeverFireOnAbsentData", Pkg: "./internal/checks",
		File: "internal/checks/gcp_cloudsql.go",
		Old:  "v, ok := cloudSQLFlag(a, \"POSTGRES\", \"db_flag_log_connections\")\n\t\treturn ok && v != \"on\"",
		New:  "v, _ := cloudSQLFlag(a, \"POSTGRES\", \"db_flag_log_connections\")\n\t\treturn v != \"on\"",
		Why:  "a Cloud SQL instance whose flag list was never read fires every unset-is-a-violation flag check at once",
	},
	{
		Guard: "TestCloudSQLNoSSL", Pkg: "./internal/checks",
		File: "internal/checks/gcp_cloudsql.go",
		Old:  "\tcase \"ENCRYPTED_ONLY\", \"TRUSTED_CLIENT_CERTIFICATE_REQUIRED\":\n\t\treturn false\n",
		New:  "",
		Why:  "an instance enforcing TLS through sslMode reports requireSsl=false and is flagged as accepting cleartext",
	},
	{
		Guard: "TestGKENetworkPolicyDataplaneV2", Pkg: "./internal/checks",
		File: "internal/checks/gcp_gke.go",
		Old:  "return ok && dp != \"ADVANCED_DATAPATH\" && a.Metadata[\"network_policy\"] == \"false\"",
		New:  "return ok && dp == dp && a.Metadata[\"network_policy\"] == \"false\"",
		Why:  "a Dataplane V2 cluster, which enforces NetworkPolicy while its addon reads disabled, is reported as enforcing none",
	},
	{
		Guard: "TestCollect_AutomountResolvesFromServiceAccount", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/pods_hardening.go",
		Old:  "if _, set := meta[\"automount_sa_token\"]; set || !listed {",
		New:  "if _, set := meta[\"automount_sa_token\"]; set {",
		Why: "a namespace whose ServiceAccount list failed defaults every deferring pod to a mounted token — an " +
			"unread SA setting becomes a k8s-automount-sa-token finding on every workload in the namespace",
	},
	{
		Guard: "TestAutomountSATokenCoversDefaultServiceAccount", Pkg: "./internal/checks",
		File: "internal/checks/k8s_workload.go",
		Old:  "return !onDefaultSA || a.Metadata[\"automount_sa_token_set_on_pod\"] == \"true\"",
		New:  "return !onDefaultSA",
		Why:  "pods on the default ServiceAccount are skipped outright again — the case CIS 5.1.5/5.1.6 care about most",
	},
	{
		Guard: "TestK8sNamespaceExemptionsAreDescribed", Pkg: "./internal/checks",
		File: "internal/checks/k8s_workload.go",
		Old:  "compromise the entire cluster.\" + k8sSystemPodNote,",
		New:  "compromise the entire cluster.\",",
		Why:  "k8s-privileged-container skips kube-system and the other system namespaces without saying so on its findings or in docs/cspm-coverage.md",
	},
	{
		Guard: "TestBindingSubjectChecks", Pkg: "./internal/checks",
		File: "internal/checks/k8s_rbac_bindings.go",
		Old:  "\t\ta.Metadata[\"platform_managed\"] == \"false\"\n}",
		New:  "\t\ta.Metadata[\"platform_managed\"] != \"true\"\n}",
		Why: "a binding collected before platform_managed existed reads as org-owned, so the bootstrap " +
			"system:masters and system:authenticated bindings every cluster ships become findings",
	},
	{
		Guard: "TestRBACAttacksSurface", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "if slices.ContainsFunc(stock.subjectSets, func(set []string) bool { return slices.Equal(set, got) }) {",
		New:  "if len(got) >= 0 {",
		Why: "a binding with a stock name and roleRef is the platform's whatever it names, so adding User/alice to " +
			"the bootstrap cluster-admin binding grants cluster-admin unreported",
	},
	{
		Guard: "TestPlatformManagedBinding", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "|| stock.roleKind != b.roleKind || stock.roleRef != b.roleRef {",
		New:  "{",
		Why: "a stock binding name repointed at cluster-admin — system:controller:job-controller granting it to its " +
			"own SA — still reads as the platform's",
	},
	{
		Guard: "TestFreshDistroObjectsOnWrongDistroReport", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "func (e platformEnv) has(d distro) bool { return d == distroUpstream || e[d] }",
		New:  "func (e platformEnv) has(d distro) bool { return d != \"\" || e[d] }",
		Why: "every distribution's tables apply to every cluster, so aws-node with `*` created on a non-EKS cluster, " +
			"or kubeadm:cluster-admins on one that is not kubeadm, is a silent cluster-admin",
	},
	{
		Guard: "TestStockRoleInjectionReports", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "if len(injected) == 0 && !wildVerbs && !wildResources {",
		New:  "if len(injected) >= 0 {",
		Why: "a rule added to a stock role — {*,*,*} on system:kube-scheduler, aws-node or a system:controller role, " +
			"which reconciliation never removes — stays suppressed as platform-managed",
	},
	{
		Guard: "TestStockClusterRBACIsSilent", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "if c == \"\" || base[c] || base[strings.TrimSuffix(c, dangerSuffixScoped)] {",
		New:  "if c == \"\" {",
		Why: "the baseline no longer subtracts a stock role's by-design grants, so every stock cluster reports " +
			"its built-ins and controllers as injected",
	},
	{
		Guard: "TestIsEKSIssuer", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/identity.go",
		Old:  "(strings.HasSuffix(host, \".amazonaws.com\") || strings.HasSuffix(host, \".amazonaws.com.cn\"))",
		New:  "(host != \"\" || strings.HasSuffix(host, \".amazonaws.com.cn\"))",
		Why: "any issuer host starting oidc.eks. reads as EKS, so EKS's stock RBAC tuples apply on a cluster whose " +
			"issuer merely looks like one",
	},
	{
		Guard: "TestScopedBaselineDoesNotExplainUnscopedGrant", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "if c == \"\" || base[c] || base[strings.TrimSuffix(c, dangerSuffixScoped)] {",
		New:  "if c == \"\" || base[c] || base[strings.TrimSuffix(c, dangerSuffixScoped)] || base[c+dangerSuffixScoped] {",
		Why: "a scoped baseline explains the unscoped grant, so kubeadm:kubeadm-certs widened from the one " +
			"kubeadm-certs Secret to every Secret stays suppressed",
	},
	{
		Guard: "TestRBACAttacksSurface", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "if orgBound[a.ID] && !builtin {",
		New:  "if orgBound[a.ID] && !builtin && false {",
		Why: "a stock role an organisation binding grants — system:kubelet-api-admin bound to an eks:-named user — " +
			"stays suppressed, so the kubelet access it hands out is never reported",
	},
	{
		Guard: "TestPlatformClusterAdminReportsAtInfo", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac_platform.go",
		Old:  "\treturn !mastersOnly\n",
		New:  "\treturn !mastersOnly && false\n",
		Why:  "kubeadm:cluster-admins and eks:addon-cluster-admin, standing cluster-admin grants, are fully silent",
	},
	{
		Guard: "TestAssessK8sRBACMustFix_PlatformUsersAreInternal", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/mustfix_k8s_rbac.go",
		Old:  "if !isExternalRBACSubject(s) || platform[s] {",
		New:  "if !isExternalRBACSubject(s) {",
		Why:  "EKS's own eks:addon-manager reads as an identity from outside the cluster, elevating every grant it holds",
	},
	{
		Guard: "TestGrantToEveryoneReadsUnsuppressedRole", Pkg: "./internal/checks",
		File: "internal/checks/rbac_namespaced.go",
		Old:  "return privilegedRoleRef(a) || a.Metadata[\"dangerous_perms_detail\"] != \"\" || a.Metadata[\"role_wildcard_verbs\"] == \"true\"",
		New:  "return privilegedRoleRef(a)",
		Why: "a grant to everyone is judged on the platform-suppressed flags, so a forged-label wildcard role or an " +
			"aggregated view with Secrets bound to system:authenticated is not Critical",
	},
	{
		Guard: "TestRBACNonAttacksStaySilent", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac.go",
		Old:  "\t\t\t\tif core && verbs.any(\"create\", \"get\", \"*\") {\n\t\t\t\t\tadd(dangerCategoryNodeProxy, scoped)",
		New:  "\t\t\t\tif core {\n\t\t\t\t\tadd(dangerCategoryNodeProxy, scoped)",
		Why: "a read-only list/watch on every resource reports kubelet access it does not have, so every " +
			"monitoring role is a node-proxy finding",
	},
	{
		Guard: "TestRoleAssets_WildcardVerbsMeansVerbsOnly", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac.go",
		Old:  "return slices.ContainsFunc(rules, func(r rbacv1.PolicyRule) bool { return slices.Contains(r.Verbs, \"*\") })",
		New:  "return slices.ContainsFunc(rules, func(r rbacv1.PolicyRule) bool { return slices.Contains(r.Verbs, \"*\") || slices.Contains(r.APIGroups, \"*\") })",
		Why: "a read-only apiGroups: [\"*\"] reads as wildcard verbs, which every binding to the role inherits as a " +
			"privilege signal",
	},
	{
		Guard: "TestDangerousPermissions_WildcardsCoverEveryCapability", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac.go",
		Old:  "for _, res := range expandWildcardResources(r.Resources) {",
		New:  "for _, res := range r.Resources {",
		Why: "a `*` rule no longer expands to the resources it covers, so a full-wildcard role evidences none of the " +
			"per-capability CIS 5.1.x controls and reads as passing them",
	},
	{
		Guard: "TestDangerousPermissions_WildcardsCoverEveryCapability", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/rbac.go",
		Old:  "\t\tcase strings.HasPrefix(r, \"*/\"):\n",
		New:  "\t\tcase strings.HasSuffix(r, \"/*\"):\n",
		Why: "the wildcard form reverts to `<resource>/*`, which RBAC does not accept, so `*/exec` (exec into every " +
			"pod) is missed and `pods/*` (a grant of nothing) is reported",
	},
	{
		Guard: "TestPodChecksEvaluateLivePodsOnly", Pkg: "./internal/checks",
		File: "internal/checks/k8s_pod_security.go",
		Old:  "return p != \"Succeeded\" && p != \"Failed\"",
		New:  "return p != \"Succeeded\"",
		Why:  "every failed CronJob run's pod produces its own copy of each pod-security finding",
	},
	{
		Guard: "TestPodHardeningSignals_RecordsEveryWeakening", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/pods_hardening.go",
		Old:  "return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(c))), \"CAP_\")",
		New:  "return strings.TrimSpace(string(c))",
		Why:  "CAP_SYS_ADMIN and sys_admin — spellings the runtime accepts — no longer count as SYS_ADMIN",
	},
	{
		Guard: "TestCollectorChartRBACMatchesReads", Pkg: "./internal/collect/kubernetes",
		File: "deploy/helm-chart/graph/templates/kubernetes-collector-rbac.yaml",
		Old:  `resources: ["namespaces", "pods", "services", "serviceaccounts", "configmaps"]`,
		New:  `resources: ["namespaces", "pods", "services", "serviceaccounts"]`,
		Why: "a resource the collector lists but the opt-in ClusterRole does not grant fails every sync " +
			"with Forbidden on a fresh install",
	},
	{
		Guard: "TestRBACCapabilityChecks", Pkg: "./internal/checks",
		File: "internal/checks/k8s_rbac_grants.go",
		Old:  "\tif a.Type != \"k8s_cluster_role\" && a.Type != \"k8s_role\" {\n\t\treturn nil\n\t}\n",
		New:  "",
		Why: "every binding inherits its role's dangerous_perms_detail, so each capability finding repeats once " +
			"per binding to the role",
	},
	{
		Guard: "TestClusterAdminBindingIsClusterAdminOnly", Pkg: "./internal/checks",
		File: "internal/checks/rbac_cluster.go",
		Old:  "(a.Metadata[\"platform_managed\"] == \"false\" || a.Metadata[\"platform_cluster_admin\"] == \"true\")",
		New:  "(true || a.Metadata[\"role_ref\"] == \"admin\")",
		Why: "k8s-cluster-admin-binding fires on the bootstrap cluster-admin binding to system:masters every " +
			"cluster ships, so the cluster-admin control fails everywhere",
	},
	{
		Guard: "TestAzureFoundationsChecksNeverFireOnAbsentData", Pkg: "./internal/checks",
		File: "internal/checks/azure_network.go",
		Old:  "return observedNone(a, \"nsg_id\") && !azureNSGExemptSubnets[a.Name]",
		New:  "return a.Metadata[\"nsg_id\"] == \"\" && !azureNSGExemptSubnets[a.Name]",
		Why:  "a subnet whose properties were never returned would read as having no NSG — every subnet a finding on one degraded VNet listing",
	},
	{
		Guard: "TestAzureFoundationsChecks_AbsentKeysNotEvaluable", Pkg: "./internal/checks",
		File: "internal/checks/azure_storage_account.go",
		Old:  "\tTableProbes: []string{\"2000-01-01T00:00:00Z\"},\n",
		New:  "",
		Why:  "without a timestamp probe an account whose key times went missing reads as evaluated-clean and its stale-key finding closes as fixed",
	},
	{
		Guard: "TestAzureSecurityChecksNeverFireOnAbsentData", Pkg: "./internal/checks",
		File: "internal/checks/azure_entra.go",
		Old:  "\tif observedNone(a, \"ca_mfa_all_users_policies\") {",
		New:  "\tif a.Metadata[\"ca_mfa_all_users_policies\"] == \"\" {",
		Why:  "a Conditional Access list Graph refused (403, no consent) would read as no MFA policy — a High finding on every tenant without Policy.Read.All",
	},
	{
		Guard: "TestMFASettings_NeedsBothReads", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/entra.go",
		Old:  "\tif f.mfa == nil || f.disabledUsers == nil {",
		New:  "\tif f.mfa == nil {",
		Why:  "without the disabled-user list every disabled account without MFA is counted as an exposed user",
	},
	{
		Guard: "TestListAll_FollowsNextLinkAndFailsOnAnyPage", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/restclient.go",
		Old:  "\t\t\treturn nil, fmt.Errorf(\"listAll %s: %w\", path, err)",
		New:  "\t\t\treturn out, nil",
		Why:  "a Graph/ARM page that fails mid-sequence would read as a short list (fewer users without MFA, fewer CA policies) instead of unknown",
	},
	{
		Guard: "TestListAll_FollowsNextLinkAndFailsOnAnyPage", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/restclient.go",
		Old:  "\t} else if !sameOrigin(path, c.base) {",
		New:  "\t} else if false {",
		Why:  "a server-supplied nextLink on another host would receive the connector's bearer token",
	},
	{
		Guard: "TestReadOnlyARM_DisablesProviderRegistration", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/armoptions.go",
		Old:  "\t\tDisableRPRegistration: true,",
		New:  "\t\tDisableRPRegistration: false,",
		Why:  "the ARM SDK would answer MissingSubscriptionRegistration by registering the resource provider — a write from a read-only scanner",
	},
	{
		Guard: "TestKeySettings", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/keyvault.go",
		Old:  "\tif rotationKnown {\n",
		New:  "\tif rotationKnown || true {\n",
		Why:  "a key whose rotation policy the data plane refused would count as rotating, closing 8.3.9 on firewalled vaults",
	},
	{
		Guard: "TestResourceLoggingSettings", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/resource_logging.go",
		Old:  "\t\tif !complete[t] {",
		New:  "\t\tif !complete[t] && false {",
		Why:  "a resource listing that failed would make the 6.1.4 rollup read as every resource logging",
	},
	{
		Guard: "TestARMClientsDisableProviderRegistration", Pkg: "./internal/collect/azure",
		File: "internal/app/executor/azure.go",
		Old:  "armnetwork.NewSecurityRulesClient(subscriptionID, cred, &arm.ClientOptions{DisableRPRegistration: true})",
		New:  "armnetwork.NewSecurityRulesClient(subscriptionID, cred, nil)",
		Why:  "an ARM client built with nil options auto-registers resource providers — a write nobody approved",
	},
	{
		Guard: "TestPurgeAndDelete_AzureTenantAssetGoesWithTheLastConnector", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service.go",
		Old:  "\t\tif !shared {\n",
		New:  "\t\tif shared || !shared {\n",
		Why:  "purging one subscription would delete the tenant asset other connectors still write, resolving findings that come straight back",
	},
	{
		Guard: "TestNSGAllowsWorldAnyPort_UDP", Pkg: "./internal/checks",
		File: "internal/checks/azure.go",
		Old:  "out = append(out, r.FromPort, r.ToPort+1)",
		New:  "out = append(out, r.FromPort)",
		Why:  "probing only rule starts misses the ports a partial higher-priority deny leaves open, so an open UDP range reads as closed",
	},
	{
		Guard: "TestNSGAllPortsRollup_OneFindingPerRule", Pkg: "./internal/checks",
		File: "internal/checks/azure.go",
		Old:  "return nsgFirstMatch(nsgWorldRules(a), \"tcp\", port) == nsgAllowedNarrow",
		New:  "return nsgFirstMatch(nsgWorldRules(a), \"tcp\", port) != nsgDenied",
		Why:  "one allow-everything NSG rule fans out into an RDP, SSH, WinRM and HTTP finding on top of the rollup — five findings for one root cause",
	},
	{
		Guard: "TestStorageKeyChecks_StepAsideWhenSharedKeyDisabled", Pkg: "./internal/checks",
		File: "internal/checks/azure_storage_account.go",
		Old:  "\t\tif a.Metadata[\"allow_shared_key_access\"] != \"true\" {\n\t\t\treturn false\n\t\t}\n",
		New:  "",
		Why:  "account keys that cannot authenticate are reported as live stale credentials at Medium",
	},
	{
		Guard: "TestWAFPolicies", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/waf_policies.go",
		Old:  "\t\tif !ok || p.state == \"\" {\n\t\t\tdelete(a.Metadata, \"waf_enabled\")\n\t\t\tcontinue\n\t\t}\n",
		New:  "\t\tif !ok || p.state == \"\" {\n\t\t\tcontinue\n\t\t}\n",
		Why:  "a failed WAF policy listing leaves every gateway with an attached policy reading as WAF-protected, so a Disabled policy passes CIS 7.10",
	},
	{
		Guard: "TestReadNetworkWatchers_FlowLogPaging", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/network_watcher.go",
		Old:  "\t\t\t\t\treturn networkWatchers{}, fmt.Errorf(\"readNetworkWatchers: list flow logs of %s: %w\", *w.ID, err)\n",
		New:  "\t\t\t\t\tbreak\n",
		Why:  "a failed flow-log page ends the listing early and every VNet on the unread pages reads as having no flow log",
	},
	{
		Guard: "TestStorageServiceMetadata", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/storage_services.go",
		Old:  "blob service properties unreadable\")\n\t\t} else {\n",
		New:  "blob service properties unreadable\")\n\t\t\tblobServiceMetadata(p, meta)\n\t\t} else {\n",
		Why:  "an unreadable blob service is written as soft delete and versioning off — a 403 becomes a Low finding on every account",
	},
	{
		Guard: "TestVMAssetWithNICs_UnreadNICIsUnknown", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/vms.go",
		Old:  "\t\t\tnic, err := getNIC(nicID)\n\t\t\tif err != nil {\n\t\t\t\tnicsKnown = false\n",
		New:  "\t\t\tnic, err := getNIC(nicID)\n\t\t\tif err != nil {\n",
		Why:  "a VM whose NIC read failed is written direct_public_ip=false, so its public-IP finding closes as fixed",
	},
	{
		Guard: "TestVMAssetWithNICs_AssociatedPublicIPWithoutAddress", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/vms.go",
		Old:  "\tcase public:\n",
		New:  "\tcase public && vmAsset.PublicIP != \"\":\n",
		Why:  "a stopped VM whose dynamic public IP has no address is written direct_public_ip=false, so its public-IP finding closes as fixed",
	},
	{
		Guard: "TestVMAssetWithNICs_NICWithoutPropertiesIsUnknown", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/vms.go",
		Old:  "\tif !complete {\n\t\tnicsKnown = false\n",
		New:  "\tif !complete {\n",
		Why:  "a VM whose NIC came back without properties is written direct_public_ip=false, so its public-IP finding closes as fixed",
	},
	{
		Guard: "TestExposureWithoutPropertiesIsUnknown", Pkg: "./internal/collect/azure",
		File: "internal/collect/azure/sql.go",
		Old:  "\tif srv.Properties == nil {\n\t\tmeta[\"public_access\"] = publicAccessUnknown\n",
		New:  "\tif srv.Properties == nil {\n\t\tmeta[\"public\"] = \"false\"\n",
		Why:  "a SQL server returned without properties is written public=false, so its public-network finding closes as fixed",
	},
	{
		Guard: "TestAssessSafety_UnreadDependentsCarryNoClass", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/safety.go",
		Old:  "\tif safetyUnassessableTypes[f.ResourceType] || asset.DependentsUnread(seed) {\n",
		New:  "\tif safetyUnassessableTypes[f.ResourceType] {\n",
		Why:  "a secret whose IAM policy was unreadable has zero accesses_secret edges and is graded safe, so it lands in the Start-here worklist",
	},
	{
		Guard: "TestAssessImpact_UnreadSeedDependents", Pkg: "./internal/app/respond",
		File: "internal/app/respond/impact.go",
		Old:  "\t\tDependentsKnown: dependentsKnown && !asset.DependentsUnread(seed),\n",
		New:  "\t\tDependentsKnown: dependentsKnown,\n",
		Why:  "a secret whose IAM policy was unreadable reads as measured to have no dependents, and a fix on it is banded safe",
	},
	{
		Guard: "TestCollectSecrets_UnreadPolicyIsUnknownAccess", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/secrets.go",
		Old:  "asset.MetaAccessorsKnown: fmt.Sprintf(\"%t\", aErr == nil),",
		New:  "asset.MetaAccessorsKnown: \"true\",",
		Why:  "a secret whose IAM policy could not be read looks like one no service account can access",
	},
	{
		Guard: "TestAzureAKSChecks_OneFindingPerRootCause", Pkg: "./internal/checks",
		File: "internal/checks/azure_aks.go",
		Old:  "\t\tif r == \"0.0.0.0/0\" {\n",
		New:  "\t\tif r == \"\" {\n",
		Why:  "an authorized range of 0.0.0.0/0 reads as a restricted API server and the internet-open cluster is graded Low instead of High",
	},
	{
		Guard: "TestAzureAKSChecks_OneFindingPerRootCause", Pkg: "./internal/checks",
		File: "internal/checks/azure_aks.go",
		Old:  "\t\treturn a.Metadata[\"entra_integration\"] == \"true\" && a.Metadata[\"local_accounts_disabled\"] == \"false\"\n",
		New:  "\t\treturn a.Metadata[\"local_accounts_disabled\"] == \"false\"\n",
		Why:  "a cluster without Entra integration gets a local-accounts finding on top of the Entra one — two findings for one root cause",
	},
	{
		Guard: "TestStorageKeyUntrackedIsStale", Pkg: "./internal/checks",
		File: "internal/checks/azure_storage_account.go",
		Old:  "\tif created == storageKeyUntracked {\n\t\treturn true\n\t}\n",
		New:  "",
		Why:  "a key never regenerated since Azure began recording creation times — the oldest keys there are — reads as unknown and is never reported",
	},

	// ── asset: ephemeral liveness + the OPTIMIZE job ────────────────────
	{
		Guard: "TestEphemeralTypesMatchTheLivenessCondition", Pkg: "./internal/app/asset",
		File: "internal/app/asset/optimize.go",
		Old:  "var EphemeralTypes = []string{\"k8s_pod\", \"container\", \"k8s_job\"}",
		New:  "var EphemeralTypes = []string{\"k8s_pod\", \"k8s_job\"}",
		Why:  "drift between the sweep's resolve-on-absence set and the graph's liveness filter resolves findings for a type the graph still trusts",
	},
	{
		Guard: "TestEphemeralLivenessArithmetic", Pkg: "./internal/app/asset",
		File: "internal/app/asset/repo.go",
		Old:  "- INTERVAL 72 HOUR)`",
		New:  "- INTERVAL 24 HOUR)`",
		Why:  "shortening the grace window resolves findings on pods that are merely late — every Go-level test runs against a fake that reimplements this",
	},
	{
		Guard: "TestEveryCHRepoMethodInThisFileHasAPerQueryTimeout", Pkg: "./internal/app/asset",
		File: "internal/app/asset/optimize.go",
		Old: "\tqCtx, cancel := context.WithTimeout(ctx, OptimizeTableTimeout)\n" +
			"\tdefer cancel()\n" +
			"\tqCtx = r.ch.WithQuerySettings(qCtx, map[string]any{",
		New: "\tqCtx := r.ch.WithQuerySettings(ctx, map[string]any{",
		Why: "a ClickHouse call with no deadline of its own: OPTIMIZE FINAL has no incremental unit, so one slow table eats the whole pass budget",
	},
	{
		Guard: "TestOptimizeTableBoundsTheServerToo", Pkg: "./internal/app/asset",
		File: "internal/app/asset/optimize.go",
		Old:  "\t\t\"max_execution_time\": int(OptimizeTableTimeout.Seconds()),",
		New:  "\t\t\"max_threads\": 4,",
		Why:  "a client-side cancel does not stop a running merge server-side, so a runaway merge keeps saturating ClickHouse CPU",
	},
	{
		Guard: "TestOptimizableTablesAreKnownReplacingMergeTrees", Pkg: "./internal/app/asset",
		File: "internal/app/asset/optimize.go",
		Old:  "\"findings\", \"assets\"}",
		New:  "\"findings\", \"asstes\"}",
		Why:  "a typo in the optimizable-table list makes the job silently error every tick, or optimize a table nobody meant to touch",
	},
	{
		Guard: "TestRepoCommentDoesNotContradictOptimizableTables", Pkg: "./internal/app/asset",
		File: "internal/app/asset/repo.go",
		Old:  "\t// assetSelect uses FINAL to read the deduplicated ReplacingMergeTree\n",
		New:  "\t// assetSelect uses FINAL because the optimize job skips assets entirely\n",
		Why:  "repo.go's load-bearing comment has been wrong twice in opposite directions, both times as plausible prose beside code that said otherwise",
	},

	// ── cmd/graph wiring ────────────────────────────────────────────────

	// ── admin gating, audit wiring, migration safety ────────────────────
	{
		Guard: "TestEveryWriteRouteIsGatedOrExempt", Pkg: "./internal/httpsrv",
		File: "internal/httpsrv/server.go",
		Old:  "\tmux.HandleFunc(\"POST /api/users\", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, authH.CreateUser))))",
		New:  "\tmux.HandleFunc(\"POST /api/users\", authH.RequireAuth(authH.RequireSession(authH.CreateUser)))",
		Why: "a state-changing route losing its role gate — the drift the hand-maintained list showed " +
			"(seven writes missing, including both connector credential writes)",
		// This mutation used to be a gofmt-style line split, which is what
		// EXPOSED the old regex: it required auth.RequireRole on the same
		// physical line as HandleFunc, so splitting the line dropped the route
		// from the derived set with every assertion still green. The AST parse
		// that replaced it sees through formatting, so the split is now a no-op
		// and would make this row vacuous. Removing the gate outright is the
		// bug the guard actually exists to catch.
	},
	{
		Guard: "TestHighImpactWritesRequireSession", Pkg: "./internal/httpsrv",
		File: "internal/httpsrv/server.go",
		Old:  "authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, h.Policy.Update)))",
		New:  "authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Policy.Update))",
		Why: "a session-only admin write losing RequireSession, so an admin API key an agent holds " +
			"can loosen the approval policy with no person involved and no refusal row",
	},
	{
		Guard: "TestChartAuthHardeningValues", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/deployment-serve.yaml",
		Old:  "- name: REQUIRE_ADMIN_TOTP\n  value: \"true\"",
		New:  "- name: REQUIRE_ADMIN_MFA\n  value: \"true\"",
		Why: "config.requireAdminTotp rendering an env name serve never reads, so the chart's MFA " +
			"switch does nothing while the install looks hardened",
	},
	{
		Guard: "TestChartAuthHardeningValues", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/deployment-serve.yaml",
		Old:  "- name: TLS_PROXY\n  value: \"true\"",
		New:  "- name: TLS_PROXIED\n  value: \"true\"",
		Why: "config.tlsProxy rendering an env name serve never reads, so the hardened gate is " +
			"satisfied while serve sends no HSTS behind the ingress",
	},
	{
		Guard: "TestHardenedScriptCoversEveryCheck", Pkg: "./cmd/graph",
		File: "scripts/check-chart-hardened.sh",
		Old:  "refuses worker.pprofPort --set-string worker.pprofPort=6060\n",
		New:  "",
		Why: "a hardened check loses the CI case that trips it, so a template edit that stops " +
			"it firing ships with every check still green",
	},
	{
		Guard: "TestHardenedRefusesEveryDangerousFlag", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/checks/hardened.yaml",
		Old:  `"COOKIE_INSECURE" "OAUTH_REDIRECT_FROM_HOST"`,
		New:  `"OAUTH_REDIRECT_FROM_HOST"`,
		Why: "a dangerous flag drops out of the hardened refusal list, so extraEnv can set " +
			"COOKIE_INSECURE on an install that renders as hardened",
	},
	{
		Guard: "TestHardenedRefusesSignInEnv", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/checks/hardened.yaml",
		Old:  `"OKTA_CLIENT_ID" "OKTA_CLIENT_SECRET" "OKTA_DOMAIN"`,
		New:  `"OKTA_CLIENT_ID" "OKTA_CLIENT_SECRET"`,
		Why: "a sign-in variable drops out of the hardened extraEnv refusals, so an entry can point " +
			"Okta sign-in at another tenant on an install that renders as hardened",
	},
	{
		Guard: "TestHardenedOverlayLeavesOperatorValuesEmpty", Pkg: "./cmd/graph",
		File: "deploy/helm-values/hardened.yaml",
		Old:  "  # cannot change under a moved tag.\n  digest: \"\"",
		New:  "  # cannot change under a moved tag.\n  digest: \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
		Why: "the overlay ships a value only the operator knows, so the overlay alone renders " +
			"and an install runs an image nobody looked up or verified",
	},
	{
		Guard: "TestHardenedRoleMappingClassMatchesSplitCSV", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/checks/hardened.yaml",
		Old:  "regexMatch `[^,\\t\\n\\v\\f\\r\\x{85}\\p{Z}]`",
		New:  "regexMatch `[^,\\s]`",
		Why: "the role-mapping check counts a no-break space as a mapping while serve's splitCSV " +
			"trims it away, so an install with no admin mapping renders as hardened and its first " +
			"SSO sign-in becomes admin",
	},
	{
		Guard: "TestHardenedChecksRenderNothing", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/checks/hardened.yaml",
		Old:  "{{- with $gaps }}",
		New:  "kind: ConfigMap\n{{- with $gaps }}",
		Why:  "the checks template emits content of its own, so hardened: true adds an object to the install instead of only refusing a render",
	},
	{
		Guard: "TestExecutorIsWiredWithAudit", Pkg: "./cmd/graph",
		File: "cmd/graph/serve.go",
		// The constructor is now a multi-line option chain, which is exactly what
		// broke the old regex-based guard: it required .WithAudit( on the same
		// physical line and reported a correctly-wired call as unwired. The guard
		// is an AST walk now, so the mutation has to remove the option outright
		// rather than merely reformat it.
		Old: "executor.NewService(connectorSvc).\n\t\tWithAudit(executor.NewCHAuditRepo(ch)).\n\t\tWithApprovals(executorApprover)",
		New: "executor.NewService(connectorSvc).\n\t\tWithApprovals(executorApprover)",
		Why: "a construction that forgets the audit option compiles and looks identical to one that does not — while the doc comment still promises every execution is audited",
	},
	{
		Guard: "TestOnlyHumanTransportsBuildExecutionRequests", Pkg: "./internal/app/executor",
		File: "internal/app/mcp/tools_cloud.go",
		Old:  "RequireGrant:  true,",
		New:  "RequireGrant:  false,",
		Why: "the MCP execute_action tool stops demanding a different admin's grant: an LLM client holding an admin " +
			"key — reading attacker-influenced findings — could then mutate the cloud with no person saying yes",
	},
	{
		Guard: "TestSuppressIsWiredWithAudit", Pkg: "./cmd/graph",
		File: "cmd/graph/worker.go",
		Old:  "suppress.NewService(suppress.NewPGRepo(pool)).WithAudit(suppress.NewCHAuditRepo(ch))",
		New:  "suppress.NewService(suppress.NewPGRepo(pool))",
		Why:  "the same silent-drop on the worker's suppress wiring — human-triggered writes that never reach audit_events",
	},
	{
		Guard: "TestAdminServicesAreWiredWithAudit", Pkg: "./cmd/graph",
		File: "cmd/graph/serve.go",
		Old:  "WithOrgDiscoverer(newAWSOrgDiscoverer()).\n\t\tWithAudit(adminAudit)",
		New:  "WithOrgDiscoverer(newAWSOrgDiscoverer())",
		Why:  "a connector switched to read_write, created, deleted or purged leaves no audit_events row, and nothing fails",
	},

	{
		Guard: "TestSetMode_IsAuditedWithBeforeAndAfter", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service.go",
		Old:  "\ts.record(ctx, AuditActionModeChange, id, map[string]any{\"before\": string(before), \"after\": string(mode)})\n",
		New:  "\t_ = before\n",
		Why:  "the in-app gate before every cloud mutation opens with no record of who opened it",
	},
	{
		Guard: "TestRequireAdminTOTP_RefusesPasswordSignInWithoutTOTP", Pkg: "./internal/app/auth",
		File: "internal/app/auth/service.go",
		Old:  "if s.requireAdminTOTP && creds.Role == RoleAdmin && creds.TOTPSecret == \"\" {",
		New:  "if false && s.requireAdminTOTP && creds.Role == RoleAdmin && creds.TOTPSecret == \"\" {",
		Why:  "REQUIRE_ADMIN_TOTP=true still lets an admin with no TOTP enrolled sign in with a password alone",
	},
	{
		Guard: "TestLLMConsumersAreMetered", Pkg: "./cmd/graph",
		File: "cmd/graph/worker.go",
		Old:  "reason.New(llmUsage.Client(llmClient, llmusage.PurposeReason), getenv(\"REASON_MODEL\"))",
		New:  "reason.New(llmClient, getenv(\"REASON_MODEL\"))",
		Why:  "a raw provider client handed to a consumer spends with no ledger row and no budget check — the monthly cap bypassed silently",
	},
	{
		Guard: "TestObsSourcesAreAllWired", Pkg: "./cmd/graph",
		File: "cmd/graph/worker_metrics.go",
		// Removes only the field's code, not its preceding doc comment — the
		// comment orphans harmlessly above ConnectorCoverage's field for the
		// duration of the mutation, which the guard (an AST walk over the
		// obs.Sources{} literal's keys) never reads anyway.
		Old: "\t\tSourceActivity: func(ctx context.Context) []obs.SourceActivityStat {\n" +
			"\t\t\tstats, err := findingSvc.SourceActivity(ctx)\n" +
			"\t\t\tif err != nil {\n" +
			"\t\t\t\treturn nil\n" +
			"\t\t\t}\n" +
			"\t\t\tout := make([]obs.SourceActivityStat, len(stats))\n" +
			"\t\t\tfor i, s := range stats {\n" +
			"\t\t\t\tout[i] = obs.SourceActivityStat{Source: s.Source, LastActivityUnix: s.LastActivityUnix}\n" +
			"\t\t\t}\n" +
			"\t\t\treturn out\n" +
			"\t\t},\n",
		New: "",
		Why: "a field added to obs.Sources and never wired into registerMetricsSources compiles clean and looks " +
			"identical to one that is — the shape that lets a metric such as SourceActivity ship dark, " +
			"caught only by an absent() tripwire alert rather than any test",
	},
	{
		Guard: "TestAdvisoryLockWaitIsBounded", Pkg: "./internal/migrate",
		File: "internal/migrate/migrate.go",
		Old:  "const lockTimeout = \"30s\"",
		New:  "const lockTimeout = \"3m\"",
		Why:  "an advisory-lock wait longer than the init container's patience turns a contended boot into a wedged one",
	},
	{
		Guard: "TestEveryQueueConsumingClientDisablesTheReindexer", Pkg: "./internal/jobs",
		File: "internal/jobs/client.go",
		Old:  "\t\tPeriodicJobs:      buildPeriodicJobs(cfg),\n\t\tReindexerSchedule: reindexerSchedule,\n",
		New:  "\t\tPeriodicJobs:      buildPeriodicJobs(cfg),\n",
		Why:  "a queue-consuming client that leaves River's reindexer on runs it concurrently with the other pods' copies",
	},
	{
		Guard: "TestEveryElectableClientConfiguresSoftStopTimeout", Pkg: "./internal/jobs",
		File: "internal/jobs/client.go",
		Old:  "\t\tReindexerSchedule: reindexerSchedule,\n\t\tSoftStopTimeout:   scannerSoftStopTimeout,\n",
		New:  "\t\tReindexerSchedule: reindexerSchedule,\n",
		Why: "a queue-consuming client with no SoftStopTimeout hard-cancels every in-flight job the instant " +
			"SIGTERM arrives (river.Config's default), so every deploy — not just a crash — kills whatever " +
			"was running and forces a full retry, no matter how close to finishing, which can surface as " +
			"GraphCorrelateFullSweepStale",
	},
	{
		Guard: "TestShutdownFitsTerminationGracePeriod", Pkg: "./internal/jobs",
		File: "deploy/helm-chart/graph/templates/deployment-worker.yaml",
		Old:  "      terminationGracePeriodSeconds: 50\n",
		New:  "      terminationGracePeriodSeconds: 30\n",
		Why: "a grace period shorter than River's stop plus the coalescer's final flush gets the worker " +
			"SIGKILLed mid-flush, losing buffered partial-correlate enqueues on every deploy",
	},

	// ── enrichment repair reachability ──────────────────────────────────
	{
		Guard: "TestEnrichSweepWorker_Phase1CeilingIsHigherNotAbsent", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich.go",
		Old:  "\tif !sweepHasCapacity(ctx, backfillQueueCeiling) {\n\t\treturn nil\n\t}\n",
		New:  "",
		Why: "removing the never-enriched backfill's ceiling entirely: enrichSweepMax bounds one tick, not the " +
			"accumulated queue, so at a 15-minute cadence depth grows without limit — the backlog can OOM the " +
			"worker and starve the graph queue behind it. (Gating it on enrichQueueMax instead is the other " +
			"broken shape; the guard rejects that too.)",
	},

	// ── dead write paths ────────────────────────────────────────────────
	{
		Guard: "TestNoGraphNodesWriter", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/service.go",
		Old:  "// AssetSource provides all assets for the bulk sync.",
		New: "// upsertNodesQ was the graph.nodes write path.\n" +
			"const upsertNodesQ = `INSERT INTO graph.nodes (id, type, label, risk_score, last_seen)`\n\n" +
			"// AssetSource provides all assets for the bulk sync.",
		Why: "a graph.nodes write-back is a large row volume on the rebuild's critical path against zero " +
			"reads (Ladybug serves the post-BFS score), and its rows go stale without anyone noticing because " +
			"nobody reads them. An INSERT-only path with no reader breaks nothing when it drifts, which is " +
			"exactly why adding one has to fail loudly",
	},

	// ── ladybug rebuild gate: the load digest ───────────
	{
		Guard: "TestLoadDigest_RiskScoreChangeMovesOnlyScoresHalf", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/loaddigest.go",
		Old:  "\t\t\t\tif hasRisk && i == riskIdx {\n",
		New:  "\t\t\t\tif hasRisk && i == riskIdx+len(vals) {\n",
		Why: "the shipped bug: asset RiskScore hashed into the topology half. It is rewritten between sweeps by " +
			"construction (collector base scorer, CIEM, scoreAssetsFromFindings), so the gate never fires " +
			"and every sweep pays for a full rebuild",
	},
	{
		Guard: "TestRiskScoreColIdxMatchesLoader", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/loaddigest.go",
		Old:  "\t\t\tif c == \"score\" {\n",
		New:  "\t\t\tif c == \"type\" {\n",
		Why: "a skip index pointing at the wrong column both leaks RiskScore back into the topology half (gate dies " +
			"silently) and removes a real topology column from it (type changes stop forcing rebuilds)",
	},
	{
		// Guard was TestLoadDigest_TopoChangeDetected earlier: that test
		// relied on an INCIDENTAL collision in its shared fixture (flipping
		// reachComplete happened to cancel exactly against the internet_hops
		// change it caused), and the fixture's data drifted for unrelated reasons
		// until every one of its cases passed even with mix64 disabled — a guard
		// that stopped biting without anyone touching mix64 itself. Repointed at
		// TestMix64Avalanches, which tests the property directly and cannot rot
		// the same way.
		Guard: "TestMix64Avalanches", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/loaddigest.go",
		Old:  "func mix64(x uint64) uint64 {\n\tx ^= x >> 30\n",
		New:  "func mix64(x uint64) uint64 {\n\tif true {\n\t\treturn x\n\t}\n\tx ^= x >> 30\n",
		Why: "without the avalanche the additive combine inherits FNV's byte-linearity: two trailing-byte changes " +
			"differ by k·prime each and can cancel — observed, not hypothesised: flipping reachComplete and the " +
			"internet_hops -1→-2 it caused cancelled exactly in an earlier version of this fixture, making the flip " +
			"invisible to the digest",
	},
	{
		Guard: "TestLoadFromSnapshot_WarmStartSkipsRebuild", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/service_snapshot.go",
		Old:  "\tif snap.TopoDigest != 0 && scoresApplied {\n",
		New:  "\tif snap.TopoDigest != 0 && scoresApplied && false {\n",
		Why: "a baseline that does not survive a restart is half the load-digest gate: every restart forces a full " +
			"rebuild because lastDigest resets to nil, so a worker that restarts often never benefits from the gate",
	},
	{
		Guard: "TestSyncFromSources_GateTakesEachPath", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/score_refresh.go",
		Old:  "\t\tif old, ok := (*prev)[id]; ok && old == f {\n",
		New:  "\t\tif _, ok := (*prev)[id]; ok {\n",
		Why: "an inert score refresh — skip every node the stash knows — makes the cheap path a fancy way to serve " +
			"stale risk: the gate skips the rebuild AND nobody writes the changed scores. Excluding RiskScore from " +
			"the topology half is only sound while this write path actually works",
	},

	// ── rebuild cost attribution ─────────────
	{
		Guard: "TestEveryDeclaredPhaseIsMarked", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/service_sync.go",
		Old:  "\t\tphases.mark(phaseSnapshot)\n",
		New:  "",
		Why: "a declared phase that nothing marks is an invisible step: the metric's help text claims it is " +
			"measured, the phase sum silently under-attributes the rebuild, and the missing time looks like it " +
			"belongs to whichever phase happens to be marked next. This is the same shape as the failure the load-digest gate " +
			"guards against one layer up — a signal that exists and cannot move. The snapshot write is " +
			"the phase most likely to be dropped, because it is the last one and sits inside a conditional",
	},
	{
		Guard: "TestReachOverlayIsDerivedInOnePlace", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/reach.go",
		Old:  "\ts.Exposed = o.exposed[id]\n",
		New:  "\ts.Exposed = exposedSeedSet(nil)[id]\n",
		Why: "the exposure set and the hop map must be derived ONCE per sweep and passed down. Re-deriving at a " +
			"consumer is another full pass over every edge on a memory-constrained worker, and — the bigger half — another " +
			"independent copy of a pair that must agree: node_rows.go documents that exposed[id] and hops[id]==0 " +
			"are deliberately NOT the same predicate, so N derivations is N chances for must-fix classification to " +
			"drift. A re-derivation is invisible: it returns a correct-looking value",
	},
	{
		Guard: "TestScoreRowsByLabelRoutesEachRowExactlyOnce", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/score_refresh.go",
		Old:  "\t\trows[label] = append(rows[label], map[string]any{\"id\": a.ID, \"score\": v})\n",
		New:  "\t\tfor _, l := range bfsScoreLabels {\n\t\t\trows[l] = append(rows[l], map[string]any{\"id\": a.ID, \"score\": v})\n\t\t}\n",
		Why: "the shipped write amplification: propagateRisk sent every boosted row to all four bfsScoreLabels and " +
			"let MATCH discard the ~3/4 belonging to another label. Correct and four times the work, inside the " +
			"post-COPY half, which dominates rebuild time. Fanning out again is invisible behaviourally — the graph " +
			"ends up identical — so only a test on the routing itself can catch it",
	},
	{
		Guard: "TestScoreRowsByLabelAbortsBeforeMaterialisingOverTheCap", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/score_refresh.go",
		Old:  "\t\tif maxRows > 0 && total > maxRows {\n",
		New:  "\t\tif false && maxRows > 0 && total > maxRows {\n",
		Why: "the cap has to trip DURING construction, not after. refreshScores' diff is unbounded (a cold stash " +
			"makes it the whole corpus), each row is a map, and this runs on a memory-constrained worker " +
			"— so 'build it all, then check the size' allocates exactly the transient the cap exists to " +
			"prevent, and then still falls back to the rebuild",
	},
	{
		Guard: "TestDecodeMapKeepDoesNotPinTheSourceDocument", Pkg: "./internal/app/asset",
		File: "internal/app/asset/repo.go",
		Old:  "\t\treturn strings.Clone(body), true\n",
		New:  "\t\treturn body, true\n",
		Why: "a Go substring shares its backing array, so returning the slice makes every kept key/value " +
			"pin the ENTIRE raw JSON document for the life of the Asset or Edge — an iam_role keeping an " +
			"11-byte trust_entry would retain ~10KiB of policy blobs, quietly undoing the projection. No " +
			"value comparison can see it (aliased strings are equal) and the live-heap breakdown cannot " +
			"either (it narrows maps decoded from a gob snapshot, where the aliasing path never runs)",
	},
	{
		Guard: "TestEveryMappedLabelIsLoadable", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/domain.go",
		Old:  "\t\"iam_policy\":         NodeAsset,\n",
		New:  "\t\"iam_policy\":         NodeIamPolicy,\n",
		Why: "a type routed to a label absent from nodeCSVCols/nodeUnwindQ is read, filtered and digested " +
			"and then never emitted as a node, so every edge touching it is discarded at COPY. Three such " +
			"labels coexisted (ElasticIP, DNSZone, IamPolicy); the first silently dropped dns_points_to edges, the " +
			"other two were harmless only by the coincidence that their edge types are unfed for unrelated " +
			"reasons",
	},
	{
		Guard: "TestProducerEndpointsAreNotSyncExcluded", Pkg: "./internal/app/graphstore",
		File: "internal/app/asset/repo.go",
		Old:  "\t\"vpc_peering_connection\", \"gcp_firewall\",\n",
		New:  "\t\"vpc_peering_connection\", \"gcp_firewall\", \"elastic_ip\",\n",
		Why: "NeverSyncTypes excludes at the SQL level, BEFORE filterLadybugAssets, so retentionEdgeTypes " +
			"cannot rescue the endpoint and the edge is discarded at COPY as endpointAbsent — the one drop " +
			"reason operators are told is normal attrition. elastic_ip in this list, for example, drops " +
			"dns_points_to edges and starves dns_chain_exposure of its input",
	},
	{
		Guard: "TestSyncEdgePropertyKeysCoverEveryReader", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/metadata_keys.go",
		Old:  "\t\tasset.EdgePropPublicAccess: true, // exposure tier (reach.go, node_rows.go)\n",
		New:  "",
		Why: "the sync now narrows Edge.Properties, and a dropped key does not error — the map read " +
			"returns \"\" and the value silently becomes empty. Dropping public_access specifically makes " +
			"every POSSIBLE exposure read as CONFIRMED, because assetPublicTier treats an absent tier as " +
			"confirmed by design; for a rel rowKey it is the RunsImage.image_ref empty-column bug",
	},
	{
		Guard: "TestGraphstoreReadsNoAssetTags", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/metadata_keys.go",
		Old:  "\t\tSkipTags:         true,\n",
		New:  "\t\tSkipTags:         false,\n",
		Why: "retaining Tags in the bulk sync costs a large share of LIVE heap on a big inventory (hundreds of bytes " +
			"per asset) for data nothing in graphstore reads, and with allocator " +
			"retention that is closer to double that in RSS on a worker with a tight cgroup limit. The guard also " +
			"protects the other direction: a nil Tags map reads as empty, so a new Tags reader would " +
			"compile and silently produce a wrong answer on every asset",
	},
	{
		Guard: "TestSyncMetadataKeysCoverNodeLoader", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/metadata_keys.go",
		Old:  "\t\"storage_encrypted\",   // RDS encryption (assetEncrypted)\n",
		New:  "",
		Why: "an under-declared projection key does not error — the bulk sync stops asking ClickHouse for it, the " +
			"loader reads \"\", and the graph column silently takes the zero value. Dropping storage_encrypted marks " +
			"every RDS instance unencrypted in the DSPM view; the same shape of silent wrong answer as label-promotion " +
			"label-promotion drops",
	},
	{
		Guard: "TestDigestLatchIsGatedOnScoresApplied", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/service_sync.go",
		// Anchored on the preceding comment: the bare condition also occurs one
		// indent deeper at the snapshot-write site, and the harness requires a
		// unique match.
		Old: "\t// Latching nothing is what actually forces the rebuild.\n\tif digErr == nil && scoresApplied {\n",
		New: "\t// Latching nothing is what actually forces the rebuild.\n\tif digErr == nil {\n",
		Why: "latching the digest over a graph whose BFS scores failed to write is permanent, not transient: the " +
			"Scores half is computed from what ClickHouse returned rather than what the graph holds, so an " +
			"unchanged corpus matches next sweep, the cheap path skips the refresh, and the un-boosted scores " +
			"serve until an unrelated topology change. Withholding only the lastScores stash does not help — " +
			"refreshScores is never called",
	},

	// ── pruned nodes must stay distinguishable from genuine negatives ────
	{
		Guard: "TestFallbackRepo_PrunedNodeReachesClickHouse", Pkg: "./internal/app/explore",
		File: "internal/app/explore/tiered_repo.go",
		Old:  "\treturn nodeCount == 0 && len(ids) > 0\n",
		New:  "\treturn false\n",
		Why: "Ladybug is a FILTERED projection — filterLadybugAssets prunes every asset with no retention edge and " +
			"no risk score (a very large number of dns_record and dns_zone assets) — so its zero-rows-nil-error " +
			"answer for an id is byte-identical to \"no such asset\". With emptiness not a miss, both tier " +
			"wrappers switch on err alone and the pruned node short-circuits the ClickHouse tier that still " +
			"holds it AND its edges: /api/graph/expand answers 200 {\"nodes\":[],\"edges\":[]} and a seeded view " +
			"answers 400 ErrNoSeed for an asset the inventory lists",
	},
	{
		Guard: "TestLadybugBlastProvider_PrunedSeedFallsBackToClickHouse", Pkg: "./cmd/graph",
		File: "cmd/graph/ladybug_blast.go",
		// Restores the exact pre-fix form (a silent typeless seed), not a broken
		// condition — a mutation that panics on a nil map lookup would fail the
		// guard for the wrong reason. Updated when BlastRadius was
		// retargeted off Ladybug onto the retained Go adjacency (BlastSeed replaces
		// MatchSeed) — same bug shape, same fix, new call.
		Old: "\tseed, ok := k.graph.BlastSeed(seedID)\n" +
			"\tif !ok {\n" +
			"\t\tlog.FromContext(ctx).Debug().Str(\"seed_id\", seedID).\n" +
			"\t\t\tMsg(\"ladybug_blast: seed not in the retained adjacency (pruned, unknown, or not yet built), falling back to CH BFS\")\n" +
			"\t\treturn k.assets.BlastRadius(ctx, seedID, maxDepth)\n" +
			"\t}\n",
		New: "\tseed := asset.Asset{ID: seedID}\n" +
			"\tif s, ok := k.graph.BlastSeed(seedID); ok {\n" +
			"\t\tseed = s\n" +
			"\t}\n",
		Why: "a BlastSeed miss on a pruned asset is not \"no blast radius\": the walk returns a typeless " +
			"one-asset BlastRadius with a NIL error, and respond.blastRadiusFor only retries via ResolveID on " +
			"err != nil, so its recovery path never runs and Decide sizes a confirmed subdomain takeover " +
			"(dns_record findings in the page/high bands) as zero-blast — the exact " +
			"failure the blastRadiusFor comment says it exists to stop",
	},
	// ── CT log blackout ─────────────────────────
	{
		Guard: "TestCheckCTLogs_TotalBlackoutIsAnError", Pkg: "./internal/app/intel",
		File: "internal/app/intel/ct.go",
		Old:  "\tif stats.Queried > 0 && stats.Failed == stats.Queried {\n",
		New:  "\tif false {\n",
		Why: "crt.sh is the phishing pipeline's only upstream, it has no fallback, and it can serve 502 for days " +
			"at a time, for every base name AND on its own root URL. Without the " +
			"total-blackout check, every query failing returns ([], nil): RunScan logs hits=0, writes no candidates " +
			"and the job COMPLETES SUCCESSFULLY, so \"we could not look\" becomes byte-identical to \"no squatting " +
			"domains exist\" — phishing_candidates can go weeks without a write and nothing reports the gap",
	},

	// ── finding age ──────────────────────────────
	{
		Guard: "TestFindingAgeReadsFirstDetectedAtOnly", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_age.go",
		Old:  "\tage := a.clock().Sub(f.FirstDetectedAt)\n",
		New:  "\tage := a.clock().Sub(f.DetectedAt)\n",
		Why: "detected_at is re-stamped by every finding producer on every re-observation, so reading it as age " +
			"measures time-since-last-seen \u2014 inverted, because a finding that persists is re-observed more often " +
			"and therefore looks newer. It compiles, it produces plausible scores, and its only symptom is that " +
			"findings never get old: the age demotions (-5 past 90d, -10 past a year) simply never fire",
	},

	// ── deletion authority ─────────────────────────────
	{
		Guard: "TestForgetNeverActsWithoutProvenCompleteness", Pkg: "./internal/app/forget",
		File: "internal/app/forget/domain.go",
		Old:  "\tif _, ok := ParseScope(in.Scope.Key); !ok {\n\t\treturn refuse(RefusalNotEnforceable)\n\t}\n",
		New:  "\tif false {\n\t\treturn refuse(RefusalNotEnforceable)\n\t}\n",
		Why: "this is the one gate standing between an unaudited or malformed scope key and a forget decision — " +
			"drop it and Decide falls through to the same population-vs-threshold arithmetic for EVERY scope, " +
			"audited or not, so a collector family nobody has read the pagination loop for gets exactly the same " +
			"deletion authority as ec2:instances the moment its absence counts pass the relative/absolute caps; " +
			"this is the specific mistake the deletion-authority design exists to make structurally impossible rather than reviewed-in",
	},
	{
		Guard: "TestEnforceableFamiliesAreDeclaredByACollector", Pkg: "./internal/app/forget",
		File: "internal/collect/aws/aws.go",
		Old:  "complete(region, \"ec2:instances\", []string{\"ec2_instance\"}, len(instances))",
		New:  "complete(region, \"ec2:instance\", []string{\"ec2_instance\"}, len(instances))",
		Why: "forget.enforceableFamilies grants ec2:instances deletion authority ON THE STRENGTH of this exact " +
			"MarkComplete call proving it enumerates completely — a one-character drift in the family key " +
			"(plural to singular, the kind a refactor makes without noticing) leaves the allow-list still claiming " +
			"coverage while the collector has silently stopped declaring completeness for it, so every future sweep " +
			"for that scope refuses on unconfirmed forever with no watermark ever advancing again and nothing " +
			"surfacing why",
	},
	{
		Guard: "TestCollectSubnets_RegionNotAvailabilityZone", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/network.go",
		Old:  "\t\t\t\tType:      \"subnet\",\n\t\t\t\tProvider:  asset.ProviderAWS,\n\t\t\t\tRegion:    region,",
		New:  "\t\t\t\tType:      \"subnet\",\n\t\t\t\tProvider:  asset.ProviderAWS,\n\t\t\t\tRegion:    awssdk.ToString(sn.AvailabilityZone),",
		Why: "reverts a subnet's stored Region back to its AvailabilityZone (e.g. \"eu-west-1a\") instead of the " +
			"region being collected (\"eu-west-1\") — the exact bug that excluded ec2:subnets from " +
			"forget.enforceableFamilies until a later fix: a scope declares completeness per REGION, but a " +
			"region's population can never be selected by an exact match against a stored AZ, so the newly-added " +
			"deletion authority for subnets would silently refuse everything as unconfirmed forever",
	},
	{
		Guard: "TestClassifyRoutes", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/network.go",
		Old:  "\tcase defaultOpaque:\n\t\tv.public = \"\"\n",
		New:  "",
		Why: "a default route through a transit gateway, peering or inspection appliance would read as a private " +
			"subnet instead of unknown, so the reachability correlator demotes the exposure of every public-IP " +
			"instance behind a firewall VPC — positive evidence manufactured out of a path the collector cannot see",
	},
	{
		Guard: "TestCollectECSResources_StaleTargetGroupDropsOnlyItself", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/ecs_images.go",
		Old:  "\t\tcase errors.As(err, &notFound) && len(batch) == 1:\n",
		New:  "\t\tcase errors.As(err, &notFound) && len(batch) == 0:\n",
		Why: "a target group deleted while a service still references it fails the whole lookup again, dropping " +
			"every load_balancer -routes_to-> ecs_service edge in the region and marking the connector partial every " +
			"sweep — which disables finding auto-resolution for the account indefinitely",
	},
	{
		Guard: "TestCollectECSResources_HostNetworkedExposureUnknown", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/ecs.go",
		Old:  "\tif pubIP != \"\" {\n\t\tmeta[\"public\"]",
		New:  "\tif true {\n\t\tmeta[\"public\"]",
		Why: "a bridge/host-networked ECS service is stamped public=false as if measured, though its exposure is " +
			"the host instance's — an unmeasured exposure reads as a confirmed negative",
	},
	{
		Guard: "TestGuardDutySeverity", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/guardduty.go",
		Old:  "\tcase s >= 9:\n\t\treturn finding.SeverityCritical\n",
		New:  "",
		Why:  "GuardDuty Critical (9.0-10.0, Extended Threat Detection attack sequences) is downgraded to High",
	},
	{
		Guard: "TestCodeownersPatternSemantics", Pkg: "./internal/app/asset",
		File: "internal/app/asset/codeowners.go",
		Old:  "\tcase directChildren && anchored:\n\t\tb.WriteString(\"$\")\n",
		New:  "\tcase directChildren && anchored:\n\t\tb.WriteString(\"(?:/.*)?$\")\n",
		Why: "CODEOWNERS \"docs/*\" claims nested files again and \"/*\" owns the whole repo, routing findings " +
			"to a team GitHub itself does not consider the owner",
	},
	{
		Guard: "TestCollectCodeowners_UnreadKeepsStoredRules", Pkg: "./internal/collect/github",
		File: "internal/collect/github/codeowners.go",
		Old:  "\t\tkept := c.carryForwardCodeowners(ctx, out, unread)\n",
		New:  "\t\tkept := 0\n",
		Why: "a rejected CODEOWNERS batch writes the repo asset without its codeowners key, erasing the stored " +
			"rules — \"not read\" becomes \"nobody owns it\" until the next good sweep",
	},
	{
		Guard: "TestCollect_SameNameTwoZones", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/gcp.go",
		Old:  "\treturn projectID + \"/\" + zone + \"/\" + name\n",
		New:  "\treturn projectID + \"/\" + name\n",
		Why: "same-named GCE instances in two zones collapse into one asset, and OS Config packages from both " +
			"are attached to it",
	},
	{
		Guard: "TestCollectCloudRun_SameNameTwoRegions", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/cloudrun.go",
		Old:  "\treturn projectID + \"/cloudrun/\" + region + \"/\" + name\n",
		New:  "\treturn projectID + \"/cloudrun/\" + name\n",
		Why:  "same-named Cloud Run services in two regions collapse into one asset carrying both regions' images",
	},
	{
		Guard: "TestCollectCloudSQL_RequireSSLNeedsIPConfig", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/cloudsql.go",
		Old:  "\t\tif in.IPConfigObserved {\n\t\t\tmd[\"require_ssl\"]",
		New:  "\t\tif in.SettingsObserved {\n\t\t\tmd[\"require_ssl\"]",
		Why: "a Settings returned without ipConfiguration writes the Go zero require_ssl=false, and " +
			"gcp-cloudsql-no-ssl fires on an instance whose TLS setting was never read",
	},
	{
		Guard: "TestInternetExposure", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/firewall_shadow.go",
		Old:  "d.Network != r.Network || d.Priority > r.Priority ||",
		New:  "d.Network != r.Network ||",
		Why: "a deny that loses to the allow on priority is credited as blocking it, so an SSH rule open to " +
			"the internet reads as shadowed and gcp-firewall-ssh-open-internet goes silent",
	},
	{
		Guard: "TestInternetExposure", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/firewall_shadow.go",
		Old:  "!targetsCover(d, r) || !destinationsCover(d, r)",
		New:  "!targetsCover(d, r)",
		Why: "a deny limited to one subnet's destination ranges is credited across the whole network, so a " +
			"network-wide SSH rule reads as shadowed for every VM outside that subnet",
	},
	{
		Guard: "TestInternetExposure", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/firewall_shadow.go",
		Old:  "\t\tex.SSH = reach(sshPort) && !ex.AllPorts\n",
		New:  "\t\tex.SSH = reach(sshPort)\n",
		Why:  "one all-ports rule fans out into an all-ports, an SSH and an RDP finding — three findings for one root cause",
	},
	{
		Guard: "TestGKEAuthorizedNetworksDNSOnly", Pkg: "./internal/checks",
		File: "internal/checks/gcp_gke.go",
		Old:  " &&\n\t\t\ta.Metadata[\"ip_endpoints_enabled\"] != \"false\"",
		New:  "",
		Why:  "a cluster reachable only through its IAM-authorized DNS endpoint is told to restrict an IP endpoint it does not have",
	},
	{
		Guard: "TestProjectAsset_AuditUnknownWhenAncestorsUnread", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/iam_project.go",
		Old:  "\tif eff.ancestorsComplete {\n",
		New:  "\tif eff.ancestorsComplete || len(eff.bindings) >= 0 {\n",
		Why: "an unreadable org policy, which may be the one enabling Data Access logs, becomes an observed " +
			"audit_logging_all_services=false on every project a project-scoped credential sees",
	},
	// ── no state-changing action proceeds without a human (ADR 087) ─────
	//
	// Two places autonomy can come back: the gate that grants it, and the Go
	// that tells the gate which action is being proposed.
	{
		Guard: "TestAutoExecuteGateRequiresKnownEvidence", Pkg: "./internal/policy",
		File: "internal/policy/policy.go",
		Old:  "\tcase in.ActionClass == classObserve:\n\t\treturn Decision{AllowAuto: true}\n",
		New: "\tcase in.ActionClass == classObserve:\n\t\treturn Decision{AllowAuto: true}\n" +
			"\tcase in.ActionClass == \"remediate\" && in.ConfidenceBand == \"high\":\n\t\treturn Decision{AllowAuto: true}\n",
		Why: "reinstates the confidence-earned autonomy rule ADR 087 removed: a high-confidence remediation would " +
			"execute a cloud mutation that no human said yes to, the one thing the product must never do",
	},
	{
		Guard: "TestDecide_NoStateChangingPlanEverAutoExecutes", Pkg: "./internal/app/respond",
		File: "internal/app/respond/service.go",
		Old:  "policy.Input{\n\t\tActionClass:    string(plan.ActionClass),",
		New:  "policy.Input{\n\t\tActionClass:    string(ClassObserve),",
		Why: "policy.Decide is intact but respond.Decide no longer tells it which action is proposed — every plan " +
			"reaches the gate as a read-only observe and leaves Decide as one, so a remediation drops out of the " +
			"approval queue unasked. Only the seam test with the real gate sees it",
	},
	{
		Guard: "TestBlastRadius_HydrationFailureErrors", Pkg: "./internal/app/asset",
		File: "internal/app/asset/service.go",
		Old:  "\t\t\treturn result, fmt.Errorf(\"BlastRadius: depth %d: hydrate %d nodes: %w\", depth, len(ids), err)\n",
		New:  "\t\t\tfetched = nil // degrade to stubs below\n",
		Why: "restores the verbatim pre-fix line. A ByIDs failure mid-walk substitutes Asset{ID, Type} stubs for " +
			"every node in the hop — no Provider, no RiskScore, no LastSeen — keeps the COUNT correct so nothing " +
			"looks wrong, leaves Truncated false so the reason-cache fingerprint does not even change, and returns " +
			"a nil error. summarizeBlast's ByType and topReachable then render the placeholders to the LLM reasoner " +
			"as measurements, and respond.blastRadiusFor reports the walk as a measurement because it got no error",
	},

	{
		Guard: "TestNodeBudgetFitsTheDeployedMemoryLimit", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/node_budget_test.go",
		Old:  "\treferenceLimitMiB      = 20480\n",
		New:  "\treferenceLimitMiB      = 16384\n",
		Why: "a 16Gi reference worker limit leaves no headroom: GOMEMLIMIT 8192MiB (which Go fills) " +
			"plus graphstore.NodeBudget nodes at the per-node rule of thumb comes to more than the limit, so " +
			"the budget sits outside the memory it claims to fit inside. Nothing else checks this sum, " +
			"because the two numbers live in different files",
		MutatesTest: true,
	},
	{
		Guard: "TestDerive_ReferenceConfiguration", Pkg: "./internal/memlimit",
		File: "internal/memlimit/memlimit_test.go",
		Old:  "\treferenceGoMemLimitMiB = 8192\n",
		New:  "\treferenceGoMemLimitMiB = 18000\n",
		Why: "loosens the reference worker.goMemLimit past the derived budget (cgroup 20480MiB − ladybug 2048MiB − reserve " +
			"1024MiB = 17408MiB derived; 18000MiB exceeds it), which memlimit.Derive is supposed to catch by " +
			"applying whichever of the two is TIGHTER — a goMemLimit raised past the derived ceiling without " +
			"re-deriving is exactly how the original defect (GOMEMLIMIT and the cgroup limit drifting " +
			"apart with nothing comparing them) recurs, and this is the test that pins a reference configuration " +
			"in Go, next to the assertion, so it cannot silently drift the way a hardcoded copy of the " +
			"deployed values once did",
		MutatesTest: true,
	},
	{
		Guard: "TestClassifyRelEndpointsTrustsOnlyVerifiedExpiry", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/copy_load_relcsv.go",
		Old:  "\tif (!srcLoaded && verifiedExpired[src]) || (!dstLoaded && verifiedExpired[dst]) {\n\t\treturn relRowEndpointExpired\n\t}\n",
		New:  "\tif (!srcLoaded && spec.from == NodeK8sWorkload) || (!dstLoaded && spec.to == NodeK8sWorkload) {\n\t\treturn relRowEndpointExpired\n\t}\n",
		Why: "reverts relRowEndpointExpired to trusting the endpoint's declared K8sWorkload label " +
			"instead of the caller's ClickHouse-verified map \u2014 the exact gap the fix closed. A wrong or " +
			"stale producer type, or a future load-set regression that drops a live ephemeral asset for an " +
			"unrelated reason, would force \"expired\" (the never-alerted-on outcome) with nothing ever verifying " +
			"it against the asset table",
	},

	// ── sync/sweep health ──────────────────────
	{
		Guard: "TestBestEffort_ServiceDisabledIsNotPartial", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/gcp.go",
		Old:  "\tif serviceDisabledErr(ctx, err) {",
		New:  "\tif false && serviceDisabledErr(ctx, err) {",
		Why: "reverts bestEffort to folding a permanent SERVICE_DISABLED 403 (a project that has never enabled " +
			"the API being called) into the same Partial flag as a genuine transient failure — which keeps such " +
			"connectors permanently partial and disables deletion reconciliation for their scopes",
	},

	// ── fidelity refusal episodes ──────────────
	{
		Guard: "TestFidelityState_RecordRefusal_TracksDeclineStreak", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/fidelity.go",
		Old:  "\tcase declines(s, *f.refused):\n\t\tf.declineStreak++\n\tcase withinTolerance(s.TotalEdges, f.refused.TotalEdges) && withinTolerance(s.Assets, f.refused.Assets):",
		New:  "\tcase declines(s, *f.refused):\n\t\tf.declineStreak++\n\tcase false:",
		Why: "removes the no-op branch for a retry that reproduces the last refused shape, so it falls through to " +
			"the default (reset to 1) exactly like the original bug \u2014 River retries ladybug_rebuild within seconds " +
			"of every real refusal, so the streak would be reset right before the next real sweep's check reads " +
			"it, and a genuine multi-day monotonic decline could never accumulate declineStreak past 1",
	},
	{
		Guard: "TestFidelityState_RecordRefusal_RetryDoesNotResetTheAgeClock", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/fidelity.go",
		Old:  "\tif newEpisode {\n\t\tf.lastRefusalUnix = nowUnix\n\t}",
		New:  "\tf.lastRefusalUnix = nowUnix",
		Why: "unconditionally overwrites lastRefusalUnix on every call, including a retry seconds after the " +
			"original refusal \u2014 a persistently-retrying failure then never accumulates minRepeatAge of age, so " +
			"neither accept-on-repeat rule can mature, defeating the exact wedge case 4 was meant to fix",
	},
	{
		Guard: "TestFidelityState_RecordRefusal_NewEpisodeResetsTheAgeClock", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/fidelity.go",
		Old:  "\t\tf.declineStreak = 1\n\t\tnewEpisode = true",
		New:  "\t\tf.declineStreak = 1",
		Why: "follow-up to the fix above: drops the default case's newEpisode=true, " +
			"reverting to the old bug where only the very-first-ever refusal (f.refused == nil) reset the age " +
			"clock. A genuinely new, unrelated shape then inherits lastRefusalUnix from whatever earlier, " +
			"unrelated episode was on record \u2014 if that episode was already older than minRepeatAge, the new " +
			"failure's first retry could pass the age gate immediately and publish through accept-on-repeat " +
			"within seconds, the exact bypass minRepeatAge exists to prevent",
	},
	{
		Guard: "TestNextConfirmAnchor_StaysStickyUntilItMatures", Pkg: "./internal/app/forget",
		File: "internal/app/forget/domain.go",
		Old:  "\tcase in.Now.Sub(in.PrevCompleteAt) >= ConfirmWindow:\n\t\t// The anchor just matured",
		New:  "\tcase true:\n\t\t// The anchor just matured",
		Why: "makes the anchor roll forward on EVERY sweep instead of only once it has aged ConfirmWindow \u2014 the " +
			"original bug, where PrevCompleteAt was re-derived from the previous sweep's own completion time every " +
			"cycle, which under a sync cadence of tens of minutes is never more than one interval old, so " +
			"RefusalUnconfirmed could never clear",
	},
	{
		// Reproduces the OBSERVABLE effect (each row's contribution counted
		// twice) rather than the original single-map code path, which no longer
		// exists after splitting perRegion/allRegions into separate maps — that
		// split makes the original key-collision mechanism structurally
		// impossible, so this guards the outcome the split exists to prevent.
		Guard: "TestIndexCounts_EmptyRegionDoesNotDoubleCount", Pkg: "./internal/app/forget",
		File: "internal/app/forget/service.go",
		Old:  "\t\tall.Stored += c.Stored\n\t\tall.Absent += c.Absent\n\t\tall.Confirmed += c.Confirmed\n",
		New:  "\t\tall.Stored += c.Stored + c.Stored\n\t\tall.Absent += c.Absent + c.Absent\n\t\tall.Confirmed += c.Confirmed + c.Confirmed\n",
		Why: "doubles every row's contribution to the cross-region total — the exact effect the region-key " +
			"collision produced when a region-less StoredCount row (Region == \"\", the GCP aggregatedList shape) " +
			"shared its per-region key with the totals accumulator, overwriting it and then adding to the " +
			"overwritten value",
	},

	// ── cost collection must decrypt connector config ─────
	{
		Guard: "TestCostCollectLoopDecryptsConfigBeforeUse", Pkg: "./cmd/graph",
		File: "cmd/graph/serve_costcollect.go",
		Old:  "\t\t\tfull, getErr := connectorSvc.Get(ctx, c.ID)",
		New:  "\t\t\tfull, getErr := connector.Connector{}, error(nil)",
		Why: "reverts the loop to never decrypting the connector's config: connectorSvc.List returns connectors " +
			"with Config == nil by design, so every field this loop reads off it (region, account_id) is " +
			"always empty, baseConfig's \"region is required\" check fails for every AWS connector, and cost " +
			"collection never succeeds on any connector",
	},
	{
		Guard: "TestPoolSizesFitPostgresConnectionLimit", Pkg: "./internal/db",
		File: "internal/db/pool.go",
		Old:  "\tMaxConnsServe   = 10\n\tMaxConnsScanner = 10",
		New:  "\tMaxConnsServe   = 30\n\tMaxConnsScanner = 30",
		Why: "reverts serve and scanner to the original shared MaxConns=30 every caller of NewPool used before " +
			"a later fix: worker+serve+scanner sum to 90 theoretical connections at serve.replicas=1 against " +
			"Postgres max_connections=100, and serve.replicas=2 (otherwise safe) pushes the worst case to 120, " +
			"over the cap",
	},

	// ── ClickHouse best-practices audit ─────────────────────────
	{
		Guard: "TestResolveID_UsesEqualityLookupNotSubstringScan", Pkg: "./internal/app/asset",
		File: "internal/app/asset/service.go",
		Old:  "\tmatches, err := s.repo.FindByExactName(ctx, identifier, resolveCandidates)",
		New:  "\tmatches, err := s.repo.List(ctx, Filter{Search: identifier, Limit: resolveCandidates})",
		Why: "reverts ResolveID to the ILIKE substring-scan fallback over six unindexed columns — a full scan " +
			"per call on a hot path (respond's blast-radius resolution), for a lookup that only ever accepts an exact " +
			"match and gains nothing from the wildcard scan",
	},
	{
		Guard: "TestBindsDanglingBudgetReflectsKnownStaleRBAC", Pkg: "./internal/graphschema",
		File: "internal/graphschema/graphschema.go",
		Old:  "\t\tDanglingBudget: 0.25,",
		New:  "\t\tDanglingBudget: 0.05,",
		Why: "resets binds' dangling budget back to the 0.05 default, silently re-treating a real, " +
			"persistent stale-RBAC population (RoleBindings/ClusterRoleBindings still listing " +
			"deleted ServiceAccounts as subjects) as a graph " +
			"regression it is not — the exact false-alarm shape DanglingBudget exists to prevent",
	},

	// ── Cross-verification sweep: worker sync + CH query + graph consistency ──
	{
		Guard: "TestLadybugGraphCtx_NotFoundFallsBackToClickHouse", Pkg: "./cmd/graph",
		File: "cmd/graph/ladybug_blast.go",
		Old: "\t\tsig, err := g.graph.TryNodeSignals(ctx, resourceID)\n" +
			"\t\tif err == nil && sig.InternetHops != graphstore.ReachUnknown {\n" +
			"\t\t\treturn sig.Exposed, nil",
		New: "\t\tsig, err := g.graph.TryNodeSignals(ctx, resourceID)\n" +
			"\t\tif err == nil {\n" +
			"\t\t\treturn sig.Exposed, nil",
		Why: "restores IsExposedEdge trusting err==nil alone from TryNodeSignals — but nodeSignalByID only " +
			"queries Asset/IamRole, so a pruned or not-yet-loaded resource returns a nil error with the Go " +
			"zero-value NodeSignals (Exposed=false), and that false negative is then cached in nodeSignalsCache " +
			"for the sweep's lifetime, fingerprinting a genuinely exposed resource as clean",
	},
	{
		Guard: "TestLadybugGraphCtx_NotFoundFallsBackToClickHouse", Pkg: "./cmd/graph",
		File: "cmd/graph/ladybug_blast.go",
		Old: "\t\tsig, err := g.graph.TryNodeSignals(ctx, resourceID)\n" +
			"\t\tif err == nil && sig.InternetHops != graphstore.ReachUnknown {\n" +
			"\t\t\treturn enrichcache.PrivescBucketFor(sig.PrivescCount), nil",
		New: "\t\tsig, err := g.graph.TryNodeSignals(ctx, resourceID)\n" +
			"\t\tif err == nil {\n" +
			"\t\t\treturn enrichcache.PrivescBucketFor(sig.PrivescCount), nil",
		Why: "restores PrivescBucket trusting err==nil alone — the same not-found-zero bug as IsExposedEdge, " +
			"but for privilege-escalation finding counts: a pruned/not-yet-loaded resource with real " +
			"ciem_privesc findings reports bucket \"0\" instead of falling back to ClickHouse",
	},
	{
		Guard: "TestLadybugPeerFindings_NotFoundFallsBackToClickHouse", Pkg: "./cmd/graph",
		File: "cmd/graph/ladybug_blast.go",
		Old: "\t\tsig, err := k.graph.TryNodeSignals(ctx, f.ResourceID)\n" +
			"\t\tif err == nil && sig.InternetHops != graphstore.ReachUnknown {\n" +
			"\t\t\tpeers := make([]finding.Finding, 0, sig.PrivescCount+1)",
		New: "\t\tsig, err := k.graph.TryNodeSignals(ctx, f.ResourceID)\n" +
			"\t\tif err == nil {\n" +
			"\t\t\tpeers := make([]finding.Finding, 0, sig.PrivescCount+1)",
		Why: "restores ladybugPeerFindings.List trusting err==nil alone — a not-found resource synthesizes zero " +
			"ciem_privesc/exposure peer findings instead of falling back to ClickHouse, silently under-scoring " +
			"AttackPaths and ToxicCombo for anything Ladybug hasn't loaded yet",
	},
	{
		Guard: "TestChunkIDs_SplitsIntoIDChunkSizeBatches", Pkg: "./internal/app/explore",
		File: "internal/app/explore/repo.go",
		Old:  "\tfor start := 0; start < len(ids); start += idChunkSize {\n\t\tend := start + idChunkSize",
		New:  "\tfor start := 0; start < len(ids); start += len(ids) {\n\t\tend := start + len(ids)",
		Why: "collapses chunkIDs to a single unbounded batch regardless of idChunkSize — the same " +
			"max_query_size failure class as VerifyExpiredEphemeral (internal/app/asset/optimize.go), but " +
			"live and user-facing here (Explore UI, MCP run_cypher, NL→Cypher fallback) since explore's ids " +
			"are commonly ARN-length rather than a batch job silently stalling",
	},
	{
		Guard: "TestPackageDeployExposure_CapsWorkloadFanout", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_supply_chain.go",
		Old: `	repoOut, truncated, err := s.Graph.LineageTargets(ctx, repoIDs, "deploys_to", maxSupplyChainWorkloads)
	if err != nil {
		return deployExposure{}, err
	}
	workloadIDs := dstIDsOfType(repoOut, "deploys_to")
	if len(workloadIDs) == 0 {
		return deployExposure{lineage: true}, nil // shipped but no deployed workload found
	}
	truncated = truncated || len(workloadIDs) > maxSupplyChainWorkloads
	if truncated {
		workloadIDs = workloadIDs[:min(len(workloadIDs), maxSupplyChainWorkloads)]
	}
`,
		New: `	repoOut, truncated, err := s.Graph.LineageTargets(ctx, repoIDs, "deploys_to", maxSupplyChainWorkloads+50)
	if err != nil {
		return deployExposure{}, err
	}
	workloadIDs := dstIDsOfType(repoOut, "deploys_to")
	if len(workloadIDs) == 0 {
		return deployExposure{lineage: true}, nil // shipped but no deployed workload found
	}
	truncated = truncated || len(workloadIDs) > maxSupplyChainWorkloads
`,
		Why: "removes the workloadIDs cap reposDeployExposure's second hop needs — " +
			"maxSupplyChainRepos only bounds the FIRST hop's input, so one repo's deploys_to fanning out " +
			"to many CI/CD environments/regions can still put several thousand ids into an unbounded CHIn, " +
			"the same shape of bug that exceeded max_query_size in VerifyExpiredEphemeral",
	},
	{
		Guard: "TestFilteredAssetReadersAvoidFINAL", Pkg: "./internal/app/asset",
		File: "internal/app/asset/repo.go",
		Old: "\texternalAssetIDs = `SELECT id FROM assets\n" +
			"\t\tGROUP BY id\n" +
			"\t\tHAVING argMax(public_ip, synced_at) != '' OR argMax(domain, synced_at) != ''\n" +
			"\t\tORDER BY max(last_seen) DESC LIMIT ?`",
		New: "\texternalAssetIDs = `SELECT id FROM assets FINAL\n" +
			"\t\tWHERE public_ip != '' OR domain != ''\n" +
			"\t\tORDER BY last_seen DESC LIMIT ?`",
		Why: "restores externalAssetIDs to `assets FINAL WHERE public_ip != '' OR domain != ''` — public_ip/" +
			"domain have no skip index, so FINAL forces a full unindexed dedup-merge scan of the whole assets " +
			"table on every correlate sweep, the full-scan class already documented on assetSelect",
	},
	{
		Guard: "TestLoadDigest_SignalChangeMovesOnlySignalsHalf", Pkg: "./internal/app/graphstore",
		File: "internal/app/graphstore/loaddigest.go",
		Old: "\t\tepss := float64(0)\n" +
			"\t\tif s.CveID != \"\" {\n" +
			"\t\t\tepss = s.EPSSScore\n" +
			"\t\t}\n" +
			"\t\t_, _ = fmt.Fprintf(h, \"|%g\", epss)",
		New: "\t\t_, _ = fmt.Fprintf(h, \"|%g\", s.EPSSScore)",
		Why: "restores signalsDigest hashing the raw EPSSScore unconditionally, dropping the CveID-empty " +
			"zeroing rule appendNodeValues (node_rows.go) applies when actually loading the row — a stale " +
			"EPSSScore left behind an emptied CveID would then move the digest for a value that is never " +
			"actually loaded, the digest-vs-loader asymmetry the load-digest gate exists to forbid",
	},

	// ── Deletion-authority per-scope vs connector-wide gating ──
	{
		Guard: "TestCheckDelivered_MismatchAndPassthrough", Pkg: "./internal/jobs",
		File: "internal/jobs/sync_lifecycle.go",
		Old:  "\t\tif delivered[key] < se.Count {\n\t\t\treturn false\n\t\t}",
		New:  "\t\t_ = delivered[key]",
		Why: "disables the claim/payload divergence check that replaced the connector-wide partial gate — a " +
			"collector goroutine can call MarkComplete and then panic before its assets are appended to " +
			"res.Assets (aws.go's complete()/append are two separate, non-atomic steps under two different " +
			"mutexes), and without this check a proven-complete scope with an empty or short payload would " +
			"read as 'everything in this scope was deleted' instead of being dropped from " +
			"the sweep's evaluation",
	},

	// ── External (non-graph_) metric names ──
	{
		Guard: "TestAlertRulesReferenceOnlyKnownExternalMetrics", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old:  "max by (namespace) (container_spec_memory_limit_bytes{namespace=\"__NAMESPACE__\", container=\"worker\"} > 0)",
		New:  "max by (namespace) (container_spec_memory_limit_byte{namespace=\"__NAMESPACE__\", container=\"worker\"} > 0)",
		Why: "drops the trailing 's' from a cAdvisor metric name in GraphWorkerMemoryPeakNearLimit's denominator. " +
			"Every pre-existing check here is blind to it: metricRef only matches `graph_[a-z0-9_]+`, so a typo in " +
			"a kube-state-metrics/cAdvisor/process-collector name passes rule validation, loads into Prometheus, " +
			"and evaluates forever against a series that does not exist — the division silently yields no " +
			"samples, so the alert never fires and its silence is indistinguishable from healthy memory. " +
			"This is the alerting twin of the dark-metric class that left the observability gauges dead code",
	},

	// ── Junk-rate GuardDuty false positive ──
	{
		Guard: "TestCheckJunkRateAlertExcludesGuardDuty", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old: "          max by (namespace, check_id, source) (max_over_time(graph_check_junk_rate{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) > 0.9\n" +
			"          and on (namespace, check_id, source)\n" +
			"          max by (namespace, check_id, source) (min_over_time(graph_check_quality_measurable{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) == 1\n",
		New: "          max by (namespace, check_id, source) (max_over_time(graph_check_junk_rate{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) > 0.9\n" +
			"          and on (namespace, check_id, source)\n" +
			"          max by (namespace, check_id, source) (min_over_time(graph_check_quality_measurable{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) == 1\n",
		Why: "drops the aws_guardduty exclusion from the measurable-selector half of GraphCheckJunkRateHigh " +
			"— aws_guardduty findings have no coded 'fixed' path anywhere in this codebase, so their junk " +
			"rate sits near 1.0 forever regardless of real detection quality, the same permanently-firing " +
			"shape nuclei's exclusion (TestMustFixCoverageAlertExcludesNuclei) already guards against on " +
			"GraphMustFixClassAllBlank",
	},

	// ── Six more no-fixed-path sources ──
	{
		Guard: "TestCheckJunkRateAlertExcludesEveryNoFixedPathSource", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old: "          max by (namespace, check_id, source) (max_over_time(graph_check_junk_rate{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) > 0.9\n" +
			"          and on (namespace, check_id, source)\n" +
			"          max by (namespace, check_id, source) (min_over_time(graph_check_quality_measurable{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) == 1\n",
		New: "          max by (namespace, check_id, source) (max_over_time(graph_check_junk_rate{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\"}[10m])) > 0.9\n" +
			"          and on (namespace, check_id, source)\n" +
			"          max by (namespace, check_id, source) (min_over_time(graph_check_quality_measurable{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\"}[10m])) == 1\n",
		Why: "drops the exclusions for gcp_scc/iac/nuclei/ci_access " +
			"from GraphCheckJunkRateHigh — each shares aws_guardduty's exact structural gap " +
			"(no coded 'fixed' resolution path anywhere in this codebase), so each is guaranteed to hit this " +
			"alert's threshold once it accumulates enough resolution volume; excluded preventatively before " +
			"that happens, not retroactively after",
	},

	// ── Alert severity fan-out ──
	{
		Guard: "TestNoRuleIsCriticalWithoutJustification", Pkg: "./internal/obs",
		File: "deploy/helm-chart/graph/alerts/rules.yaml",
		Old: "      - alert: GraphCheckJunkRateHigh\n" +
			"        expr: |-\n" +
			"          max by (namespace, check_id, source) (max_over_time(graph_check_junk_rate{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) > 0.9\n" +
			"          and on (namespace, check_id, source)\n" +
			"          max by (namespace, check_id, source) (min_over_time(graph_check_quality_measurable{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) == 1\n" +
			"        for: 24h\n" +
			"        labels:\n" +
			"          severity: warning\n",
		New: "      - alert: GraphCheckJunkRateHigh\n" +
			"        expr: |-\n" +
			"          max by (namespace, check_id, source) (max_over_time(graph_check_junk_rate{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) > 0.9\n" +
			"          and on (namespace, check_id, source)\n" +
			"          max by (namespace, check_id, source) (min_over_time(graph_check_quality_measurable{namespace=\"__NAMESPACE__\", component=\"worker\", source!=\"aws_guardduty\", source!=\"gcp_scc\", source!=\"iac\", source!=\"nuclei\", source!=\"ci_access\"}[10m])) == 1\n" +
			"        for: 24h\n" +
			"        labels:\n" +
			"          severity: critical\n",
		Why: "restores a rule to severity:critical with no allowlist entry — the exact " +
			"noise problem (internal pipeline-health alerts duplicating into a wider critical " +
			"channel) that moved every rule in this file to warning by default",
	},

	// ── Worker struct field wiring ──
	{
		Guard: "TestWorkerStructFieldsAreWiredAtConstruction",
		Pkg:   "./internal/jobs",
		File:  "internal/jobs/client.go",
		Old:   "\t\tforget: deps.Forget, suppressions: suppressionCarrier(deps.Suppress),\n",
		New:   "\t\tsuppressions: suppressionCarrier(deps.Suppress),\n",
		Why:   "Omitting SyncWorker.forget silently disables cleanup of stale assets.",
	},

	// ── Cross-package known-ness pairing ──
	{
		Guard: "TestKnownnessFieldsArePaired", Pkg: "./internal/guardknownness",
		File: "internal/app/govern/domain.go",
		Old:  "\tBlastRadiusKnown bool\n",
		New:  "",
		Why:  "deletes the companion field itself — the declaration half of the convention has nothing to check against",
	},
	{
		Guard: "TestKnownnessGatesCheckTheirCompanion", Pkg: "./internal/guardknownness",
		File: "internal/app/govern/service.go",
		Old:  "// confKey is the (action class, dominant resource type) pair that identifies a\n",
		New: "func smallCluster(it QueueItem) bool {\n\tif it.BlastRadius <= 5 {\n\t\treturn true\n\t}\n\treturn false\n}\n\n" +
			"// confKey is the (action class, dominant resource type) pair that identifies a\n",
		Why: "reintroduces the unmeasured-blast-radius bug shape: a new cap check on a cluster's BlastRadius with no " +
			"BlastRadiusKnown in sight — an unmeasured walk (0) passes it MORE easily than a real measurement, the " +
			"failure CLAUDE.md names, wherever the next such gate is written",
	},

	// ── egress controls ──────────────────────────────────────────────────

	{
		Guard: "TestNewInternalVia_NamedProxyOnly", Pkg: "./pkg/safenet",
		File: "pkg/safenet/http.go",
		Old:  "\t\tproxyFunc = http.ProxyURL(proxy)\n",
		New:  "\t\tproxyFunc = http.ProxyFromEnvironment\n",
		Why: "a client built for one named proxy reads HTTPS_PROXY/HTTP_PROXY instead, so the call goes through " +
			"whatever proxy the environment names, or none",
	},

	{
		Guard: "TestNoHTTPClientConstructedOutsideSafenet", Pkg: "./pkg/safenet",
		File: "internal/app/explore/ladybug_rpc_repo.go",
		Old:  "\t\tclient:  safenet.NewInternal(LadybugRPCTimeout),",
		New:  "\t\tclient:  &http.Client{Timeout: LadybugRPCTimeout},",
		Why: "a hand-built client bypasses the safenet factories, so the next copy of it pointed at a " +
			"connector-supplied URL dials private addresses with no SSRF guard",
	},

	// ── distro advisory matching (recorded OSV / updateinfo fixtures) ────
	{
		Guard: "TestQuery_RedHat_KeepsOnlyTheHostsRelease", Pkg: "./internal/intel/osv",
		File: "internal/intel/osv/distro.go",
		Old:  "		streams := \"Red Hat:enterprise_linux:\" + release + \"::\"\n",
		New:  "		streams := \"Red Hat:enterprise_linux:\"\n",
		Why: "a RHEL host is held against every stream the bare-family query returns, so a RHEL 10 fix " +
			"reads as a RHEL 9 vulnerability and a patched host keeps findings",
	},
	{
		Guard: "TestQuery_SUSE_MatchesServicePack", Pkg: "./internal/intel/osv",
		File: "internal/intel/osv/distro.go",
		Old:  "	return strings.HasSuffix(product, \" \"+token) || strings.Contains(product, \" \"+token+\"-\")\n",
		New:  "	return product != \"\" && token != \"\"\n",
		Why:  "every SUSE product matches every service pack, so a 15 SP4 host inherits 15 SP5 advisories",
	},
	{
		Guard: "TestFetch_MirrorListRepomdUpdateinfo", Pkg: "./internal/intel/updateinfo",
		File: "internal/intel/updateinfo/fetch.go",
		Old:  "			req.Header.Set(\"If-None-Match\", prev.etag)\n",
		New:  "			_ = prev.etag\n",
		Why:  "repomd is re-downloaded unconditionally: the daily refresh stops being a conditional GET",
	},
	{
		Guard: "TestFetch_AnyRepoFailingFailsTheRelease", Pkg: "./internal/intel/updateinfo",
		File: "internal/intel/updateinfo/fetch.go",
		Old:  "		if err != nil {\n			return nil, fmt.Errorf(\"Fetch %s: %w\", src.Ecosystem, err)\n		}\n",
		New:  "		if err != nil {\n			continue\n		}\n",
		Why: "an unread repository (Oracle AppStream) drops out silently, and the refresh reconciles " +
			"against the partial advisory set as if its advisories had been fixed",
	},

	// ── source-package matching (recorded dpkg / apk fixtures) ────────────
	{
		Guard: "TestDpkgPackages_CarrySourcePackage", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/packages.go",
		Old:  "		case \"Source\":\n			src = value\n",
		New:  "		case \"Source\":\n			_ = value\n",
		Why: "dpkg's Source field is ignored, so libc6 is asked of OSV as libc6 rather than glibc and " +
			"matches nothing: Debian advisories are keyed by source package",
	},
	{
		Guard: "TestDpkgPackages_UbuntuSource", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/packages.go",
		Old:  "	if !ok {\n		return field, \"\"\n	}\n",
		New:  "	if !ok {\n		return name, \"\"\n	}\n",
		Why:  "a Source field without a version is dropped, so Ubuntu's libssl3 is queried as libssl3 (0 advisories) not openssl",
	},
	{
		Guard: "TestApkPackages_CarryOrigin", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/packages.go",
		Old:  "			origin = strings.TrimPrefix(line, \"o:\")\n",
		New:  "			_ = line\n",
		Why:  "apk's origin is ignored, so libcrypto3 is asked of OSV as itself (0 advisories) rather than openssl",
	},
	{
		Guard: "TestScanImage_QueriesBySourcePackage", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/imagevuln.go",
		Old:  "		name, version := distro.AdvisoryQuery(p.Ecosystem, p.Name, p.Version, p.SourceName, p.SourceVersion)\n",
		New:  "		name, version := distro.AdvisoryQuery(p.Ecosystem, p.Name, p.Version, \"\", \"\")\n",
		Why: "the image scanner asks OSV by binary name, so every Debian/Ubuntu/Alpine binary whose name " +
			"differs from its source package (libssl3, libc6, libcrypto3) reads as clean",
	},
	{
		Guard: "TestOSVWorker_DebianQueriesSourceNameAndVersion", Pkg: "./internal/jobs",
		File: "internal/jobs/osv.go",
		Old:  "				a.Metadata[pkginventory.MetaSourcePackage], a.Metadata[pkginventory.MetaSourceVersion])\n",
		New:  "				a.Metadata[pkginventory.MetaSourcePackage], \"\")\n",
		Why:  "a binNMU is asked at its binary version, which Debian's source-versioned records do not describe",
	},
	{
		Guard: "TestOSVWorker_ReconcileSkipsSourceKeyedPackagesWithoutSourceName", Pkg: "./internal/jobs",
		File: "internal/jobs/osv.go",
		Old:  "				if !unsourced[purl] {\n",
		New:  "				if unsourced[purl] || !unsourced[purl] {\n",
		Why: "a source-keyed binary asked by its own name (a lower bound) has the image scanner's findings " +
			"resolved as fixed by the daily refresh",
	},
	{
		Guard: "TestDpkgPackages_DistrolessStatusD", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/packages.go",
		Old:  "	entries, err := fs.ReadDir(root, dpkgStatusDir)\n",
		New:  "	entries, err := fs.ReadDir(root, dpkgStatusPath)\n",
		Why:  "distroless status.d paragraphs are never read, so a distroless image has no OS packages at all",
	},
	{
		Guard: "TestRegistryImageSource_ReadsDistrolessStatusD", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/pkginventory/packages.go",
		Old:  "		if f, err = root.Open(usrOSReleasePath); err != nil {\n",
		New:  "		if f, err = root.Open(osReleasePath); err != nil {\n",
		Why: "usr/lib/os-release is not read, so an image whose etc/os-release is a symlink (Debian, Ubuntu, " +
			"distroless) is stamped unqualified \"Debian\" — Ubuntu packages matched against Debian advisories",
	},
	{
		Guard: "TestOSVWorker_OneFindingPerCVE", Pkg: "./internal/jobs",
		File: "internal/intel/osv/hits.go",
		Old:  "	if cves := v.CVEs(); len(cves) > 0 && !IsMalicious(v.ID) {\n		return cves\n",
		New:  "	if cves := v.CVEs(); len(cves) > 0 && !IsMalicious(v.ID) {\n		return cves[:1]\n",
		Why: "a distro advisory bundling several CVEs becomes one finding keyed on its first CVE, so KEV and " +
			"EPSS never see a known-exploited CVE listed second",
	},
	{
		Guard: "TestHits_OnePerCVEAcrossDistroAdvisories", Pkg: "./internal/intel/osv",
		File: "internal/intel/osv/hits.go",
		Old:  "		return na < nb\n",
		New:  "		return na > nb\n",
		Why:  "the bundle, not the per-CVE record, describes a merged hit — and which one wins depends on what else it bundles",
	},
	{
		Guard: "TestCVEGap_AdvisorySourceDisabled", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/osinventory.go",
		Old:  "	case !enabled[fam.Source]:\n",
		New:  "	case enabled == nil && !enabled[fam.Source]:\n",
		Why: "a VM whose advisory feed is switched off (INTEL_ALAS_DISABLED, OFFLINE_MODE) is stamped matchable, " +
			"and its empty finding list reads as clean",
	},
	{
		Guard: "TestScanImage_OSPackagesUnmatchableIsAFinding", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/pkginventory/rpm.go",
		Old:  "		if err == nil {\n			_ = f.Close()\n			return p\n",
		New:  "		if err == nil && p == \"\" {\n			_ = f.Close()\n			return p\n",
		Why:  "an rpm-based image whose database cannot be read reports no gap, and reads exactly like a patched one",
	},

	// ── rpm database reader wiring (recorded rpmdb fixtures) ──────────────
	{
		Guard: "TestEveryRPMDBPathIsRead", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/langpackages.go",
		Old:  "	if slices.Contains(rpmDBPaths, p) || isRPMWAL(p) {\n",
		New:  "	if slices.Contains(rpmDBPaths[:0], p) || isRPMWAL(p) {\n",
		Why: "an rpm database is never streamed out of an image layer, so an rpm-based image has no OS " +
			"packages and no gap — it reads like a scratch image",
	},
	{
		Guard: "TestRegistryImageSource_ReadsRPMDatabase", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "		w.keep(clean, nil)\n		return nil\n	}\n	data, err := io.ReadAll(io.LimitReader(r, size))\n",
		New:  "		w.keep(clean, nil)\n		return nil\n	}\n	data, err := io.ReadAll(io.LimitReader(r, 0))\n",
		Why: "the layer walker keeps an rpm database's presence but not its bytes, so every rpm-based " +
			"image is package_db_unread and none of its packages are matched",
	},
	{
		Guard: "TestInventoryPackages_ReadsRPMDatabases", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/packages.go",
		Old:  "	out = append(out, rpm...)",
		New:  "	out = append(out, rpm[:0]...)",
		Why:  "the rpm packages are read and dropped, so a RHEL, Amazon Linux or SUSE root inventories no OS packages",
	},
	{
		Guard: "TestScanImage_AmazonLinuxRoutedToALAS", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/imagevuln.go",
		Old:  "		if !distro.MatchedByOSV(p.Ecosystem) {\n",
		New:  "		if false && !distro.MatchedByOSV(p.Ecosystem) {\n",
		Why: "Amazon Linux packages are asked of OSV, which reports them unqueried, and the OSV adapter " +
			"fails every Amazon Linux image scan",
	},
	{
		Guard: "TestImageVulnWorker_ResolvesCoverageOnceMatchable", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln_coverage.go",
		Old:  "	if res.OSCVEGap == \"\" {\n		ids = append(ids, imagevuln.OSCoverageFindingID(digest))\n",
		New:  "	if res.OSCVEGap == \"never\" {\n		ids = append(ids, imagevuln.OSCoverageFindingID(digest))\n",
		Why: "an image's coverage finding stays open after the scanner learns to read its rpm database: " +
			"every UBI, Rocky and Amazon Linux image keeps claiming it is unmatched",
	},
	{
		Guard: "TestImageVulnWorker_ResolvesLanguageCoverageIndependently", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln_coverage.go",
		Old:  "	if res.LanguageGap == \"\" && res.OSCVEGap != asset.CVEGapScanIncomplete {\n",
		New:  "	if true {\n",
		Why:  "an image's language-coverage finding is closed by a scan that still missed language packages",
	},
	{
		Guard: "TestImageVulnWorker_PartialWalkKeepsLanguageCoverageOpen", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln_coverage.go",
		Old:  "	if res.LanguageGap == \"\" && res.OSCVEGap != asset.CVEGapScanIncomplete {\n",
		New:  "	if res.LanguageGap == \"\" {\n",
		Why:  "a walk cut short at the stream cap closes the language finding for layers it never reached",
	},
	{
		Guard: "TestLanguagePackages_GoProbeBudgetStopsTheWalk", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/langpackages.go",
		Old:  "		gap = fmt.Sprintf(\"the %d MiB Go build-info probe budget",
		New:  "		_ = fmt.Sprintf(\"the %d MiB Go build-info probe budget",
		Why:  "a disk's Go binaries past the probe budget are only logged, and read as having no modules",
	},
	{
		Guard: "TestReadManifests_HardlinkToAReadTargetIsNoGap", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "	if _, read := w.read[normalizeTarPath(target)]; read {\n",
		New:  "	if _, read := w.read[normalizeTarPath(target)]; read && target == \"\" {\n",
		Why:  "every conda env hardlink into pkgs/ raises a false language gap",
	},
	{
		Guard: "TestReadManifests_HardlinkToAReadTargetIsNoGap", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "	if _, read := w.read[normalizeTarPath(target)]; read {\n",
		New:  "	if _, read := w.read[normalizeTarPath(target)]; read || target != \"\" {\n",
		Why:  "a hardlink into an unread pnpm store is taken as read, and its packages vanish silently",
	},
	{
		Guard: "TestReadManifests_HardlinkedManifestsAreGaps", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "	case languageKind(kind):\n",
		New:  "	case kind.IsLanguage():\n",
		Why:  "a hardlinked root package-lock.json marks the OS walk incomplete instead of a language gap",
	},
	{
		Guard: "TestReadManifests_RetentionCapsAreAGap", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "		w.skipOversized(clean, hdr.Size, languageKind(kind))\n",
		New:  "		w.skipOversized(clean, hdr.Size, false)\n",
		Why:  "an oversized root lockfile turns a fully matched OS inventory into scan_incomplete",
	},
	{
		Guard: "TestTranslationAddressesCannotReachMetadata", Pkg: "./pkg/safenet",
		File: "pkg/safenet/http.go",
		Old:  "		return []netip.Addr{v4([4]byte{b[2], b[3], b[4], b[5]})}\n",
		New:  "		return []netip.Addr{v4([4]byte{b[4], b[5], b[6], b[7]})}\n",
		Why:  "6to4 addresses are decoded at the wrong offset, so 2002:6464:64c8:: reaches Alibaba's metadata service",
	},
	{
		Guard: "TestTranslationAddressesCannotReachMetadata", Pkg: "./pkg/safenet",
		File: "pkg/safenet/http.go",
		Old:  "	for _, v4 := range embeddedIPv4(addr) {\n",
		New:  "	for _, v4 := range embeddedIPv4(addr)[:0] {\n",
		Why:  "64:ff9b::a9fe:a9fe — 169.254.169.254 through NAT64 — is dialable once an allow list covers it",
	},
	{
		Guard: "TestTranslationAddressesCannotReachMetadata", Pkg: "./pkg/safenet",
		File: "pkg/safenet/http.go",
		Old:  "		for _, t := range translationRanges {\n",
		New:  "		for _, t := range translationRanges[:0] {\n",
		Why:  "an allow list may cover NAT64/6to4/Teredo space and with it every IPv4 address it embeds",
	},
	{
		Guard: "TestReadManifests_RetentionCapsAreAGap", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "	w.resolved[clean] = struct{}{}\n	if len(w.files) >= maxRetainedFiles {\n",
		New:  "	if len(w.files) >= maxRetainedFiles {\n",
		Why:  "a file refused at the retention cap leaves its path open, and an older layer's copy is kept instead",
	},
	{
		Guard: "TestReadManifests_RetentionCapsAreAGap", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "		w.skipOversized(clean, size, true)\n		return nil\n",
		New:  "		w.skipOversized(clean, size, true)\n		return errStreamBudget\n",
		Why:  "one oversized node_modules package.json or dist-info METADATA stops the walk and loses the base layer",
	},
	{
		Guard: "TestParseLanguage_GoProbeBudgetIsEnforced", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "		w.markLanguageGap(fmt.Sprintf(\"the %d MiB Go build-info probe budget",
		New:  "		_ = (fmt.Sprintf(\"the %d MiB Go build-info probe budget",
		Why:  "Go binaries past the probe budget are skipped silently and read as having no modules",
	},
	{
		Guard: "TestReadManifests_HardlinkedManifestsAreGaps", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "			w.noteUnreadHardlink(clean, hdr.Linkname)\n",
		New:  "			_ = clean\n",
		Why:  "a hardlinked manifest is taken without being read, and its packages vanish silently",
	},
	{
		Guard: "TestScanImage_LanguageGapDoesNotFlipTheOSGap", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/imagevuln.go",
		Old:  "	if incomplete != \"\" {\n",
		New:  "	if incomplete+langGap != \"\" {\n",
		Why:  "a skipped Go binary turns a fully matched OS inventory into scan_incomplete",
	},
	{
		Guard: "TestImageScanMaxStream", Pkg: "./cmd/graph",
		File: "cmd/graph/worker_deps.go",
		Old:  "	return int64(n) << 30, nil\n",
		New:  "	return int64(n), nil\n",
		Why:  "IMAGE_SCAN_MAX_STREAM_GIB is read as bytes, so every image scan stops almost at once",
	},
	// ── alert noise (ADR 088/089 amendments) ────────────────────────────
	{
		Guard: "TestEnrichWorker_NSweeps_OneAlert", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich_alert.go",
		Old:  "\t\tcase err == nil:\n\t\t\tprev = st\n",
		New:  "\t\tcase err == nil:\n\t\t\t_ = st\n",
		Why:  "the last-alert ledger is ignored, so every correlate sweep's re-enrich re-sends \"New critical finding\"",
	},
	{
		Guard: "TestEnrichWorker_ResolvedFindingSkipped", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich.go",
		Old:  "\tif f.Resolved() {\n",
		New:  "\tif false {\n",
		Why:  "a resolved finding is re-scored and alerted on as if it were still open",
	},
	{
		Guard: "TestInvalidateExposedFindings_SkipsResolved", Pkg: "./internal/jobs",
		File: "internal/jobs/correlate.go",
		Old:  "\t\t\tif !f.Resolved() {\n",
		New:  "\t\t\tif true {\n",
		Why:  "every correlate sweep re-enqueues the resolved findings on exposed assets",
	},
	{
		Guard: "TestEnrichWorker_GraphReadErrorIsNotAStateChange", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich_fingerprint.go",
		Old:  "\treturn enrichcache.CarryForward(in, m, prev)\n",
		New:  "\treturn enrichcache.CarryForward(in, enrichcache.Measured{Exposed: true, Privesc: true, Reach: true}, prev)\n",
		Why:  "a failed graph read hashes its zero value, so the fingerprint flaps on every outage and recovery",
	},
	{
		Guard: "TestSupplyChain_TruncatedWalkNeverContained", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/mustfix.go",
		Old:  "\tcase repoTruncated:\n",
		New:  "\tcase repoTruncated && false:\n",
		Why:  "a lineage walk capped at 200 runners claims \"not internet-reachable\" and INV-3 caps the score",
	},
	{
		Guard: "TestSupplyChain_KEVAndMaliciousNeverContained", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/mustfix.go",
		Old:  "\tcase f.KnownExploited && (imageKnown || repoKnown):\n",
		New:  "\tcase false:\n",
		Why:  "a KEV package on internal workloads is stamped contained and grounded as Low",
	},
	{
		Guard: "TestAggregate_RootCauseCapsBelowPageOverAPageFloor", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/score.go",
		Old:  "\tif rootCause && sum >= ThresholdPage {\n",
		New:  "\tif false && rootCause && sum >= ThresholdPage {\n",
		Why:  "a fleet-canonical KEV package pages beside its fleets: 11 pages for 10 fleets",
	},
	{
		Guard: "TestIsControlled", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/mustfix.go",
		Old:  "a.Metadata[\"active_key_count\"] == \"0\"",
		New:  "atoiOr(a.Metadata[\"active_key_count\"], 0) == 0",
		Why:  "an iam_user whose access keys could not be listed reads as keyless and is demoted to controlled",
	},
	{
		Guard: "TestAlertCarrier", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_supply_chain_rootcause.go",
		Old:  "\t\t\tif err != nil || running != len(listed) {\n",
		New:  "\t\t\tif err != nil || running < 0 {\n",
		Why:  "a capped root-cause image listing is read as complete, silencing CVEs on images it never named",
	},
	{
		Guard: "TestRoutingOf_PackageFindingRoutesToRunners", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/routing_package.go",
		Old:  "\towner, ok := commonOwner(exposedRunners)\n",
		New:  "\towner, ok := commonOwner(allRunners)\n",
		Why:  "a package alert routes to whoever runs it most, not to the owner of the exposed host that makes it urgent",
	},
	{
		Guard: "TestReconcile_HighFloorNeverGroundsBelowHigh", Pkg: "./internal/app/belief",
		File: "internal/app/belief/reconcile.go",
		Old:  "\tif in.HighFloor && (",
		New:  "\tif false && in.HighFloor && (",
		Why:  "a GuardDuty C&C detection on an internal host is grounded as a confirmed Low",
	},
	{
		Guard: "TestDispatch_OwnerWithNoChannelRoutesAsUnowned", Pkg: "./internal/app/notify",
		File: "internal/app/notify/service.go",
		Old:  "\tn.Unowned = true\n\treturn n\n}\n",
		New:  "\treturn n\n}\n",
		Why:  "an alert whose owner has no channel (\"repo:org/x\") reaches no channel at all",
	},
	{
		Guard: "TestResolve_RereadsBeforeWriting", Pkg: "./internal/app/finding",
		File: "internal/app/finding/service.go",
		Old:  "\t\t\tfresh = append(fresh, st)\n",
		New:  "\t\t\tfresh = append(fresh, caller)\n",
		Why:  "Resolve writes back the caller's stale row, reverting what a sync recorded since",
	},
	{
		Guard: "TestNewFindingNotification_RoutingContext", Pkg: "./internal/jobs",
		File: "internal/jobs/alerts.go",
		Old:  "\t\tenv = string(asset.EnvUnknown)\n",
		New:  "\t\tenv = string(asset.EnvUnknown)[:0]\n",
		Why:  "an alert whose environment read failed is rejected by every env-scoped channel",
	},
	{
		Guard: "TestEnrichWorker_UndeliveredAlertIsRetried", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich_alert.go",
		Old:  "\tif err != nil || delivered == 0 {\n",
		New:  "\tif err != nil {\n",
		Why:  "a page no channel delivered (Slack down, no channel accepting it) is recorded as sent and never retried",
	},
	{
		Guard: "TestResolve_NotifiesTheResolveObserver", Pkg: "./internal/app/finding",
		File: "internal/app/finding/service.go",
		Old:  "\tif s.resolved != nil && len(fresh) > 0 {\n",
		New:  "\tif false && s.resolved != nil && len(fresh) > 0 {\n",
		Why:  "a resolve never ends the alert episode, so a finding that paged once never pages on regression",
	},
	{
		Guard: "TestFindingsResolved_EndsTheAlertEpisode", Pkg: "./internal/app/enrichcache",
		File: "internal/app/enrichcache/service.go",
		Old:  "\t\ts.repo.ClearAlertStates(ctx, findingIDs),\n",
		New:  "\t\tnil,\n",
		Why:  "a resolved finding keeps its alert high-water mark, so its regression is deduped against the old page",
	},
	{
		Guard: "TestAlertable_ReachIndependentClasses", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich_alert.go",
		Old:  "\treturn score.Band == enrich.BandHigh && enrich.UrgentRegardlessOfReach(score.Factors)\n",
		New:  "\treturn false\n",
		Why:  "GuardDuty C&C/Backdoor, SCC threats, live secrets and DNS takeovers only floor to High, so a page-only bar silences them",
	},
	{
		Guard: "TestAlertCarrier", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_supply_chain_rootcause.go",
		Old:  "\t\tif !ok || !BandAtLeast(rc.band, memberBand) {\n",
		New:  "\t\tif !ok {\n",
		Why:  "a member paging on points (or newly KEV) is silenced by a base that never raised that page",
	},
	{
		Guard: "TestFingerprintInput_RootCauseCounts", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich_fingerprint.go",
		Old:  "\t\tRootCause:      rootCauseCounts(f),\n",
		New:  "\t\tRootCause:      \"\",\n",
		Why:  "a base that gains a KEV member keeps its fingerprint, so it is never re-scored to the page its silenced members rely on",
	},
	{
		Guard: "TestThreatFloor_GuardDutySeverityFallback", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_threat_floor.go",
		Old:  "\tif f.Source == \"aws_guardduty\" && !strings.HasPrefix(id, \"Policy:\") {\n",
		New:  "\tif false && f.Source == \"aws_guardduty\" && !strings.HasPrefix(id, \"Policy:\") {\n",
		Why:  "a critical GuardDuty AttackSequence/ReverseShell/Trojan finding no marker names lands in pipeline and never pages",
	},
	{
		Guard: "TestEnrichWorker_ResolvedDuringEnrich_NothingRecorded", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich.go",
		Old:  "err == nil && fresh.Resolved() {\n",
		New:  "err == nil && fresh.Resolved() && false {\n",
		Why:  "a finding resolved mid-enrich alerts as New and gets its cleared alert state written back",
	},
	{
		Guard: "TestEnrichWorker_NoChannelsConfigured_KeepsTheChangeGate", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich_alert.go",
		Old:  "\t\tif err == nil && !w.anyChannels(ctx) {\n",
		New:  "\t\tif err == nil && !w.anyChannels(ctx) && false {\n",
		Why:  "an install with no channels re-enriches every alertable finding on every visit, the change-gate disabled",
	},
	{
		Guard: "TestAlertCarrier_FleetBandIsTheMinimumOverFleets", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_supply_chain_vm.go",
		Old:  "!seen || bandRank(b) < bandRank(cov.minBand)",
		New:  "!seen || bandRank(b) > bandRank(cov.minBand)",
		Why:  "one paging fleet silences a member whose sibling fleet never paged",
	},
	{
		Guard: "TestThreatFloor_GuardDutySeverityFallback", Pkg: "./internal/app/enrich",
		File: "internal/app/enrich/sources_threat_floor.go",
		Old:  "f.Source == \"aws_guardduty\" && !strings.HasPrefix(id, \"Policy:\")",
		New:  "f.Source == \"aws_guardduty\"",
		Why:  "a standing-configuration Policy: finding (root credentials used) floors to High and alerts like a compromise",
	},
	{
		Guard: "TestEnrichWorker_ChannelCheckError_StillRetries", Pkg: "./internal/jobs",
		File: "internal/jobs/enrich_alert.go",
		Old:  "\treturn err != nil || has\n",
		New:  "\treturn (err != nil && false) || has\n",
		Why:  "an unreadable channel list reads as no channels, so an undelivered page is given up on",
	},
	{
		Guard: "TestNoRecipientWarnIsRateLimited", Pkg: "./internal/app/notify",
		File: "internal/app/notify/service.go",
		Old:  "now.Sub(s.noRecipientLastWarn) < noRecipientWarnEvery {",
		New:  "now.Sub(s.noRecipientLastWarn) < 0 {",
		Why:  "every retry of an undelivered alert logs a warning",
	},

	// ── image scanner: partial walks, whiteouts, unscanned images, SSRF ───
	{
		Guard: "TestScanImage_IncompleteWalkIsAGapNotAClean", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/imagevuln.go",
		Old:  "		gap, detail = asset.CVEGapScanIncomplete, incomplete\n",
		New:  "		_ = incomplete\n",
		Why: "an image whose base layer was never read (stream cap, corrupt layer) is recorded as a clean, " +
			"complete scan, and its coverage finding is resolved",
	},
	{
		Guard: "TestReadManifests_CorruptLayerStopsTheWalkAndSaysSo", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "		return counted.n, fmt.Errorf(\"corrupt layer: %w\", err)\n",
		New:  "		return counted.n, nil\n",
		Why: "a corrupt layer is read as complete: its remainder — whiteouts included — is dropped and the " +
			"older layers are read past it",
	},
	{
		Guard: "TestReadManifests_DirectoryWhiteoutHidesItsTree", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "		if _, gone := w.resolved[dir]; gone {\n",
		New:  "		if _, gone := w.resolved[dir+\"/\"]; gone {\n",
		Why: "`rm -rf /app/node_modules` resurrects every package below it from the older layer: phantom " +
			"packages with phantom CVEs",
	},
	{
		Guard: "TestOSCVEGap_DegradedRoots", Pkg: "./internal/scanner/pkginventory",
		File: "internal/scanner/pkginventory/osinventory.go",
		Old:  "	return eco, asset.CVEGapPackageDBUnread,\n		fmt.Sprintf(\"os-release names %q",
		New:  "	return eco, \"\",\n		fmt.Sprintf(\"os-release names %q",
		Why: "an image that runs a known distribution but yields no OS packages (Ubuntu Chiseled, an empty " +
			"database) reads as having no OS — clean",
	},
	{
		Guard: "TestImageVulnWorker_FailedScanKeepsLastKnownPackagesLive", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln_coverage.go",
		Old:  "		n, err := w.restampPackageEdges(ctx, running)\n",
		New:  "		n, err := w.restampPackageEdges(ctx, nil)\n",
		Why: "a running image that cannot be scanned lets its runs_package edges age out, and every CVE on " +
			"its packages is resolved resource_gone while it still runs",
	},
	{
		Guard: "TestOpen_DefaultTransportBlocksPrivateRegistries", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/registry.go",
		Old:  "		transport = safenet.NewGuardedTransport(registryDialTimeout, nil)\n",
		New:  "		transport, _ = remote.DefaultTransport, safenet.NewGuardedTransport\n",
		Why:  "registry pulls of connector-supplied image refs dial private and metadata addresses (SSRF)",
	},
	{
		Guard: "TestRegistryKeychain_DockerConfigIsOptIn", Pkg: "./cmd/graph",
		File: "cmd/graph/worker_deps.go",
		Old:  "	if strings.EqualFold(strings.TrimSpace(getenv(\"IMAGE_REGISTRY_DOCKER_KEYCHAIN\")), \"true\") {\n",
		New:  "	if getenv != nil {\n",
		Why:  "the pod's ambient docker credentials are presented to whatever registry an image ref names",
	},
	{
		Guard: "TestNewGuardedTransport_AllowListAndRedirects", Pkg: "./pkg/safenet",
		File: "pkg/safenet/http.go",
		Old:  "		if p.Contains(addr) {\n",
		New:  "		if p.IsValid() {\n",
		Why:  "any allow-list entry opens every private address, the metadata endpoint included",
	},
	{
		Guard: "TestSSRFDialer_MetadataAddressesIgnoreTheAllowList", Pkg: "./pkg/safenet",
		File: "pkg/safenet/http.go",
		Old:  "\t\tif _, metadata := metadataAddrs[addr.Unmap()]; metadata {\n",
		New:  "\t\tif _, metadata := metadataAddrs[addr.Unmap()]; metadata && d.allow == nil {\n",
		Why:  "allowing fd00::/8 or 100.64.0.0/10 for a registry opens AWS IPv6 IMDS or Alibaba's metadata service",
	},
	{
		Guard: "TestSSRFDialer_MetadataAddressesIgnoreTheAllowList", Pkg: "./pkg/safenet",
		File: "pkg/safenet/http.go",
		Old:  "\tnetip.MustParseAddr(\"168.63.129.16\"):   {}, // Azure WireServer (public address space)\n",
		New:  "",
		Why: "the Azure WireServer address, which sits in public address space and hands out VM extension secrets, " +
			"is dialable because no private-range rule catches it",
	},

	{
		Guard: "TestScanImage_ChainguardStaticUsrmergedApkDatabase", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/pkginventory/langpackages.go",
		Old:  "	case apkInstalledPath, usrApkInstalledPath:\n",
		New:  "	case apkInstalledPath:\n",
		Why: "a usrmerged Wolfi/Chainguard image's apk database (usr/lib/apk/db/installed) is never streamed, " +
			"so it reads zero packages and a permanent package_db_unread",
	},
	{
		Guard: "TestReadManifests_RetentionCapsAreAGap", Pkg: "./internal/scanner/imagevuln",
		File: "internal/scanner/imagevuln/layerwalk.go",
		Old:  "		w.skipOversized(clean, hdr.Size, languageKind(kind))\n		return nil\n",
		New:  "		w.skipOversized(clean, hdr.Size, languageKind(kind))\n		return errStreamBudget\n",
		Why:  "one oversized lockfile stops the walk and loses the base layer with its OS package database",
	},
	{
		Guard: "TestImageVulnWorker_IncompleteScanKeepsLastKnownPackagesLive", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln.go",
		Old:  "	unscanned := append(partial, plan.backedOff...)\n",
		New:  "	unscanned := append(partial[:0], plan.backedOff...)\n",
		Why: "after a partial walk the base layer's packages exist only as an earlier scan's edges, which age " +
			"out and resolve its CVEs resource_gone",
	},
	{
		Guard: "TestImageVulnWorker_AllBackedOffStillKeepsPackagesLive", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln.go",
		Old:  "		w.coverUnscanned(ctx, nil, plan.backedOff)\n",
		New:  "		w.coverUnscanned(ctx, nil, nil)\n",
		Why:  "a sweep with every digest backing off keeps no running image's packages live",
	},
	{
		Guard: "TestImageVulnWorker_DeadlineUnreachedTargetsKeepPackagesLive", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln.go",
		Old:  "plan.overCap...), targets[dispatched:]...)\n",
		New:  "plan.overCap...), targets[len(targets):]...)\n",
		Why:  "images the sweep's deadline stopped it reaching let their package edges age out",
	},
	{
		Guard: "TestImageVulnWorker_NoManifestsHasItsOwnWording", Pkg: "./internal/jobs",
		File: "internal/jobs/imagevuln.go",
		Old:  "				noManifests: errors.Is(err, imagevuln.ErrNoManifests),\n",
		New:  "				noManifests: false && errors.Is(err, imagevuln.ErrNoManifests),\n",
		Why:  "a busybox or pause image is told to grant pull access it already has",
	},
	// ── control plane (executor, govern, MCP, LLM budget, chat) ────────
	{
		Guard: "TestExecutorREST_APIKeyNeedsADifferentAdminsGrant", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service.go",
		Old:  "\tneedsGrant := destructive || req.RequireGrant || viaAPIKey(ctx)\n",
		New:  "\tneedsGrant := destructive || req.RequireGrant\n",
		Why:  "an admin API key, which an agent may hold, changes cloud state over REST with no second admin's grant while MCP requires one",
	},
	{
		Guard: "TestExecutorREST_APIKeyNeedsADifferentAdminsGrant", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service.go",
		Old:  "\tif viaAPIKey(ctx) {\n\t\treturn Approval{}",
		New:  "\tif false && viaAPIKey(ctx) {\n\t\treturn Approval{}",
		Why:  "an API key mints grants, so an agent holding two admins' keys approves its own execution with no person involved",
	},
	{
		Guard: "TestRunDecision_APIKeyNeedsADifferentAdminsRequest", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service_decision.go",
		Old:  "\tif viaAPIKey(ctx) {\n\t\treturn DecisionRun{}, ExecutionResult{}, s.refuseDecision(ctx, \"run_decision\"",
		New:  "\tif false && viaAPIKey(ctx) {\n\t\treturn DecisionRun{}, ExecutionResult{}, s.refuseDecision(ctx, \"run_decision\"",
		Why:  "an API key's ungranted decision run is claimed and marked failed instead of refused up front",
	},
	{
		Guard: "TestRunDecisionREST_APIKey_403", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service_decision.go",
		Old:  "\tif viaAPIKey(ctx) {\n\t\treturn DecisionRun{}, s.refuseDecision(ctx, \"request_decision_approval\"",
		New:  "\tif false && viaAPIKey(ctx) {\n\t\treturn DecisionRun{}, s.refuseDecision(ctx, \"request_decision_approval\"",
		Why:  "an API key reaches the decision checks and gets a 400 instead of the up-front 403 on a grant request",
	},
	{
		Guard: "TestResolve_APIKey_403", Pkg: "./internal/app/govern",
		File: "internal/app/govern/handler.go",
		Old:  "if _, viaKey := auth.APIKeyFromContext(r.Context()); viaKey {",
		New:  "if _, viaKey := auth.APIKeyFromContext(r.Context()); false && viaKey {",
		Why:  "an admin API key resolves queue verdicts without a signed-in approver",
	},
	{
		Guard: "TestUserAdminHandlers_APIKey_403", Pkg: "./internal/app/auth",
		File: "internal/app/auth/users_handler.go",
		Old:  "\tif _, viaKey := APIKeyFromContext(r.Context()); !viaKey {\n",
		New:  "\tif _, viaKey := APIKeyFromContext(r.Context()); true || !viaKey {\n",
		Why:  "a leaked admin key creates or promotes an account of its own and keeps access after the key is revoked",
	},
	{
		Guard: "TestExecute_RefusesYoungExecutorAccounts", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service.go",
		Old:  "\tif err := s.checkAccountAge(executor, \"executing\"); err != nil {\n",
		New:  "\tif err := s.checkAccountAge(executor, \"executing\"); false && err != nil {\n",
		Why:  "the age floor on the approver only: one admin with an old account approves and a second admin account they created a minute ago executes, satisfying the two-person rule alone",
	},
	{
		Guard: "TestPlan_RejectsMalformedRegionOnEveryAWSAction", Pkg: "./internal/app/executor",
		File: "internal/app/executor/plan.go",
		Old:  "\tif !validAWSRegion(p[ParamRegion]) {\n",
		New:  "\tif false && !validAWSRegion(p[ParamRegion]) {\n",
		Why:  "a region from finding data reaches the SDK endpoint the execution role signs requests to, and the copyable CLI line",
	},
	{
		Guard: "TestMarkStalledRunFailed", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service_stalled.go",
		Old:  "\tif evidence != evidenceNoIntent && !verified {\n",
		New:  "\tif false && evidence != evidenceNoIntent && !verified {\n",
		Why:  "releasing a stalled run whose intent row has no result without the admin attesting they checked the cloud invites a second run of a mutation that may already have happened",
	},
	{
		Guard: "TestApprovalWebhook_IsSignedOverTimestampAndBody", Pkg: "./internal/app/govern",
		File: "internal/app/govern/notifier.go",
		Old:  "\tif n.secret != \"\" {\n\t\twebhooksig.SetHeaders(",
		New:  "\tif false && n.secret != \"\" {\n\t\twebhooksig.SetHeaders(",
		Why:  "an unsigned approval handoff lets anyone who can reach the receiver forge a human approval",
	},
	{
		Guard: "TestResolveByLink_ApprovesOnlyNonDestructiveClasses", Pkg: "./internal/app/govern",
		File: "internal/app/govern/emaillink.go",
		Old:  "\tstring(respond.ClassModify):    true,\n",
		New:  "\tstring(respond.ClassModify):    true,\n\tstring(respond.ClassIsolate):   true,\n",
		Why:  "a 48-hour mailbox bearer link approving an isolate plan: a forwarded email takes a resource offline",
	},
	{
		Guard: "TestResolveOne", Pkg: "./internal/app/alertctx",
		File: "internal/app/alertctx/resolve_one.go",
		Old:  "\tcase len(r.Matches) > 1 || r.MoreMatches:\n",
		New:  "\tcase false:\n",
		Why:  "picking the first of several matching assets lets a resource anyone can name stand in for the real one in investigate_resource",
	},
	{
		Guard: "TestClient_ConcurrentCallsCannotOvershootTheBudget", Pkg: "./internal/app/llmusage",
		File: "internal/app/llmusage/reserve.go",
		Old:  "\ts.hold(r, 1)\n",
		New:  "",
		Why:  "a check that reserves nothing lets N concurrent calls all pass on one 'under budget' reading",
	},
	{
		Guard: "TestGraphQuery_IsLimitedPerUser", Pkg: "./internal/app/mcp",
		File: "internal/app/mcp/mcp.go",
		Old:  "\t\tlimit:       limitLLM,\n",
		New:  "",
		Why:  "an unlimited LLM-backed MCP tool lets any viewer drain the interactive budget that also halts background work",
	},
	{
		Guard: "TestAlertContext_IsLimitedPerUser", Pkg: "./internal/app/mcp",
		File: "internal/app/mcp/tools_alert.go",
		Old:  "\t\tlimit: limitAlertContext,\n",
		New:  "",
		Why:  "get_alert_context runs an unindexed attribute scan over assets; unlimited, one caller can saturate ClickHouse",
	},
	{
		Guard: "TestCoVe_Check8_ObserveFloor", Pkg: "./internal/app/respond",
		File: "internal/app/respond/cove.go",
		Old:  "\tif plan.ActionClass == ClassObserve {\n",
		New:  "\tif false && plan.ActionClass == ClassObserve {\n",
		Why:  "an injected 'observe' on a page-band or must_fix finding removes it from every human queue",
	},
	{
		Guard: "TestStream_StopsAtTheTokenBudget", Pkg: "./internal/app/chat",
		File: "internal/app/chat/limits.go",
		Old:  "\t\tMaxTokens:     l.MaxTokens,\n",
		New:  "",
		Why:  "a chat turn with no token cap resends a growing conversation every iteration with no bound on spend",
	},
	{
		Guard: "TestReserve_HungLedgerReadTimesOut", Pkg: "./internal/app/llmusage",
		File: "internal/app/llmusage/reserve.go",
		Old:  "\treadCtx, cancel := context.WithTimeout(ctx, s.readTimeout)\n\tdefer cancel()\n\tspend, err := s.repo.SpendSince(",
		New:  "\treadCtx, cancel := context.WithCancel(ctx)\n\tdefer cancel()\n\tspend, err := s.repo.SpendSince(",
		Why:  "a ledger read with no deadline, held under the gate every LLM call waits on: one hung Postgres read stalls the whole process",
	},
	{
		Guard: "TestClient_PanicSettlesTheReservation", Pkg: "./internal/app/llmusage",
		File: "internal/app/llmusage/service.go",
		Old:  "\tdefer func() { m.settle(ctx, r, req, resp, err, recover()) }()\n\treturn m.next.Complete(",
		New:  "\tdefer func() { m.settle(ctx, r, req, resp, err, nil) }()\n\treturn m.next.Complete(",
		Why:  "a panicking provider call is recorded as a success at no failure, hiding it from the ledger",
	},
	{
		Guard: "TestDecide_PatternDenied_UrgentFindingEscalates", Pkg: "./internal/app/respond",
		File: "internal/app/respond/service.go",
		Old:  "\t\t\tif UrgentEvidence(f) == \"\" {\n",
		New:  "\t\t\tif true {\n",
		Why:  "an injection steers an urgent finding onto a once-denied pattern and it is suppressed for 90 days, reaching no queue",
	},
	{
		Guard: "TestApplyPolicyRules_DisabledKeepsUrgentItems", Pkg: "./internal/app/govern",
		File: "internal/app/govern/service.go",
		Old:  "\t\t\tif !it.Urgent {\n",
		New:  "\t\t\tif true {\n",
		Why:  "a guidance-only class rule hides an urgent cluster (an escalated observe plan on a page-band finding) from the queue",
	},
	{
		Guard: "TestDecisionNotifiable", Pkg: "./internal/app/respond",
		File: "internal/app/respond/domain.go",
		Old:  "\treturn d.Plan.ActionClass != ClassObserve || d.Outcome.AwaitingHuman()\n",
		New:  "\treturn d.Plan.ActionClass != ClassObserve\n",
		Why:  "an observe plan CoVe escalated for an urgent finding never reaches the decision webhook or Slack",
	},
	{
		Guard: "TestMarkStalledRunFailed_DryRunsCannotHideTheIntent", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service_stalled.go",
		Old:  "\tif len(events) >= DecisionRunEventsLimit {\n",
		New:  "\tif false {\n",
		Why:  "a full page of the trail is read as complete, so a cut-off intent row reads as no_intent and the verification gate is skipped",
	},
	{
		Guard: "TestInvestigateResource_SharesTheAlertContextLimit", Pkg: "./internal/app/mcp",
		File: "internal/app/mcp/tools_investigate.go",
		Old:  "\t\t// get_alert_context.\n\t\tlimit: limitAlertContext,\n",
		New:  "\t\t// get_alert_context.\n",
		Why:  "investigate_resource runs the unindexed attribute scan with no per-user limit",
	},
	{
		Guard: "TestChatStream_OversizedPageContextIs400", Pkg: "./internal/app/chat",
		File: "internal/app/chat/service.go",
		Old:  "\tif len(pageContext) > s.limits.MaxContextBytes {\n",
		New:  "\tif false {\n",
		Why:  "the page context bypasses every history cap and reaches the model at any size",
	},
	{
		Guard: "TestExecute_CloudCallHasItsOwnTimeout", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service.go",
		Old:  "\trunCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.execTimeout)\n",
		New:  "\trunCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))\n",
		Why:  "a cloud call with no timeout of its own can outlive the stall window, so a release races a call still in flight",
	},
	{
		Guard: "TestRunDecision_CutOffCallNeedsVerificationBeforeRetry", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service.go",
		Old:  "\t\tif runCtx.Err() != nil {\n",
		New:  "\t\tif false && runCtx.Err() != nil {\n",
		Why:  "a call cut off after its intent row reads as a plain failure, so a click retries a mutation that may have landed",
	},
	{
		Guard: "TestResolveByLink_CannotDenyAnUrgentFinding", Pkg: "./internal/app/govern",
		File: "internal/app/govern/emaillink.go",
		Old:  "\tif c.Verdict == VerdictDenied {\n",
		New:  "\tif false && c.Verdict == VerdictDenied {\n",
		Why:  "a forwarded deny link takes an urgent finding out of the queue until its context changes",
	},
	{
		Guard: "TestVerify", Pkg: "./pkg/webhooksig",
		File: "pkg/webhooksig/webhooksig.go",
		Old:  "\tif secret == \"\" {\n",
		New:  "\tif false && secret == \"\" {\n",
		Why:  "a receiver missing its secret accepts any request signed with the empty key",
	},
	{
		Guard: "TestRunDecision_StateIsWrittenAfterTheRequestDeadline", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service_decision.go",
		Old:  "\twctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runStateWriteTimeout)\n",
		New:  "\twctx, cancel := context.WithTimeout(ctx, runStateWriteTimeout)\n",
		Why:  "the run's state is written on the request context: once the HTTP deadline passes the write fails and a finished run stays running",
	},
	{
		Guard: "TestExecute_CloudCallHasItsOwnTimeout", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service.go",
		Old:  "\trunCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.execTimeout)\n",
		New:  "\trunCtx, cancel := context.WithTimeout(ctx, s.execTimeout)\n",
		Why:  "a client disconnect or the request deadline cuts a cloud mutation off mid-flight",
	},
	{
		Guard: "TestExecute_CallCutOffAfterIntentIsOutcomeUnknown", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service.go",
		Old:  "\t\taction = AuditActionExecuteOutcomeUnknown\n",
		New:  "\t\taction = AuditActionExecuteFailed\n",
		Why:  "a cut-off call is audited as failed, indistinguishable from one that changed nothing",
	},
	{
		Guard: "TestRequestDecisionApproval_RefusesWhileOutcomeUnknown", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service_decision.go",
		Old:  "r.Status == RunRunning || r.Status == RunOutcomeUnknown ||",
		New:  "r.Status == RunRunning ||",
		Why:  "a grant is minted for a decision whose last run may have landed and cannot be retried",
	},
	{
		Guard: "TestMarkStalledRunFailed_OutcomeUnknownAlwaysNeedsVerification", Pkg: "./internal/app/executor",
		File: "internal/app/executor/service_stalled.go",
		Old:  "\t\t// shows, only the admin's check settles what happened.\n\t\tevidence = evidenceIntentWithoutResult\n",
		New:  "\t\t// shows, only the admin's check settles what happened.\n",
		Why:  "an outcome-unknown run whose trail reads as no intent is released without the admin's check",
	},
	{
		Guard: "TestResolveByLink_CannotDenyAnUrgentFinding", Pkg: "./internal/app/govern",
		File: "internal/app/govern/emaillink.go",
		Old:  "\tif f.ScoreBand == \"\" {\n",
		New:  "\tif false && f.ScoreBand == \"\" {\n",
		Why:  "an unscored finding reads as not urgent, so a deny link takes it out of the queue",
	},
	{
		Guard: "TestExecuteAction_OutcomeUnknownIsExplicit", Pkg: "./internal/app/mcp",
		File: "internal/app/mcp/mcp.go",
		Old:  "\tif errors.Is(err, executor.ErrOutcomeUnknown) {\n",
		New:  "\tif false && errors.Is(err, executor.ErrOutcomeUnknown) {\n",
		Why:  "an agent sees a cut-off execution as a generic failure and may retry a mutation that landed",
	},
	// ── authentication ──────────────────────────────────────────────────
	{
		Guard: "TestOAuth2Proxy_HeaderWithoutSharedSecretIsRefused", Pkg: "./internal/app/auth",
		File: "internal/app/auth/proxyauth.go",
		Old:  "	if h.oauth2ProxySecretSet && !h.oauth2ProxySecretValid(r) {\n",
		New:  "	if false && !h.oauth2ProxySecretValid(r) {\n",
		Why: "X-Auth-Request-Email is accepted from any caller again, so anything that reaches the pod " +
			"signs in as an existing admin by naming their address",
	},
	{
		Guard: "TestNewAuthHandler_RefusesForgeableConfig", Pkg: "./cmd/graph",
		File: "cmd/graph/serve_auth.go",
		Old:  "		case secret == \"\" && issuer == \"\":\n",
		New:  "		case false:\n",
		Why:  "serve starts with OAUTH2_PROXY=true and no way to verify the proxy, leaving the header path forgeable",
	},
	{
		Guard: "TestRolePolicyProvision", Pkg: "./internal/app/auth",
		File: "internal/app/auth/domain.go",
		Old:  "	return Provisioning{Role: RoleViewer, BootstrapAdmin: domainAllowlisted && len(p.AdminEmails) == 0 && !p.HasGroupMapping()}\n",
		New:  "	if domainAllowlisted {\n\t\treturn Provisioning{Role: RoleAdmin}\n\t}\n\treturn Provisioning{Role: RoleViewer}\n",
		Why:  "every first SSO sign-in from an allowlisted domain is provisioned as admin again",
	},
	{
		Guard: "TestRolePolicyProvision", Pkg: "./internal/app/auth",
		File: "internal/app/auth/domain.go",
		Old:  "domainAllowlisted && len(p.AdminEmails) == 0 && !p.HasGroupMapping()}",
		New:  "domainAllowlisted && len(p.AdminEmails) == 0}",
		Why:  "with an admin group mapped, the first allowlisted non-member of an empty install still becomes admin",
	},
	{
		Guard: "TestIDTokenVerifier", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "		jwt.WithAudience(v.audience),\n",
		New:  "",
		Why:  "an ID token the IdP issued to any other client passes as a sign-in to this one",
	},
	{
		Guard: "TestOAuth2Proxy_IDTokenMode", Pkg: "./internal/app/auth",
		File: "internal/app/auth/proxyauth.go",
		Old:  "	if h.oauth2ProxyIDToken.configured() {\n\t\tsession, hasSession := h.cookieSession(r)",
		New:  "	if false {\n\t\tsession, hasSession := h.cookieSession(r)",
		Why:  "with ID-token verification configured, X-Auth-Request-Email plus a leaked shared secret signs in as anyone",
	},
	{
		Guard: "TestIDTokenVerifier_TrailingSlashIssuer", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "		issuer:          issuer,\n",
		New:  "		issuer:          strings.TrimSuffix(issuer, \"/\"),\n",
		Why:  "an IdP issuing with a trailing slash (Auth0) fails every sign-in: iss is compared exactly",
	},
	{
		Guard: "TestIDTokenVerifier", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "	verified := claims.EmailVerified != nil && bool(*claims.EmailVerified)\n",
		New:  "	verified := claims.EmailVerified == nil || bool(*claims.EmailVerified)\n",
		Why: "a token with no email_verified binds an existing unbound account by an email the IdP " +
			"never verified (Azure \"nOAuth\")",
	},
	{
		Guard: "TestIDTokenVerifier", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "	if (len(claims.Audience) > 1 || claims.AZP != \"\") && claims.AZP != v.audience {\n",
		New:  "	if false {\n",
		Why:  "a token issued to another client that merely lists this one as an audience is accepted",
	},
	{
		Guard: "TestValidateOIDCIssuer", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "	return fmt.Errorf(\"ValidateOIDCIssuer: %q must use https\", issuer)\n",
		New:  "	return nil\n",
		Why:  "signing keys are fetched over plain http, so anyone on the path can swap them",
	},
	{
		Guard: "TestIDTokenVerifier_RefetchIsRateLimited", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "	v.attempted = time.Now()\n",
		New:  "",
		Why:  "every token with an unknown kid triggers a discovery and JWKS fetch against the IdP",
	},
	{
		Guard: "TestIDTokenVerifier_FetchSurvivesRequestCancellation", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "context.WithTimeout(context.WithoutCancel(ctx), idTokenFetchTimeout)",
		New:  "context.WithTimeout(ctx, idTokenFetchTimeout)",
		Why:  "a client hanging up during the cold-start key fetch fails every sign-in until the refetch gap passes",
	},
	{
		Guard: "TestOAuth2Proxy_IDTokenAndSession", Pkg: "./internal/app/auth",
		File: "internal/app/auth/proxyauth.go",
		Old:  "		case hasSession:\n",
		New:  "		case false:\n",
		Why:  "a second person's proxy sign-in in the same browser leaves the first person's session alive",
	},
	{
		Guard: "TestOAuth2Proxy_GroupsHeaderNeedsExplicitTrust", Pkg: "./internal/app/auth",
		File: "internal/app/auth/proxyauth.go",
		Old:  "		if h.oauth2ProxyTrustGroups {\n",
		New:  "		if true {\n",
		Why:  "a client-supplied X-Auth-Request-Groups naming an admin group self-grants admin on first sign-in",
	},
	{
		Guard: "TestIAP_RejectsWrongIssuerAndMissingSubject", Pkg: "./internal/app/auth",
		File: "internal/app/auth/iap.go",
		Old:  "		jwt.WithIssuer(iapIssuer),\n",
		New:  "",
		Why:  "an ES256 token with the right audience but another issuer passes as an IAP assertion",
	},
	{
		Guard: "TestIAP_BindsIdentity", Pkg: "./internal/app/auth",
		File: "internal/app/auth/proxyauth.go",
		Old:  "	token, matched, err := h.svc.LoginOIDC(ctx, id, h.roles.Provision(id.Email, nil, allowlisted))\n",
		New:  "	token, matched, err := h.svc.LoginOAuth(ctx, id.Email, h.roles.Provision(id.Email, nil, allowlisted))\n",
		Why:  "IAP signs in by email alone, so a recycled address or another subject asserting it takes the account",
	},
	{
		Guard: "TestClientIP_HeaderOnlyFromTrustedProxies", Pkg: "./internal/app/auth",
		File: "internal/app/auth/ratelimit.go",
		Old:  "	if header == \"\" || !peerTrusted(peer, trusted) {\n",
		New:  "	if header == \"\" {\n",
		Why: "CLIENT_IP_HEADER is honoured from any peer, so a caller reaching serve directly picks the address " +
			"keying its login rate limit and the executor's same-address flag",
	},
	{
		Guard: "TestAPIKeyWrites_RefusedForAPIKeyPrincipal_403", Pkg: "./internal/app/apikey",
		File: "internal/app/apikey/handler.go",
		Old:  "	if _, viaKey := auth.APIKeyFromContext(r.Context()); viaKey {\n",
		New:  "	if _, viaKey := auth.APIKeyFromContext(r.Context()); viaKey && false {\n",
		Why:  "a leaked read-scoped key mints successor keys and deletes its owner's admin keys",
	},
	{
		Guard: "TestMatchKeyComparesDigestsInConstantTime", Pkg: "./internal/app/apikey",
		File: "internal/app/apikey/repo.go",
		Old:  "	if subtle.ConstantTimeCompare([]byte(hashKey(plaintext)), []byte(c.hash)) != 1 {\n",
		New:  "	if subtle.ConstantTimeCompare(nil, nil) != 1 || hashKey(plaintext) != c.hash {\n",
		Why: "the API-key digest is compared with !=, which every behavioural test accepts while response timing " +
			"leaks how much of a guessed digest is right",
	},
	{
		Guard: "TestDecisionWebhookNotifier", Pkg: "./cmd/graph",
		File: "cmd/graph/alert_adapters.go",
		Old:  "		if getenv(\"DECISION_WEBHOOK_ALLOW_UNSIGNED\") != \"true\" {\n",
		New:  "		if false {\n",
		Why:  "decision webhooks are sent unsigned again, indistinguishable from forgeries to the receiver",
	},

	// ── aws_org onboarding (ADR 091) ────────────────────────────────────
	{
		Guard: "TestReconcileOrg_DiscoveryFailureKeepsChildren", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_org.go",
		Old:  "\t\ts.recordOrgSync(ctx, orgID, err, false)\n\t\treturn ReconcileResult{}, fmt.Errorf(\"ReconcileOrg: discovery: %w\", err)\n",
		New:  "\t\ts.recordOrgSync(ctx, orgID, err, false)\n\t\tdiscovered = nil\n",
		Why: "a failed organization listing reads as \"every account left\": every child is disabled " +
			"because discovery could not list, not because any account changed",
	},
	{
		Guard: "TestReconcileOrg_DiscoveryFailureKeepsChildren", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_org.go",
		Old:  "\tif err == nil && len(discovered) == 0 {\n\t\terr = ErrEmptyDiscovery\n\t}\n",
		New:  "\n",
		Why:  "a listing that succeeds with zero accounts is degraded input, and taking it at face value disables every child",
	},
	{
		Guard: "TestReconcileOrg_ChildrenNeverStoreCopiedKeys", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_org.go",
		Old:  "\t\t\"aws_account_id\":       accountID,\n\t}\n",
		New:  "\t\t\"aws_account_id\":       accountID,\n\t\t\"aws_access_key_id\":    org.Config[\"aws_access_key_id\"],\n\t}\n",
		Why:  "the hub key is copied into every child connector — N copies of one secret, the bootstrap shape ADR 091 replaced",
	},
	{
		Guard: "TestCheckChildConfig_RejectsEverySecretKey", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_org.go",
		Old:  "\t\tif cfg[k] != \"\" {\n\t\t\treturn fmt.Errorf(\"%w: %s\", ErrChildStoresSecret, k)\n",
		New:  "\t\tif false {\n\t\t\treturn fmt.Errorf(\"%w: %s\", ErrChildStoresSecret, k)\n",
		Why:  "the write-side guard is gone, so a future child-config change can persist a key or the ExternalId unnoticed",
	},
	{
		Guard: "TestGet_OrgChildWithMissingOrgFails", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_org.go",
		Old:  "\tif errors.Is(err, ErrNotFound) {\n\t\treturn nil, fmt.Errorf(\"resolveChild: %w\", ErrOrgParentMissing)\n",
		New:  "\tif errors.Is(err, ErrNotFound) {\n\t\treturn child, nil\n",
		Why:  "an orphaned child falls back to whatever ambient identity the pod has instead of failing",
	},
	{
		Guard: "TestReconcileOrg_LifecycleDisablesAndReenables", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_org.go",
		Old:  "\t\treturn OrgAccountSuspended, \"suspended by AWS; its child connector is disabled and its data kept\", childDisable\n",
		New:  "\t\treturn OrgAccountSuspended, \"suspended by AWS; its child connector is disabled and its data kept\", childKeep\n",
		Why:  "a suspended account's connector keeps syncing (and failing) forever",
	},
	{
		Guard: "TestReadOnlyRoleGrantsOnlyReads", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-readonly-role.yaml",
		Old:  "                  - identitystore:DescribeGroup\n",
		New:  "                  - identitystore:DescribeGroup\n                  - identitystore:DeleteUser\n",
		Why:  "a write slips into the member role every account trusts",
	},
	{
		Guard: "TestHubPodIdentityTrustIsPinnedToGraphsServiceAccount", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-hub-role.yaml",
		Old:  "                  aws:RequestTag/kubernetes-namespace: !Ref PodNamespace\n",
		New:  "",
		Why:  "a pod identity association in any namespace of the account obtains the hub",
	},
	{
		Guard: "TestHubTrustsServeServiceAccountWithoutExecutionRole", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-hub-role.yaml",
		Old:  "                    - ServeTrusted\n",
		New:  "                    - ExecutorPinned\n",
		Why:  "with serviceAccount.serveName set and no execution role, the hub refuses serve, which loses its cloud identity",
	},
	{
		Guard: "TestHubExecutionPathIsItsOwnStatement", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-hub-role.yaml",
		Old:  "                Resource: !Sub arn:${AWS::Partition}:iam::*:role/${MemberRoleName}\n",
		New:  "                Resource: !Sub arn:${AWS::Partition}:iam::*:role/${MemberRoleName},arn:${AWS::Partition}:iam::*:role/${ExecutionRoleName}\n",
		Why:  "the read statement grants the execution role too, so the ServiceAccount pin on the execution statement holds nothing",
	},
	{
		Guard: "TestS3GrantsAreHeldToTheOwnAccount", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-readonly-role.yaml",
		Old:  "                      s3:ResourceAccount: !Ref AWS::AccountId\n",
		New:  "                      aws:SourceAccount: !Ref AWS::AccountId\n",
		Why:  "the Terraform-state wildcard reaches state buckets in other accounts whose bucket policy admits the member role",
	},
	{
		Guard: "TestExecutionRoleSkipsProtectedResources", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-execution-role.yaml",
		Old:  "                  - iam:DeleteAccessKey\n                Resource: \"*\"\n",
		New:  "                Resource: \"*\"\n",
		Why:  "an approved fix can delete the access key of a user tagged vulngraph-protected, a break-glass user included",
	},
	{
		Guard: "TestScannerPodGetsNoAppSecretsOrCloudIdentity", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/deployment-scanner.yaml",
		Old:  "{{ include \"graph.podEnv\" (dict \"Values\" .Values \"scanner\" true) }}\n",
		New:  "{{ include \"graph.podEnv\" (dict \"Values\" .Values \"scanner\" true) }}\n{{ include \"graph.appSecretEnv\" . }}\n",
		Why:  "the pod that parses responses from scanned hosts holds GRAPH_SECRET_KEY, the LLM key and the signing secrets",
	},
	{
		Guard: "TestScannerPodGetsNoAppSecretsOrCloudIdentity", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/_helpers.tpl",
		Old:  "{{- $global := ternary list (.Values.extraEnvFrom | default list) (eq .component \"scanner\") -}}\n",
		New:  "{{- $global := .Values.extraEnvFrom | default list -}}\n",
		Why:  "a secretRef the operator adds chart-wide for serve and the worker (GRAPH_SECRET_KEY, an LLM key) reaches the scanner pod",
	},
	{
		Guard: "TestChartIsolatesDiskReadsWhenEnabled", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/values.yaml",
		Old:  "scanner:\n  enabled: true\n",
		New:  "scanner:\n  enabled: false\n",
		Why:  "disk reads run in the worker, the pod that holds GRAPH_SECRET_KEY and the cloud identity",
	},
	{
		Guard: "TestOnlyTheWorkerHoldsKubernetesAPIAccess", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/deployment-serve.yaml",
		Old:  "      automountServiceAccountToken: false\n",
		New:  "",
		Why:  "the internet-facing serve pod mounts the shared ServiceAccount's token, and with it the collector's cluster-wide list on pods and config maps",
	},
	{
		Guard: "TestChartImageHonoursDigest", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/deployment-worker.yaml",
		Old:  "image: {{ include \"graph.image\" . | quote }}",
		New:  "image: \"{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}\"",
		Why:  "with image.digest pinned, the worker still pulls by a tag that can be moved to another image",
	},
	{
		Guard: "TestChartDefaultImageTagIsPublished", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/Chart.yaml",
		Old:  "appVersion: \"0.1.0\"",
		New:  "appVersion: \"edge\"",
		Why:  "a plain helm install runs the rolling main-branch build: unversioned, no upgrade guarantees, and with pullPolicy IfNotPresent a different build on each node",
	},
	{
		Guard: "TestChartDatastoreDSNsDeclareTransport", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/secret.yaml",
		Old:  "@graph-postgres:5432/graph?sslmode=%s%s\" (.Values.secret.postgresPassword | urlquery) $sslMode $rootCert",
		New:  "@graph-postgres:5432/graph\" (.Values.secret.postgresPassword | urlquery)",
		Why:  "postgres.sslMode is dropped from the DSN, so a deploy set to require or verify-full silently connects with prefer, which falls back to plaintext",
	},
	{
		Guard: "TestDriftAnalysis_NeverEnqueuesScanKinds", Pkg: "./internal/app/driftanalysis",
		File: "internal/app/driftanalysis/service.go",
		Old:  "\"github.com/vulngraph/vulngraph/internal/llm\"",
		New:  "\"github.com/vulngraph/vulngraph/internal/llm\"\n\t_ \"github.com/vulngraph/vulngraph/internal/scanner/diskscan\"",
		Why:  "the advisory drift verdict package imports the disk scanner, so an LLM verdict can reach scan execution",
	},
	{
		Guard: "TestBundledDatastoreAppUsersAreNotAdmins", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/files/postgres-init.sql",
		Old:  "CREATE ROLE graph LOGIN NOSUPERUSER NOCREATEDB",
		New:  "CREATE ROLE graph LOGIN SUPERUSER NOCREATEDB",
		Why:  "the app role becomes a superuser, so a compromised pod runs programs on the database host with COPY ... TO PROGRAM",
	},
	{
		Guard: "TestClickHouseAppGrantsMatchTheCode", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/files/clickhouse-users.xml",
		Old:  "<query>GRANT SELECT, INSERT ON graph.*</query>",
		New:  "<query>GRANT ALL ON graph.*</query>",
		Why:  "the natural fix for a missing-privilege error hands the app user DDL and ALTER DELETE on audit_events, so a compromised pod can erase the audit trail",
	},
	{
		Guard: "TestClickHouseAppGrantsMatchTheCode", Pkg: "./cmd/graph",
		File: "internal/app/asset/purge.go",
		Old:  "const purgeAccountDelete = `ALTER TABLE assets DELETE WHERE provider = ? AND account_id = ?`",
		New:  "const purgeAccountDelete = `UPDATE assets SET last_seen = 0 WHERE provider = ? AND account_id = ?`",
		Why:  "a lightweight UPDATE needs ALTER UPDATE, which graph does not hold, so the connector purge fails on every install the first time someone runs it",
	},
	{
		Guard: "TestClickHouseUsersHaveNoAdmin", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/files/clickhouse-users.xml",
		Old:  "        <default remove=\"remove\"/>\n",
		New:  "",
		Why:  "the image's default user comes back: no password and access management, so anything that reaches the ClickHouse pod's loopback is a server admin",
	},
	{
		Guard: "TestScannerGrantsMatchWhatTheScannerRuns",
		Pkg:   "./internal/migrate",
		File:  "internal/db/sqlcgen/disk_scan_packages.sql.go",
		Old:   "SELECT disk_scan_mode FROM disk_scan_connector_modes WHERE connector_id = $1",
		New:   "SELECT disk_scan_mode, (SELECT count(*) FROM users) FROM disk_scan_connector_modes WHERE connector_id = $1",
		Why:   "The scanner must not query tables outside its restricted grants.",
	},
	{
		Guard: "TestClickHouseUsersHaveNoAdmin", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/files/clickhouse-users.xml",
		Old:  "        <graph_scanner>\n",
		New:  "        <ops>\n            <access_management>1</access_management>\n        </ops>\n        <graph_scanner>\n",
		Why:  "a user with no password and access management, beside the three the test checks: anything that reaches the ClickHouse pod can log in as it and grant itself every table",
	},
	{
		Guard: "TestScannerGrantsMatchWhatTheScannerRuns",
		Pkg:   "./internal/migrate",
		File:  "internal/db/sqlcgen/disk_scan_packages.sql.go",
		Old:   "SELECT disk_scan_mode FROM disk_scan_connector_modes WHERE connector_id = $1",
		New:   "SELECT disk_scan_mode, (SELECT count(*) FROM system.parts) FROM disk_scan_connector_modes WHERE connector_id = $1",
		Why:   "The scanner must not query tables outside its restricted grants.",
	},
	{
		Guard: "TestScannerGrantsMatchWhatTheScannerRuns",
		Pkg:   "./internal/migrate",
		File:  "internal/migrate/scanner.go",
		Old:   "\t\"GRANT SELECT ON disk_scan_connector_modes TO \" + ScannerRole,\n",
		New:   "",
		Why:   "The disk reader needs its connector-mode view, without access to connector credentials.",
	},
	{
		Guard: "TestChartNetworkPolicyIsLeastPrivilegeByDefault", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/values.yaml",
		Old:  "networkPolicy:\n  enabled: true\n",
		New:  "networkPolicy:\n  enabled: false\n",
		Why:  "a default install leaves Postgres, ClickHouse and the worker RPC reachable from every pod in the cluster",
	},
	{
		Guard: "TestChannelSecret_SealedUnderTheCanonicalID", Pkg: "./internal/app/notify",
		File: "internal/app/notify/repo.go",
		Old:  "\tif u, err := uuid.Parse(id); err == nil {\n\t\tid = u.String()\n\t}\n",
		New:  "",
		Why:  "a PUT addressed by an upper-case or braced id seals the secret to a spelling no read uses, so the channel silently stops alerting",
	},
	// ── check re-evaluation and CIEM stability ──────────────────────────
	{
		Guard: "TestRegistry_Fingerprint", Pkg: "./internal/checks",
		File: "internal/checks/checks.go",
		Old:  "\t\tentries[i] = c.ID + \"\\x01\" + c.logic\n",
		New:  "\t\tentries[i] = c.ID\n",
		Why: "the fingerprint hashes only check ids again, so editing a predicate never re-runs it on " +
			"unchanged assets and the edit stays dark on every stable connector",
	},
	{
		Guard: "TestRecheckTimeDependent", Pkg: "./internal/jobs",
		File: "internal/jobs/sync_recheck.go",
		Old:  "\t\tif s.checkIDs[f.CheckID] {\n",
		New:  "\t\tif true {\n",
		Why: "the daily end-of-life re-check reconciles every open finding on the assets it touched, " +
			"closing findings of checks that did not run as fixed",
	},
	{
		Guard: "TestAnalyzeIAM_SCPReadErrorRetainsCandidatesWithUnknownCoverage", Pkg: "./internal/jobs",
		File: "internal/jobs/sync_ciem.go",
		Old:  "\tpartial := err != nil\n",
		New:  "\tpartial := false\n",
		Why:  "a failed organization read loses its partial-sweep signal even though the observed policy coverage is incomplete",
	},
	{
		Guard: "TestSuppressionExpiryWorker_UndeliveredStaysDue", Pkg: "./internal/jobs",
		File: "internal/jobs/suppression_expiry.go",
		Old:  "\tif delivered == 0 {\n",
		New:  "\tif delivered < 0 {\n",
		Why:  "an expiry notice no channel delivered is marked sent, so the expiry is never announced",
	},
	{
		Guard: "TestRDSPublicExposureFiresOnce", Pkg: "./internal/checks",
		File: "internal/checks/cspm_extra.go",
		Old:  " && !rdsPublicSubnetIGWViolates(a)\n",
		New:  "\n",
		Why:  "a public RDS instance in an internet-gateway subnet raises two findings for one root cause",
	},
	{
		Guard: "TestOAuth2Proxy_IDTokenSessionComparesBinding", Pkg: "./internal/app/auth",
		File: "internal/app/auth/proxyauth.go",
		Old:  "			same, err := h.svc.IdentityBelongsTo(ctx, id, session.user.ID)\n",
		New:  "			same, err := session.user.Email == id.Email, error(nil)\n",
		Why:  "a token with the session user's email but another subject keeps that user's session",
	},
	{
		Guard: "TestOAuth2Proxy_IDTokenSessionComparesBinding", Pkg: "./internal/app/auth",
		File: "internal/app/auth/service.go",
		Old:  "	return creds.ID == userID, nil\n",
		New:  "	return creds.ID != \"\", nil\n",
		Why:  "any bound identity counts as the session's, so another person's proxy login keeps the old session",
	},
	{
		Guard: "TestOAuth2Proxy_IDTokenSessionStoreErrorKeepsSession", Pkg: "./internal/app/auth",
		File: "internal/app/auth/proxyauth.go",
		Old:  "			if err != nil {\n\t\t\t\t// Unknown is not",
		New:  "			if false {\n\t\t\t\t// Unknown is not",
		Why:  "a store error reads as a different person and signs every user out on a database blip",
	},
	{
		Guard: "TestIDTokenVerifier_NoKeysBackoff", Pkg: "./internal/app/auth",
		File: "internal/app/auth/idtoken.go",
		Old:  "	case recent:\n",
		New:  "	case false:\n",
		Why:  "while the IdP is down every sign-in attempt fires a discovery request at it",
	},
	{
		Guard: "TestPackageReadersGateOnLiveness", Pkg: "./internal/app/asset",
		File: "internal/app/asset/repo_packages.go",
		Old:  "\tSELECT id FROM assets\n\tWHERE id IN (` + livePackageIDs + `)\n",
		New:  "\tSELECT id FROM assets\n",
		Why: "package rows are never deleted, so an ungated packageCount counts every package any scan " +
			"ever wrote and the OSV staleness gauge's denominator stops matching the inventory the refresh scans",
	},
	{
		Guard: "TestScanLivePackages_ReadsLiveSetOnceAndWalksEveryPage", Pkg: "./internal/app/asset",
		File: "internal/app/asset/service.go",
		Old:  "\t\t\tif live[c.ID] {\n\t\t\t\tkept = append(kept, c)\n",
		New:  "\t\t\tif live[c.ID] || !live[c.ID] {\n\t\t\t\tkept = append(kept, c)\n",
		Why: "package rows are never deleted, so a pass that drops the live-set filter pages every package any scan " +
			"ever wrote and the advisory jobs keep raising findings on packages nothing runs anymore",
	},
	{
		Guard: "TestScanLivePackages_ReadsLiveSetOnceAndWalksEveryPage", Pkg: "./internal/app/asset",
		File: "internal/app/asset/service.go",
		Old:  "\t\tafter = next\n\t}\n}",
		New:  "\t\tafter = next\n\t\tif live, err = s.repo.LivePackageIDs(ctx); err != nil {\n\t\t\treturn PackageScan{}, err\n\t\t}\n\t}\n}",
		Why: "re-deriving liveness per page judges each page against a different now(), so a package whose edge " +
			"crosses the cutoff mid-pass shifts the walk; it also full-scans graph_edges once per page",
	},
	{
		Guard: "TestFetch_ChecksumMismatchFails", Pkg: "./internal/intel/updateinfo",
		File: "internal/intel/updateinfo/fetch.go",
		Old:  "	if hex.EncodeToString(h.Sum(nil)) != wantSum {\n",
		New:  "	if wantSum == \"-\" && hex.EncodeToString(h.Sum(nil)) != wantSum {\n",
		Why:  "a truncated or tampered updateinfo download parses as a short advisory list and resolves findings",
	},
	{
		Guard: "TestFetch_SHA1ChecksumIsVerified", Pkg: "./internal/intel/updateinfo",
		File: "internal/intel/updateinfo/fetch.go",
		Old:  "	if hex.EncodeToString(h.Sum(nil)) != wantSum {\n",
		New:  "	if wantSum == \"-\" && hex.EncodeToString(h.Sum(nil)) != wantSum {\n",
		Why:  "a sha1-checksummed updateinfo (Oracle Linux 7 and its UEK channels) is read unverified again",
	},
	{
		Guard: "TestOSVWorker_PackageLapsedDuringProducerOutageStaysOpen", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "		if !superseded(r) && !e.runnerGone(r.RunnerID) {\n",
		New:  "		if r.RunnerID == \"\" && false {\n",
		Why: "a lapsed edge proves a departure again: an SSM outage, an image stuck in scan backoff or an " +
			"expired credential resolves every CVE on hosts that still run the package as resource_gone",
	},
	{
		Guard: "TestVMVuln_CollectionOutageResolvesNothing", Pkg: "./internal/jobs",
		File: "internal/jobs/vmvuln.go",
		Old:  "			if assetGone(vm, deleted[vm.ID], now) {\n",
		New:  "			if assetGone(vm, deleted[vm.ID], now) || true {\n",
		Why: "a fleet whose account stopped being collected — or that a partial sweep missed — reads as " +
			"terminated: an expired connector credential closes every fleet finding in the account",
	},
	{
		Guard: "TestResolveFindingsForDeletedAssets_SkipsDerivedFindings", Pkg: "./internal/jobs",
		File: "internal/jobs/sync_lifecycle.go",
		Old:  "			if !f.Resolved() && !derivedFromGroup(f) {\n",
		New:  "			if !f.Resolved() {\n",
		Why: "terminating the instance a fleet finding sits on closes the whole fleet's finding, which the " +
			"next regroup reopens as a fresh alert",
	},
	{
		Guard: "TestQuery_PageCapReportsIncomplete", Pkg: "./internal/intel/osv",
		File: "internal/intel/osv/osv.go",
		Old:  "		for _, p := range pending {\n			partial[p] = true\n",
		New:  "		for _, p := range pending {\n			_ = p\n",
		Why: "an advisory list cut at the page cap reads as complete, and the reconcile resolves the unread " +
			"advisories' findings as fixed",
	},
	{
		Guard: "TestParseRepomd", Pkg: "./internal/intel/updateinfo",
		File: "internal/intel/updateinfo/fetch.go",
		Old:  "		if newHash(algo) == nil || sum == \"\" {\n",
		New:  "		if false {\n",
		Why: "an updateinfo whose repomd checksum cannot be verified is read anyway: a truncated or tampered " +
			"download parses into a short advisory list that reads as complete",
	},
	{
		Guard: "TestJudgeDepartures", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "	if !deletedAt.IsZero() && deletedAt.After(a.LastSeen) {\n",
		New:  "	if !deletedAt.IsZero() {\n",
		Why:  "a resource deleted once and seen again since still reads as deleted, and its packages' CVEs resolve while it runs them",
	},
	{
		Guard: "TestJudgeDepartures_SupersessionMarginBoundary", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "	return r.InventoryAt.Sub(r.EdgeAt) > departureMargin\n",
		New:  "	return r.InventoryAt.Sub(r.EdgeAt) > 0\n",
		Why:  "the stamp skew inside one producer write reads as a later read, so a package the same pass wrote reads as dropped",
	},
	{
		Guard: "TestJudgeDepartures", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "				if newer, ok := versionNewer(typ, version, v); ok && newer {\n",
		New:  "				if newer, ok := versionNewer(typ, version, v); v != version || (ok && newer) {\n",
		Why:  "any other version counts as an upgrade: a downgrade resolves a CVE as fixed",
	},
	{
		Guard: "TestJudgeDepartures_ReadErrorWithholdsOnlyThatPackage", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "		if err == nil {\n			add(rs)\n			continue\n		}\n",
		New:  "		if err == nil {\n			add(rs)\n			continue\n		}\n		for _, p := range purls {\n			ev.readErr[p] = true\n		}\n		break\n",
		Why:  "one package with too many runners to read stalls every departure in the estate, run after run",
	},
	{
		Guard: "TestResolveDepartures_AgedOutFallback", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "	return f.LastObservedAt.Year() > 2000 && now.Sub(f.LastObservedAt) > absenceFallback\n",
		New:  "	return false\n",
		Why:  "a package whose runner evidence aged out of the edge TTL is never judged again: its findings stay open forever",
	},
	{
		Guard: "TestResolveDepartures_UpgradeStillVulnerableIsNotFixed", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "			case stillOpen[f.CheckID+\"\\x00\"+f.ResourceID]:\n",
		New:  "			case stillOpen[f.CheckID+\"\\x00\"+f.ResourceID] && false:\n",
		Why:  "an upgrade to a version still carrying the CVE is recorded as its fix",
	},
	{
		Guard: "TestVMVuln_UpgradeMustBeNewerAndCured", Pkg: "./internal/jobs",
		File: "internal/jobs/vmvuln_reconcile.go",
		Old:  "			if !stillVulnerable[fleet+\"\\x00\"+f.CheckID] && upgradedTo(purl, purls) {\n",
		New:  "			if upgradedTo(purl, purls) {\n",
		Why:  "a fleet upgraded to a version still carrying the CVE has its fleet finding resolved as fixed",
	},
	{
		Guard: "TestResolveFindingsForDeletedAssets_SkipsDerivedFindings", Pkg: "./internal/jobs",
		File: "internal/jobs/sync_lifecycle.go",
		Old:  "		return f.Metadata[\"fleet_kind\"] != \"instance\"\n",
		New:  "		return true\n",
		Why:  "a hand-built host's fleet finding (the host IS the fleet) is never closed when the sync proves the host deleted",
	},
	{
		Guard: "TestBaseImageWorker_RetiredGroupUsesFullMembership", Pkg: "./internal/jobs",
		File: "internal/jobs/baseimage_reconcile.go",
		Old:  "	all := run.groupMembers[f.Metadata[\"base_group\"]]\n",
		New:  "	all := members\n",
		Why:  "a retired base is judged on the capped affected_image_ids list, so a surviving member past the cap is ignored",
	},
	{
		Guard: "TestMerge_KeepsStreamsApart", Pkg: "./internal/intel/updateinfo",
		File: "internal/intel/updateinfo/updateinfo.go",
		Old:  "			key := a.ID + \"\\x00\" + a.Stream\n",
		New:  "			key := a.ID\n",
		Why:  "one advisory id from two kernel lines merges into one, and one line's fix is held against the other's installs",
	},
	{
		Guard: "TestCompareDpkg", Pkg: "./internal/distro",
		File: "internal/distro/dpkgver.go",
		Old:  "	case c == '~':\n		return -1\n",
		New:  "	case c == '~':\n		return 1\n",
		Why:  "a ~ backport build sorts after its release, so a Debian downgrade reads as an upgrade and is recorded as a fix",
	},
	{
		Guard: "TestVMVuln_UnlistedFleetAgesOut", Pkg: "./internal/jobs",
		File: "internal/jobs/vmvuln_reconcile.go",
		Old:  "			if run.goneFleets[fleet] || (!run.listedFleets[fleet] && agedOut(f, now)) {\n",
		New:  "			if run.goneFleets[fleet] || (!run.listedFleets[fleet] && agedOut(f, now) && false) {\n",
		Why:  "a fleet finding whose key no VM maps to any more is never judged again and stays open forever",
	},
	{
		Guard: "TestResolveDepartures_UnreadTargetWithholdsFixed", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "			case !allRead(v.targets, targetRead):\n",
		New:  "			case !allRead(v.targets, targetRead) && false:\n",
		Why:  "an upgrade onto a version whose advisories were never read is recorded as the fix",
	},
	{
		Guard: "TestApplyDeletions_RecordFirstAndStopOnFailure", Pkg: "./internal/jobs",
		File: "internal/jobs/sync_lifecycle.go",
		Old:  "			Msg(\"sync: deletion record failed — hashes kept, the next complete sweep re-decides\")\n\t\treturn\n",
		New:  "			Msg(\"sync: deletion record failed — hashes kept, the next complete sweep re-decides\")\n",
		Why:  "hashes are dropped without the deletion record, so the proof is lost for good and derived findings wait out the fallback",
	},
	{
		Guard: "TestJudgeDepartures_BatchesAndListsLineageOnce", Pkg: "./internal/jobs",
		File: "internal/jobs/package_departure.go",
		Old:  "\t\tjudgeBatch(ctx, d, lineages, ",
		New:  "\t\tlineages = &lineageIndex{store: d.assets, now: now}\n\t\tjudgeBatch(ctx, d, lineages, ",
		Why:  "every batch re-reads the full fleet and image listings, multiplying a fleet-wide change's ClickHouse load",
	},
	// ── Kubernetes control plane and node posture (ADR 094) ─────────────
	{
		Guard: "TestControlPlaneSignals_DefaultKubeadm", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/controlplane.go",
		Old:  "r.boolean(\"anonymous_auth\", \"anonymous-auth\", true)",
		New:  "r.boolean(\"anonymous_auth\", \"anonymous-auth\", false)",
		Why:  "an absent --anonymous-auth reads as off, so every kubeadm API server that serves anonymous requests by default passes 1.2.1",
	},
	{
		Guard: "TestControlPlaneSignals_Unknown", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/controlplane.go",
		Old:  "if _, mirror := pod.Annotations[mirrorPodAnnotation]; !mirror {",
		New:  "if _, mirror := pod.Annotations[mirrorPodAnnotation]; !mirror && false {",
		Why:  "any kube-system pod labelled component=kube-apiserver is read as the control plane, so a decoy pod's flags decide the cluster's grade",
	},
	{
		Guard: "TestControlPlaneSignals_ReplicasDisagree", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/controlplane.go",
		Old:  "if !slices.Contains(values, v) {",
		New:  "if len(values) == 0 {",
		Why:  "only the first replica's value survives the merge, so the replica a rollout left on the old insecure flags is never reported",
	},
	{
		Guard: "TestControlPlaneSignals_EtcdEnvAndFlagPrecedence", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/controlplane.go",
		Old:  "found && e.ValueFrom == nil {",
		New:  "found && e.ValueFrom == nil && false {",
		Why:  "etcd settings given as ETCD_* variables are ignored, so ETCD_AUTO_TLS=true reads as the secure default",
	},
	{
		Guard: "TestCollect_ControlPlaneOnClusterAsset", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/kubernetes.go",
		Old:  "\t\t\tkubeSystemPods = pods\n",
		New:  "\t\t\tkubeSystemPods = nil\n",
		Why:  "the mirror pods never reach the control-plane reader, so every self-managed cluster's flag controls go silently unknown",
	},
	{
		Guard: "TestControlPlaneSignals_AuditStdoutAndGarbage", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/controlplane.go",
		Old:  "(!strings.HasPrefix(rest[i+1], \"-\") || rest[i+1] == \"-\")",
		New:  "!strings.HasPrefix(rest[i+1], \"-\")",
		Why:  "an audit log path of - (stdout) parses as a bare boolean flag, recording audit_log_path=true",
	},
	{
		Guard: "TestControlPlaneSignals_Unknown", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/controlplane.go",
		Old:  "if _, cfg := flags[\"config\"]; !cfg {\n\t\t\tr.boolean(\"profiling\", \"profiling\", true)",
		New:  "if true {\n\t\t\tr.boolean(\"profiling\", \"profiling\", true)",
		Why:  "kube-scheduler's --profiling is graded although --config makes the scheduler ignore it",
	},
	{
		Guard: "TestNodePostureChartPosture", Pkg: "./internal/collect/kubernetes",
		File: "deploy/helm-chart/graph/templates/node-posture.yaml",
		Old:  "      automountServiceAccountToken: false\n",
		New:  "      automountServiceAccountToken: true\n",
		Why:  "the host-mounting reader gets a Kubernetes token, so a compromise of it reaches the API as well as the node's files",
	},
	{
		Guard: "TestNodePostureChartRolesAreInterpreted", Pkg: "./internal/collect/kubernetes",
		File: "deploy/helm-chart/graph/values.yaml",
		Old:  "        container: files\n        roles:\n          - { role: kubelet_kubeconfig, kind: stat, file: kubelet.conf }",
		New:  "        container: kubelet\n        roles:\n          - { role: kubelet_kubeconfig, kind: stat, file: kubelet.conf }",
		Why:  "/etc/kubernetes is mounted into the uid-0 container, which can then read the node's 600 credentials and CA keys",
	},
	{
		Guard: "TestNodePostureChartRolesAreInterpreted", Pkg: "./internal/collect/kubernetes",
		File: "deploy/helm-chart/graph/values.yaml",
		Old:  "        container: files\n        roles:\n          - { role: kubelet_flags_defaults, kind: read, file: kubelet }",
		New:  "        container: kubelet\n        roles:\n          - { role: kubelet_flags_defaults, kind: read, file: kubelet }",
		Why:  "/etc/default is mounted into the uid-0 container, which can then read root-owned files there such as docker's proxy credentials",
	},
	{
		Guard: "TestFileSettings_MissingKubeletUnitIsUnknown", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/nodeposture_files.go",
		Old:  "\t\"kube_proxy_kubeconfig\": true, \"kubelet_config\": true,\n",
		New:  "\t\"kube_proxy_kubeconfig\": true, \"kubelet_config\": true, \"kubelet_service\": true,\n",
		Why:  "a kubelet unit the chart's path does not find reads as absent, which 4.1.1/4.1.2 pass",
	},
	{
		Guard: "TestCollect_NodePosturePartialCoverageIsUnknown", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/nodeposture.go",
		Old:  "if desired == 0 || len(reports) < desired {",
		New:  "if desired == 0 {",
		Why:  "the nodes the reader did report stand in for all of them, so an unreported failing node reads as a clean cluster",
	},
	{
		Guard: "TestCollect_NodePostureIgnoresImpostors", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/nodeposture.go",
		Old:  "return o.UID == ds.UID && o.Controller != nil && *o.Controller",
		New:  "return o.Controller != nil && *o.Controller",
		Why:  "any controller-owned pod in graph's namespace is read as the reader, so its log decides every node control",
	},
	{
		Guard: "TestNodeSettings_Unknown", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/nodeposture_files.go",
		Old:  "\t\tcase !f.Exists:\n\t\t\tif !optionalRoles[f.Role] {\n\t\t\t\tg.unknown = true\n\t\t\t}\n",
		New:  "\t\tcase !f.Exists:\n",
		Why:  "a kubeconfig the chart's path does not find reads as absent, which the file controls pass: a profile mismatch hides every file",
	},
	{
		Guard: "TestNodeSettings_DefaultKubeadmWorker", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/nodeposture_kubelet.go",
		Old:  "\tif d == 0 {\n\t\treturn defaultStreamingIdleTimeout, true\n\t}\n",
		New:  "",
		Why:  "kubeadm's 0s placeholder reads as a disabled idle timeout, a false 4.2.5 finding on every kubeadm node",
	},
	{
		Guard: "TestNodeChecks_ManagedFileLimit", Pkg: "./internal/checks",
		File: "internal/checks/k8s_node_files.go",
		Old:  "\tcase \"aws\", \"gcp\", \"azure\":\n",
		New:  "\tcase \"aws\", \"gcp\", \"azure\", \"\":\n",
		Why:  "a self-managed cluster is graded on EKS's 644, so a 644 kubelet config passes CIS Kubernetes 4.1.9 which demands 600",
	},
	{
		Guard: "TestNamespacePSA_PolicyEngineEvidence", Pkg: "./internal/checks",
		File: "internal/checks/k8s_namespace_policy.go",
		Old:  "if level == \"\" && a.Metadata[\"pod_security_engine\"] != \"\" {",
		New:  "if level == \"\" && a.Metadata[\"cluster_policy_engines\"] != \"\" {",
		Why:  "an installed engine with no policies, or Audit-only ones, reads as enforcing pod security and the namespace goes clean",
	},
	{
		Guard: "TestPodSecurityCoverage", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/admission_coverage.go",
		Old:  "if !strings.EqualFold(firstNonEmpty(action, specAction), \"enforce\") {",
		New:  "if firstNonEmpty(action, specAction) == \"\\x00\" {",
		Why:  "a Kyverno podSecurity rule in Audit, which admits everything, is counted as enforcing pod security",
	},
	{
		Guard: "TestPodSecurityCoverage", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/admission_coverage.go",
		Old:  "if action != \"\" && action != \"deny\" {",
		New:  "if action == \"\\x00\" {",
		Why:  "a Gatekeeper constraint in dryrun or warn is counted as enforcing pod security",
	},
	{
		Guard: "TestPolicyEngineChartRBACMatchesReads", Pkg: "./internal/collect/kubernetes",
		File: "deploy/helm-chart/graph/templates/policy-engine-rbac.yaml",
		Old:  "      - k8spspseccomp\n",
		New:  "",
		Why:  "a constraint kind the collector reads is not granted, so the read is forbidden and every namespace falls back to Info",
	},
	{
		Guard: "TestDecodeClusters_ExplicitPoolOptOutAndMissingZones", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/gke_posture.go",
		Old:  "\t\t\tif v, ok := explicitPrivate[p.Name]; ok {\n\t\t\t\treturn !v, true\n\t\t\t}\n",
		New:  "",
		Why:  "a node pool that opts out of private nodes on a private cluster reads as private, hiding nodes with external IPs",
	},
	{
		Guard: "TestCollectLoadBalancing", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/loadbalancing.go",
		Old:  "\tif !found {\n\t\treturn false, \"\", false\n\t}",
		New:  "\tif !found {\n\t\treturn false, \"\", true\n\t}",
		Why:  "an SSL policy that could not be read is graded strong, so a weak TLS proxy goes silent whenever the policy listing fails",
	},
	{
		Guard: "TestFilterCovers", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/logfilter.go",
		Old:  "\t\treturn !ok || !strings.EqualFold(v, x.value)\n",
		New:  "\t\treturn ok && strings.EqualFold(v, x.value)\n",
		Why:  "a negated log filter (methodName != X) matches the change it excludes and counts as the CIS change alert",
	},
	{
		Guard: "TestFilterCovers", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/logfilter.go",
		Old:  "\t\tleft = andExpr{left, right}\n",
		New:  "\t\tleft = orExpr{left, right}\n",
		Why:  "a filter AND-ing a narrowing clause (severity>=ERROR, one project) onto the CIS filter reads as covering every change",
	},
	{
		Guard: "TestCollectLoggingSettings_DeniedOptionalReadsAreNotPartial", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/target.go",
		Old:  "\tif deniedErr(ctx, err) {\n",
		New:  "\tif false && deniedErr(ctx, err) {\n",
		Why:  "a project-scoped deployment without organization grants goes partial every sweep, stopping deletion reconciliation for every asset type",
	},
	{
		Guard: "TestAnnotateIAPBypass", Pkg: "./internal/collect/gcp",
		File: "internal/collect/gcp/posture_join.go",
		Old:  "\t\tunknown := !firewallsKnown\n",
		New:  "\t\tunknown := false\n",
		Why:  "with the firewall listing failed, an IAP backend reads as reachable only through Google's proxies — a clean answer from no data",
	},
	{
		Guard: "TestGCEDefaultSAChecksExemptGKENodes", Pkg: "./internal/checks",
		File: "internal/checks/cspm_extra.go",
		Old:  "return gceDefaultSA(a) && !gceDefaultSAFullScope(a) && !gkeNodeGraded(a)",
		New:  "return gceDefaultSA(a) && !gceDefaultSAFullScope(a)",
		Why:  "every GKE node VM repeats the node pool's default-service-account finding, one per node instead of one per cluster",
	},
	{
		Guard: "TestGCEDefaultSAChecksExemptGKENodes", Pkg: "./internal/checks",
		File: "internal/checks/gcp_compute.go",
		Old:  "return gkeNode(a) && a.Metadata[\"gke_node_pool_graded\"] == \"true\"",
		New:  "return gkeNode(a)",
		Why:  "a GKE node whose cluster listing failed is silenced by its label alone, so a default-SA node with full scope goes unreported",
	},
	{
		Guard: "TestKMSRotationGradesOnlyRotatableKeys", Pkg: "./internal/checks",
		File: "internal/checks/gcp_kms_apikeys.go",
		Old:  "return a.Metadata[\"purpose\"] == \"ENCRYPT_DECRYPT\" && ",
		New:  "return ",
		Why:  "asymmetric signing keys, which cannot rotate automatically, fire the 90-day rotation finding they can never satisfy",
	},
	{
		Guard: "TestStampRDSParameterFacts", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/rds_parameters.go",
		Old:  "\t\t\tv, present := params[s.name]\n\t\t\tif !present {\n\t\t\t\tcontinue // the engine version has no such parameter\n\t\t\t}\n",
		New:  "\t\t\tv := params[s.name]\n",
		Why:  "a parameter group that was never read, or an engine version without the parameter, is stamped with the insecure default and graded as a TLS finding",
	},
	{
		Guard: "TestAuroraMySQLAuditFindingsFireOnce", Pkg: "./internal/checks",
		File: "internal/checks/aws_rds_clusters.go",
		Old:  " && !auroraServerlessV1(a) && !auroraMySQLAuditDisabled(a)\n",
		New:  " && !auroraServerlessV1(a)\n",
		Why:  "a default Aurora MySQL cluster raises two findings — auditing off and audit log not exported — for one root cause",
	},
	{
		Guard: "TestRDSNotEncryptedHandsMembersToTheirCluster", Pkg: "./internal/checks",
		File: "internal/checks/hygiene.go",
		Old:  "return a.Metadata[\"storage_encrypted\"] == \"false\" && !rdsClusterMember(a)\n",
		New:  "return a.Metadata[\"storage_encrypted\"] == \"false\"\n",
		Why:  "an unencrypted Aurora cluster is reported once per member instance on top of the cluster finding",
	},
	{
		Guard: "TestOpenSearchExposureTiers", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/opensearch.go",
		Old:  "	case policyOpen && !fgacGates:\n",
		New:  "	case policyOpen:\n",
		Why:  "a public domain whose open policy is still authenticated by fine-grained access control is graded confirmed-public Critical",
	},
	{
		Guard: "TestOpenSearchDescribesInBatchesAndFailsWhole", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/opensearch.go",
		Old:  "			return nil, fmt.Errorf(\"collectOpenSearchDomains: describe: %w\", err)\n",
		New:  "			continue\n",
		Why:  "a throttled describe batch silently drops up to five domains and the region's listing still reads as complete",
	},
	{
		Guard: "TestOpenSearchAuditLogsStepAsideWithoutFGAC", Pkg: "./internal/checks",
		File: "internal/checks/aws_opensearch.go",
		Old:  "		return a.Metadata[\"audit_logs_enabled\"] == \"false\" && a.Metadata[\"fine_grained_access_control\"] == \"true\"\n",
		New:  "		return a.Metadata[\"audit_logs_enabled\"] == \"false\"\n",
		Why:  "a domain without fine-grained access control gets two findings for one root cause: audit logs cannot exist without FGAC",
	},
	{
		Guard: "TestElastiCacheGroupNodesStepAsideForTheGroup", Pkg: "./internal/checks",
		File: "internal/checks/aws_elasticache.go",
		Old:  "{ return observedNone(a, \"replication_group_id\") }",
		New:  "{ return a.Metadata[\"replication_group_id\"] == \"\" }",
		Why:  "a cache node whose group membership was never read is graded standalone, duplicating its replication group's finding",
	},
	{
		Guard: "TestDMSEndpointSSLGradesOnlySslModeEngines", Pkg: "./internal/checks",
		File: "internal/checks/aws_dms.go",
		Old:  "slices.Contains(dmsSSLModeEngines, a.Metadata[\"engine\"])\n",
		New:  "slices.Contains(dmsSSLModeEngines, a.Metadata[\"engine\"]) || a.Metadata[\"ssl_mode\"] == \"none\"\n",
		Why:  "S3, DynamoDB, Kinesis and other HTTPS-API endpoints, whose SslMode is none by construction, are reported as unencrypted",
	},
	{
		Guard: "TestCollectMSKClusters", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/msk.go",
		Old:  "strconv.FormatBool(eit.InCluster == nil || *eit.InCluster)",
		New:  "strconv.FormatBool(awssdk.ToBool(eit.InCluster))",
		Why:  "a cluster that omits InCluster (the API default, encrypted) is reported as replicating in plaintext",
	},
	{
		Guard: "TestCollectEFS", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/efs.go",
		Old:  "			case known && ok:\n",
		New:  "			case known:\n",
		Why:  "a file system whose automatic-backup setting was never read is reported as in no backup plan",
	},
	{
		Guard: "TestBackupRuleAssigns", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/backup_selection.go",
		Old:  "	case !ok:\n		return tristateUnknown\n",
		New:  "	case !ok:\n		return tristateYes\n",
		Why:  "an unread EFS opt-in is taken as opted in, so a service-wide backup selection is credited with covering file systems it may skip",
	},
	{
		Guard: "TestEFSBackupChecksFireOncePerRootCause", Pkg: "./internal/checks",
		File: "internal/checks/aws_efs_fsx.go",
		Old:  "efsAutomaticBackupsOff(a) && a.Metadata[\"in_backup_plan\"] != \"false\"",
		New:  "efsAutomaticBackupsOff(a)",
		Why:  "a file system no backup plan covers carries two findings for one root cause",
	},
	// ── Redshift posture ────────────────────────────────────────────────
	{
		Guard: "TestStampRedshiftPortWorldOpen", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/redshift.go",
		Old:  "\t\t\tif !parsed {\n\t\t\t\tknown = false\n",
		New:  "\t\t\tif !parsed {\n\t\t\t\t_ = known\n",
		Why:  "a security group whose ingress could not be parsed is graded port-closed, closing a Redshift.15 finding on unreadable evidence",
	},
	{
		Guard: "TestRedshiftClustersPostureAndSubReads", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/redshift.go",
		Old:  "\t\tif v != nil {\n\t\t\tmeta[k] = strconv.FormatBool(*v)\n\t\t}\n",
		New:  "\t\tmeta[k] = strconv.FormatBool(awssdk.ToBool(v))\n",
		Why:  "a field DescribeClusters omitted reads as false, minting unencrypted / no-upgrade findings out of a sparse response",
	},
	{
		Guard: "TestRedshiftPublicAndWorldOpenIsOneFinding", Pkg: "./internal/checks",
		File: "internal/checks/aws_redshift.go",
		Old:  "\t\treturn a.Metadata[\"publicly_accessible\"] == \"true\" && a.Metadata[\"port_world_open\"] != \"true\"\n",
		New:  "\t\treturn a.Metadata[\"publicly_accessible\"] == \"true\"\n",
		Why:  "a public cluster with a world-open port is reported twice for one root cause",
	},
	// ── S3 exposure split ───────────────────────────────────────────────
	{
		Guard: "TestS3PublicFindingsOncePerRootCause", Pkg: "./internal/checks",
		File: "internal/checks/cis.go",
		Old:  "\t\tif s3PublicDataGrant(a) {\n",
		New:  "\t\tif false && s3PublicDataGrant(a) {\n",
		Why:  "a publicly readable bucket is reported by both aws-s3-public-read and aws-s3-public-bucket for one grant",
	},
	{
		Guard: "TestCollectS3Buckets_PublicReadWriteSplit", Pkg: "./internal/collect/aws",
		File: "internal/collect/aws/s3.go",
		Old:  "\tknown := policyKnown && (ignore || acl.aclObserved)\n",
		New:  "\tknown := policyKnown\n",
		Why:  "an unread bucket ACL is graded as granting nothing, writing public_read=false and closing a public-read finding on a permission gap",
	},
	{
		Guard: "TestRootMFAChecks", Pkg: "./internal/checks",
		File: "internal/checks/cspm_expanded.go",
		Old:  "a.Metadata[\"console_access\"] != \"false\" && a.Metadata[\"mfa_enabled\"] == \"false\"",
		New:  "a.Metadata[\"console_access\"] == \"true\" && a.Metadata[\"mfa_enabled\"] == \"false\"",
		Why:  "a root account without MFA goes silent whenever the credential report does not say whether root has a password (a root row reading not_supported)",
	},
	{
		Guard: "TestKMSRotationGradesOnlyRotatableAWSKeys", Pkg: "./internal/checks",
		File: "internal/checks/cspm_expanded.go",
		Old:  "a.Metadata[\"key_state\"] == \"Enabled\" && awsKMSRotationGraded(a) && ",
		New:  "a.Metadata[\"key_state\"] == \"Enabled\" && ",
		Why:  "asymmetric, HMAC, imported-material and custom-key-store keys are reported for a rotation AWS cannot turn on",
	},
	{
		Guard: "TestKMSRotationGradesOnlyRotatableAWSKeys", Pkg: "./internal/checks",
		File: "internal/checks/cspm_expanded.go",
		Old:  " &&\n\t\t(observedNone(a, \"multi_region_key_type\") || a.Metadata[\"multi_region_key_type\"] == \"PRIMARY\")",
		New:  "",
		Why:  "every replica of an unrotated multi-Region key gets its own finding, whose fix cannot be applied on a replica",
	},
	{
		Guard: "TestServiceLBScheme_LoadBalancerClass", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/service.go",
		Old:  "\tif awsNLBControllerManaged(svc) {\n\t\treturn awsNLBControllerScheme(svc)\n\t}\n",
		New:  "",
		Why:  "NLBs from the AWS Load Balancer Controller or EKS Auto Mode annotated internal are reported as public load balancers and exposure edges",
	},
	{
		Guard: "TestServiceLBScheme_LoadBalancerClass", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/service.go",
		Old:  "\treturn schemeUnstated\n",
		New:  "\treturn schemeInternal\n",
		Why:  "a controller NLB with no scheme annotation is read as internal and its address dropped, though an existing NLB's scheme or the controller's default can make it internet-facing",
	},
	{
		Guard: "TestServiceAsset_SourceRanges", Pkg: "./internal/collect/kubernetes",
		File: "internal/collect/kubernetes/service.go",
		Old:  "\tif len(raw) == 0 && !isAutoModeNLB(svc) {\n",
		New:  "\tif len(raw) == 0 {\n",
		Why:  "an EKS Auto Mode NLB limited only by the legacy source-ranges annotation, which Auto Mode ignores, is downgraded from world-open",
	},
	{
		Guard: "TestK8sServicePublicLoadBalancer", Pkg: "./internal/checks",
		File: "internal/checks/k8s_workload.go",
		Old:  "\t\tif a.Metadata[\"scheme_assumed\"] == \"true\" || a.Metadata[\"source_restricted\"] == \"true\" {\n",
		New:  "\t\tif a.Metadata[\"source_restricted\"] == \"true\" {\n",
		Why:  "a public LoadBalancer whose scheme an AWS controller chose unseen is reported at High as an observed internet-facing load balancer",
	},
	{
		Guard: "TestK8sServiceTargets_SourceRestrictedServiceIsPossible", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/k8s.go",
		Old:  "\t\treturn asset.PublicAccessPossible\n",
		New:  "\t\treturn asset.PublicAccessConfirmed\n",
		Why:  "a LoadBalancer limited by loadBalancerSourceRanges or on an unstated scheme is drawn as confirmed open to the whole internet",
	},
	{
		Guard: "TestK8sServiceTargets_SourceRestrictedServiceIsPossible", Pkg: "./internal/app/correlate",
		File: "internal/app/correlate/k8s.go",
		Old:  "\t\tcase betterExposure(e, edges[i]):\n",
		New:  "\t\tcase i < 0 && betterExposure(e, edges[i]):\n",
		Why:  "a workload a world-open and a restricted LoadBalancer both select keeps whichever exposure edge was read first, so it can persist as possible and flap between sweeps",
	},
	// ── VM disk scan (agentless, opt-in snapshot reads) ─────────────────
	{
		Guard: "TestDegradedIsUnknown", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old:  "\tif err := lfs.Fault(); err != nil {\n",
		New:  "\tif err := lfs.Fault(); err != nil && false {\n",
		Why: "a disk part that failed to read (unreadable blocks, a hostile size, a cancelled context) is reported " +
			"as a good inventory of whatever the parsers saw, so a half-read disk reads as clean",
	},
	{
		Guard: "TestDegradedIsUnknown_UnreadableBlocks", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old:  "\tif err := lfs.Fault(); err != nil {\n",
		New:  "\tif err := lfs.Fault(); err != nil && false {\n",
		Why: "a disk part that failed to read (unreadable blocks, a hostile size, a cancelled context) is reported " +
			"as a good inventory of whatever the parsers saw, so a half-read disk reads as clean",
	},
	{
		Guard: "TestScanDisk_XFSDegradedIsUnknown", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old:  "\tif err := lfs.Fault(); err != nil {\n",
		New:  "\tif err := lfs.Fault(); err != nil && false {\n",
		Why: "a disk part that failed to read (unreadable blocks, a hostile size, a cancelled context) is reported " +
			"as a good inventory of whatever the parsers saw, so a half-read disk reads as clean",
	},
	{
		Guard: "TestScanDisk_ContextCancelled", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old: "\tif err := ctx.Err(); err != nil {\n" +
			"\t\treturn DiskResult{}, fmt.Errorf(\"ScanDisk: %w\", err)\n",
		New: "\tif err := ctx.Err(); err != nil && false {\n" +
			"\t\treturn DiskResult{}, fmt.Errorf(\"ScanDisk: %w\", err)\n",
		Why: "a cancelled scan reports a read-error gap instead of the context error, so a job that was told to " +
			"stop records a disk as unreadable",
	},
	{
		Guard: "TestScanDisk_HostileSizesStayBounded", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/limitedfs.go",
		Old:  "\tif size > l.maxFile {\n",
		New:  "\tif size > l.maxFile && false {\n",
		Why:  "a file claiming 2^45 bytes passes the per-file cap, so a hostile filesystem decides how much the scanner reads",
	},
	{
		Guard: "TestScanDisk_LanguageManifestsAreNeverRead", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old:  "InventoryKnown: true, LanguageGap: true}, true",
		New:  "InventoryKnown: true, LanguageGap: false}, true",
		Why: "a disk inventory stops declaring that language manifests were never walked, so an OS-only inventory " +
			"reads as complete application coverage",
	},
	{
		Guard: "TestScanDisk_Layouts", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old: "\tcase errors.Is(err, part.ErrNoTable):\n" +
			"\t\treturn []candidate{{0, size}}\n",
		New: "\tcase errors.Is(err, part.ErrNoTable):\n" +
			"\t\treturn nil\n",
		Why: "a bare filesystem with no partition table (the common cloud root volume) yields no candidates and is " +
			"never scanned",
	},
	{
		Guard: "TestScanDisk_XFSRoots", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old:  "bytes.HasPrefix(head, []byte(\"XFSB\"))",
		New:  "bytes.HasPrefix(head, []byte(\"XFSX\"))",
		Why: "an XFS root is handed to the ext4 reader, fails as not-ext4 and is reported unsupported, so every " +
			"RHEL-family disk is a permanent gap",
	},
	{
		Guard: "TestScanDisk_PackageManagers", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/limitedfs.go",
		Old:  "return dir == \"var/lib/rpm\" || dir == \"usr/lib/sysimage/rpm\" || dir == dpkgStatusDir",
		New:  "return dir == \"var/lib/rpm\" || dir == \"usr/lib/sysimage/rpm\"",
		Why: "the files inside the dpkg status.d directory are not allowlisted, so a distroless image's package " +
			"database lists but cannot be read",
	},
	{
		Guard: "TestScanDisk_PartialGoodRootBeatsUnreadableNeighbour", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/scan.go",
		Old:  "\t\tif res, ok := st.scan(ctx, br, c, lim); ok {\n",
		New:  "\t\tif res, ok := st.scan(ctx, br, c, lim); ok || true {\n",
		Why: "the first partition that is not the root ends the scan, so a junk or boot partition ahead of the " +
			"root hides a readable inventory",
	},
	{
		Guard: "TestSnapshotMutationAllowlist", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/awsdisk/provider.go",
		Old:  "func hasTag(tags []ec2types.Tag, key string) bool {\n",
		New: "func hasTag(tags []ec2types.Tag, key string) bool {\n" +
			"\t(struct{ CreateSnapshot func() }{func() {}}).CreateSnapshot()\n",
		Why: "a read-only provider package calls a snapshot-creating method, so cloud state changes outside the " +
			"snapshotter chokepoint with no opt-in",
	},
	{
		Guard: "TestMutatingClientsOnlyInSnapshotter", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/awsdisk/provider.go",
		Old:  "// Clients are the per-region clients for one provider call.\n",
		New: "type snapshotCreator interface {\n" +
			"\tCreateSnapshot(ctx context.Context)\n" +
			"}\n" +
			"\n" +
			"// Clients are the per-region clients for one provider call.\n",
		Why: "a read-only provider interface declares a mutating method, so a client that can create snapshots " +
			"satisfies it and the read path holds write authority",
	},
	{
		Guard: "TestMutatingClientsOnlyInSnapshotter", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/awsdisk/provider.go",
		Old:  "// Clients are the per-region clients for one provider call.\n",
		New: "var _ *ec2.Client\n" +
			"\n" +
			"// Clients are the per-region clients for one provider call.\n",
		Why: "a concrete ec2.Client, which can create and delete snapshots, is named outside the snapshotter package",
	},
	{
		Guard: "TestJobsNeverImportCloudMutators", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_volume.go",
		Old:  "\t\"github.com/riverqueue/river\"\n",
		New: "\t_ \"github.com/aws/aws-sdk-go-v2/service/ec2\"\n" +
			"\t\"github.com/riverqueue/river\"\n",
		Why: "a job imports the EC2 client, so cloud mutation can be built inside a River worker instead of only " +
			"in cmd/graph behind the snapshotter",
	},
	{
		Guard: "TestCreateTaggedProbesThenCreatesWithTagAtCreation", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/aws.go",
		Old:  "\t\t\tTags:         []ec2types.Tag{{Key: aws.String(diskscan.TagKey), Value: aws.String(runID)}},\n",
		New:  "\t\t\tTags:         nil,\n",
		Why: "a snapshot is created without the vulngraph-disk-scan tag, so the delete guard refuses to remove it " +
			"and it lingers, billed, until a person finds it",
	},
	{
		Guard: "TestDeleteOnlyTaggedSnapshots", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/aws.go",
		Old:  "\tif !live[0].Ephemeral {\n",
		New:  "\tif false {\n",
		Why: "a snapshot whose live tags do not show Vulngraph created it is deleted anyway, so the disk-scan role " +
			"can destroy a customer's own backup",
	},
	{
		Guard: "TestCreateTaggedDryRunDenied", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/aws.go",
		Old:  "\tprobe.DryRun = aws.Bool(true)\n",
		New:  "\tprobe.DryRun = aws.Bool(false)\n",
		Why: "the permission probe really creates a snapshot, so a denied-permission connector is not detected and " +
			"a real create runs before the check",
	},
	{
		Guard: "TestAzure_RequiresValidOptIn", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/azure.go",
		Old:  "\tif !optIn.Valid() || optIn.Role() != a.optIn.Role() {\n",
		New:  "\tif false {\n",
		Why: "an Azure snapshot call proceeds on a zero or foreign opt-in, so any holder of the snapshotter can " +
			"mutate cloud state",
	},
	{
		Guard: "TestAzure_CreateTagged", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/azure.go",
		Old:  "\t\tTags:     map[string]*string{diskscan.TagKey: &runID},\n",
		New:  "\t\tTags:     nil,\n",
		Why:  "an Azure snapshot is created untagged, so the delete guard refuses it and the sweeper never lists it",
	},
	{
		Guard: "TestAzure_DeleteTagged", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/azure.go",
		Old:  "\tif _, ok := live.Tags[diskscan.TagKey]; !ok {\n",
		New:  "\tif _, ok := live.Tags[diskscan.TagKey]; !ok && false {\n",
		Why: "an Azure snapshot without the vulngraph-disk-scan tag is deleted, so the disk-scan principal can " +
			"destroy a customer's own snapshot",
	},
	{
		Guard: "TestAzure_GrantRead_RevokedOnEveryErrorPath", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/azure_read.go",
		Old:  "\t\t\tr.revokeQuietly(ctx, rg, name)\n",
		New:  "\t\t\t_, _ = rg, name\n",
		Why:  "a failed read grant is not revoked, so a SAS URL to a customer's disk outlives the scan that asked for it",
	},
	{
		Guard: "TestAzure_DeleteTagged_RefusesOtherResourceGroup", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/azure.go",
		Old:  "\tif !strings.EqualFold(id.ResourceGroupName, a.rg) {\n",
		New:  "\tif false {\n",
		Why: "a snapshot id in another resource group is deleted or granted, so the disk-scan principal acts " +
			"outside the group it was scoped to",
	},
	{
		Guard: "TestAuthorizeRead", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/contracts.go",
		Old:  "\tif grant.Mode != ModeExistingSnapshots && grant.Mode != ModeCreateSnapshots {\n",
		New:  "\tif false {\n",
		Why: "a connector whose disk-scan mode is off, or unknown, gets a read opt-in, so Azure snapshots are " +
			"read with no standing approval",
	},
	{
		Guard: "TestAuthorizeRead", Pkg: "./internal/scanner/diskscan",
		File: "internal/scanner/diskscan/contracts.go",
		Old: "\tif slices.Contains(grant.OtherRoles, grant.DiskScanRole) {\n" +
			"\t\treturn ReadOptIn{}, fmt.Errorf(\"AuthorizeRead:",
		New: "\tif false && slices.Contains(grant.OtherRoles, grant.DiskScanRole) {\n" +
			"\t\treturn ReadOptIn{}, fmt.Errorf(\"AuthorizeRead:",
		Why: "the read grant is authorized for a principal that is also the collection or execute principal, so " +
			"the SAS authority rides on a role with other grants",
	},
	{
		Guard: "TestAzure_ReadRequiresValidReadOptIn", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/azure_read.go",
		Old:  "\tif !readIn.Valid() || readIn.Principal() != r.principal {\n",
		New:  "\tif false {\n",
		Why: "an Azure read grant or revoke proceeds on a zero or foreign read opt-in, so any holder of the " +
			"snapshotter can open a SAS on a customer's disk",
	},
	{
		Guard: "TestAzureReader_ReadsAcrossResourceGroupsOfItsSubscription", Pkg: "./internal/scanner/diskscan/snapshotter",
		File: "internal/scanner/diskscan/snapshotter/azure_read.go",
		Old:  "\tif r.sub != \"\" && !strings.EqualFold(id.SubscriptionID, r.sub) {\n",
		New:  "\tif r.sub != \"\" && !strings.EqualFold(id.SubscriptionID, r.sub) && false {\n",
		Why: "a read grant is made on a snapshot in another subscription, so the principal's SAS authority leaves " +
			"the connector's own subscription",
	},
	{
		Guard: "TestSetDiskScanMode_Refusals", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_diskscan.go",
		Old:  "\tcase diskscan.DiskScanModeExistingSnapshots:\n\t\treturn t == TypeAzure\n",
		New:  "\tcase diskscan.DiskScanModeExistingSnapshots:\n\t\treturn false\n",
		Why: "Azure existing_snapshots is enabled with no disk-scan principal, so its SAS grants would use the " +
			"collection principal",
	},
	{
		Guard: "TestVolume_ReadOptInHoldsInBothModesAndNeverCreates", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_volume.go",
		Old:  "\tcase rerr == nil:\n\t\tv.readIn = readIn\n",
		New:  "\tcase rerr == nil:\n\t\t_ = readIn\n",
		Why: "the volume job never mints the read opt-in, so Azure snapshots cannot be read in either mode and " +
			"every volume reads as permission_denied",
	},
	{
		Guard: "TestVolume_AzureExistingSnapshots_GrantIsRevokedOnEveryPath", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_volume.go",
		Old:  "\t\tif err := v.access.Cloud.Release(cctx, v.ins(), snap); err != nil {\n",
		New:  "\t\tif err := func() error { _ = cctx; return nil }(); err != nil {\n",
		Why: "a snapshot's read SAS is not revoked when a scan of an existing snapshot ends, so a URL to a " +
			"customer's disk outlives the scan",
	},
	{
		Guard: "TestVolume_ExpiredCredentialsAreAGapNeverARetryLoop", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_volume.go",
		Old:  "\tif errors.Is(err, ErrDiskCredentialsExpired) {\n\t\t// The sealed credentials ran out mid-job.",
		New:  "\tif false {\n\t\t// The sealed credentials ran out mid-job.",
		Why: "a job whose sealed credentials expire mid-run returns the error, so River retries it with the same " +
			"dead credentials until attempts run out",
	},
	{
		Guard: "TestPlan_ARunStillInFlightIsNotPlannedAgain", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan.go",
		Old:  "\t\tif !run.Stale(cutoff) {\n\t\t\tbusy = true\n",
		New:  "\t\tif !run.Stale(cutoff) {\n\t\t\tbusy = false\n",
		Why: "a connector with a run in flight is planned again, so a second run's jobs queue behind the first " +
			"and start after their credentials have expired",
	},
	{
		Guard: "TestOpenRefusesExpiredAndForeignEnvelopes", Pkg: "./cmd/graph",
		File: "cmd/graph/diskscan_cloud.go",
		Old:  "\tif errors.Is(err, envelope.ErrExpired) {\n",
		New:  "\tif false {\n",
		Why: "an expired envelope is reported as a tampered one, so an expiry is recorded as read_error and the " +
			"plan treats it as an unreadable disk instead of reading the volume again at once",
	},
	{
		Guard: "TestAWSSessionPoliciesAreExactlyTheSnapshotActions", Pkg: "./cmd/graph",
		File: "cmd/graph/diskscan_aws.go",
		Old:  "`\"ec2:CreateSnapshot\",\"ec2:CreateTags\",\"ec2:DeleteSnapshot\"],\"Resource\":\"*\"}]}`",
		New:  "`\"ec2:CreateSnapshot\",\"ec2:CreateTags\",\"ec2:DeleteSnapshot\",\"ec2:ModifySnapshotAttribute\"],\"Resource\":\"*\"}]}`",
		Why: "the disk-scan session policy allows an action beyond create, tag and delete snapshot, so a " +
			"compromised scanner can share a snapshot with another account",
	},
	{
		Guard: "TestChartDiskScanOffMeansOff", Pkg: "./cmd/graph",
		File: "deploy/helm-chart/graph/templates/secret.yaml",
		Old: "  {{- if .Values.config.diskScanEnabled }}\n" +
			"  # Seals disk-scan credentials for the scanner pod. Derived from secretKey, like\n" +
			"  # the ladybug RPC secret, so it reveals nothing about it; set\n" +
			"  # secret.diskScanEnvelopeKey (base64 of 32 bytes) for an independent one.\n" +
			"  # Rendered only when disk scanning is on: off means no key exists at all.\n" +
			"  disk-scan-envelope-key: {{ default (printf \"disk-scan-envelope|%s\" .Values.secret.secretKey | sha256sum | trunc 32 | b64enc) .Values.secret.diskScanEnvelopeKey | quote }}\n" +
			"  {{- end }}\n",
		New: "  # Seals disk-scan credentials for the scanner pod. Derived from secretKey, like\n" +
			"  # the ladybug RPC secret, so it reveals nothing about it; set\n" +
			"  # secret.diskScanEnvelopeKey (base64 of 32 bytes) for an independent one.\n" +
			"  # Rendered only when disk scanning is on: off means no key exists at all.\n" +
			"  disk-scan-envelope-key: {{ default (printf \"disk-scan-envelope|%s\" .Values.secret.secretKey | sha256sum | trunc 32 | b64enc) .Values.secret.diskScanEnvelopeKey | quote }}\n",
		Why: "the disk-scan envelope key is rendered into the Secret even with disk scanning off, so \"off\" still " +
			"leaves a credential-sealing key in the cluster",
	},
	{
		Guard: "TestDiskScanRoleIsTheSnapshotActionList", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-diskscan-role.yaml",
		Old:  "                    aws:ResourceTag/vulngraph-disk-scan: \"false\"\n",
		New:  "                    aws:ResourceTag/vulngraph-disk-scan: \"true\"\n",
		Why: "the disk-scan role may delete snapshots that do NOT carry the vulngraph-disk-scan tag, so it can " +
			"delete any snapshot in the account",
	},
	{
		Guard: "TestDiskScanReadIsOptIn", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-readonly-role.yaml",
		Old: "  GrantDiskScanRead:\n" +
			"    Type: String\n" +
			"    Default: \"false\"\n",
		New: "  GrantDiskScanRead:\n" +
			"    Type: String\n" +
			"    Default: \"true\"\n",
		Why: "the read-only role reads every snapshot (a whole disk, secrets included) unless the operator opts " +
			"out, instead of only when they opt in",
	},
	{
		Guard: "TestHubDiskScanRoleIsOptIn", Pkg: "./deploy/aws",
		File: "deploy/aws/graph-hub-role.yaml",
		Old: "  DiskScanRoleName:\n" +
			"    Type: String\n" +
			"    Default: \"\"\n",
		New: "  DiskScanRoleName:\n" +
			"    Type: String\n" +
			"    Default: \"graph-diskscan\"\n",
		Why: "the hub may assume the disk-scan role by default, so the snapshot-creating path exists in every " +
			"account that installs the hub without asking for it",
	},
	{
		Guard: "TestSetDiskScanMode_Refusals", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_diskscan.go",
		Old:  "\tif !actor.Admin || actor.ViaAPIKey {\n",
		New:  "\tif false {\n",
		Why: "a non-admin session or an API key changes a connector's disk-scan opt-in, which is the standing " +
			"approval for reading VM disks",
	},
	{
		Guard: "TestSetDiskScanMode_Refusals", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_diskscan.go",
		Old:  "\t\tif confirmation != DiskScanConfirmation {\n",
		New:  "\t\tif false {\n",
		Why: "disk scanning is enabled without the typed confirmation, so one stray request grants read access to " +
			"every VM disk",
	},
	{
		Guard: "TestSetDiskScanMode_Refusals", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_diskscan.go",
		Old:  "\t\tif diskScanRoleRequired(c.Type, mode) && role == \"\" {\n",
		New:  "\t\tif false {\n",
		Why: "create_snapshots is enabled with no disk-scan role, so snapshots would be created with the " +
			"collection role's credentials",
	},
	{
		Guard: "TestSetDiskScanMode_Refusals", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_diskscan.go",
		Old:  "\t\tif role != \"\" && slices.Contains(others, role) {\n",
		New:  "\t\tif role != \"\" && slices.Contains(others, role) && false {\n",
		Why: "the disk-scan role may equal the collection, read-only or execute role, so snapshot-creating " +
			"authority is added to a role with other grants",
	},
	{
		Guard: "TestSetDiskScanMode_IsAuditedWithBeforeAfterRoleActor", Pkg: "./internal/app/connector",
		File: "internal/app/connector/service_diskscan.go",
		Old:  "\ts.record(ctx, AuditActionDiskScanChange, id, map[string]any{\n",
		New:  "\ts.record(ctx, AuditActionDiskScanChange+\"_unrecorded\", id, map[string]any{\n",
		Why: "a disk-scan opt-in change is written under a different audit action than connector.disk_scan_change, " +
			"so the change history an auditor queries is empty",
	},
	{
		Guard: "TestValidateResult_NeverCleanForUnreadableDisk", Pkg: "./internal/app/diskscan",
		File: "internal/app/diskscan/service.go",
		Old:  "\tif !slices.Contains(validGaps, r.Gap) {\n",
		New:  "\tif !slices.Contains(validGaps, r.Gap) && false {\n",
		Why: "an unknown inventory with no recognised gap is accepted, so an unreadable disk can be stored in a " +
			"form that reads as clean",
	},
	{
		Guard: "TestLatest", Pkg: "./internal/app/diskscan",
		File: "internal/app/diskscan/service.go",
		Old: "\t\tif r.Gap == GapNone {\n" +
			"\t\t\tr.Gap = GapReadError\n",
		New: "\t\tif false {\n" +
			"\t\t\tr.Gap = GapReadError\n",
		Why: "a stored row claiming neither a known inventory nor a gap is read back as clean instead of as a read error",
	},
	{
		Guard: "TestPackageInventoryKnown", Pkg: "./internal/app/asset",
		File: "internal/app/asset/domain.go",
		Old:  " || v == PackageInventoryDisk",
		New:  "",
		Why: "a VM whose packages came from a disk scan is not recognised as a known inventory, so its " +
			"runs_package edges read as unknown",
	},
	{
		Guard: "TestVolume_NoWriteCallWithoutAnOptIn", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_volume.go",
		Old:  "\tgrant.DiskScanRole, grant.OtherRoles = access.Role, access.OtherRoles\n",
		New:  "",
		Why: "the sealed envelope's role identifiers never reach Authorize, so a disk-scan role equal to the " +
			"collection role still opts in to snapshot creation",
	},
	{
		Guard: "TestVolume_CreatePathRegistersIntentFirstAndAlwaysCleansUp", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_volume.go",
		Old: "\tdefer func() { v.cleanup(ctx, sn, snap, intent.ID) }()\n" +
			"\n",
		New: "\n",
		Why: "a snapshot the job created is not deleted when the scan, the wait or the open fails, so a customer " +
			"disk copy lingers until the sweep finds it",
	},
	{
		Guard: "TestVolume_ExistingSnapshotIsReadAndNeverCreatesOne", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_volume.go",
		Old: "\terr := v.w.svc.RecordPackages(ctx, diskscan.PackageSet{\n" +
			"\t\tAssetID: v.a.AssetID, VolumeRef: v.a.VolumeRef, RunID: v.a.RunID, SnapshotID: snap.ID,\n" +
			"\t\tEcosystem: ecosystem, Packages: pkgs, ObservedAt: observed,\n" +
			"\t})\n" +
			"\tif err != nil {\n" +
			"\t\treturn fmt.Errorf(\"recordKnown: %w\", err)\n" +
			"\t}\n" +
			"\tcveGap := pkginventory.CVEGap(ecosystem, pkginventory.HasSourceNames(pkgs), v.w.advisory, v.w.clock())\n" +
			"\tres := diskscan.VolumeResult{\n" +
			"\t\tSnapshotID: snap.ID, SnapshotSource: source, Encrypted: snap.Encrypted, InventoryKnown: true,\n" +
			"\t\tCVEMatchableKnown: cveGap == \"\", PackageCount: len(pkgs), ObservedAt: observed,\n" +
			"\t}\n" +
			"\tif err := v.record(ctx, res); err != nil {\n" +
			"\t\treturn fmt.Errorf(\"recordKnown: %w\", err)\n" +
			"\t}\n",
		New: "\tcveGap := pkginventory.CVEGap(ecosystem, pkginventory.HasSourceNames(pkgs), v.w.advisory, v.w.clock())\n" +
			"\tres := diskscan.VolumeResult{\n" +
			"\t\tSnapshotID: snap.ID, SnapshotSource: source, Encrypted: snap.Encrypted, InventoryKnown: true,\n" +
			"\t\tCVEMatchableKnown: cveGap == \"\", PackageCount: len(pkgs), ObservedAt: observed,\n" +
			"\t}\n" +
			"\tif err := v.record(ctx, res); err != nil {\n" +
			"\t\treturn fmt.Errorf(\"recordKnown: %w\", err)\n" +
			"\t}\n" +
			"\terr := v.w.svc.RecordPackages(ctx, diskscan.PackageSet{\n" +
			"\t\tAssetID: v.a.AssetID, VolumeRef: v.a.VolumeRef, RunID: v.a.RunID, SnapshotID: snap.ID,\n" +
			"\t\tEcosystem: ecosystem, Packages: pkgs, ObservedAt: observed,\n" +
			"\t})\n" +
			"\tif err != nil {\n" +
			"\t\treturn fmt.Errorf(\"recordKnown: %w\", err)\n" +
			"\t}\n",
		Why: "the result that says the inventory is known is stored before the packages it vouches for, so a crash " +
			"between the two leaves a known inventory with no packages",
	},
	{
		Guard: "TestSweep_DeletesOnlyExpiredTaggedSnapshots", Pkg: "./internal/jobs",
		File: "internal/jobs/diskscan_sweep.go",
		Old:  "\t\tif !snap.Ephemeral || snap.CreatedAt.IsZero()",
		New:  "\t\tif snap.CreatedAt.IsZero()",
		Why:  "the sweep deletes an old snapshot without the Vulngraph tag, so it removes a customer's own backup",
	},
	{
		Guard: "TestOverlay_Precedence", Pkg: "./internal/jobs",
		File: "internal/jobs/sync_diskscan.go",
		Old:  "\tif asset.PackageInventoryKnown(meta) && !best.ObservedAt.UTC().Truncate(24*time.Hour).After(observedOn(meta)) {\n",
		New:  "\tif false {\n",
		Why: "a disk inventory older than the one the agent or SSM already recorded overwrites it, so fresher " +
			"package evidence is replaced by staler",
	},
	{
		Guard: "TestScannerGrantsNameRealObjects",
		Pkg:   "./internal/migrate",
		File:  "internal/migrate/scanner.go",
		Old:   "\t\"GRANT SELECT ON disk_scan_connector_modes TO \" + ScannerRole,\n",
		New:   "\t\"GRANT SELECT ON disk_scan_connector_modes, connectors TO \" + ScannerRole,\n",
		Why:   "The disk reader needs its connector-mode view, without access to connector credentials.",
	},
	{
		Guard: "TestByoaCannotMarkClean", Pkg: "./internal/app/pkginv",
		File: "internal/app/pkginv/verdict.go",
		Old:  "\tcase !s.Complete:\n",
		New:  "\tcase false:\n",
		Why: "a bring-your-own-agent submission that says complete=false is believed anyway, so a partial package " +
			"list reads as a full inventory",
	},
	{
		Guard: "TestByoaCannotMarkClean", Pkg: "./internal/app/pkginv",
		File: "internal/app/pkginv/verdict.go",
		Old:  "\tcase now.Sub(s.ObservedAt) > FreshFor:\n",
		New:  "\tcase false:\n",
		Why: "a month-old capture is believed as current, so a source that stopped reporting still reads as a " +
			"clean inventory",
	},
	{
		Guard: "TestDecodeRequest", Pkg: "./internal/app/pkginv",
		File: "internal/app/pkginv/validate.go",
		Old: "\tvar req Request\n" +
			"\tif err := dec.Decode(&req); err != nil {\n",
		New: "\treq := Request{Complete: true}\n" +
			"\tif err := dec.Decode(&req); err != nil {\n",
		Why: "an omitted complete field defaults to true, so a submission that never claimed completeness is " +
			"treated as a complete inventory",
	},
	{
		Guard: "TestLatest", Pkg: "./internal/app/pkginv",
		File: "internal/app/pkginv/service.go",
		Old:  "\t\tif r.InventoryKnown && now.Sub(r.ObservedAt) > FreshFor {\n",
		New:  "\t\tif r.InventoryKnown && now.Sub(r.ObservedAt) > 1000*FreshFor {\n",
		Why: "a stored known inventory never ages into a stale gap, so an agent that stops reporting keeps its VM " +
			"reading as clean",
	},
	{
		Guard: "TestPackageInventory_WrongScope_403", Pkg: "./internal/app/pkginv",
		File: "internal/app/pkginv/domain.go",
		Old:  "\treturn p.KeyID != \"\" && p.Scope == scopeInventory && p.OwnerRole == roleAdmin\n",
		New:  "\treturn p.KeyID != \"\" && p.OwnerRole == roleAdmin\n",
		Why: "an API key of any scope may submit package inventory, so a read-only key can rewrite what the graph " +
			"believes is installed",
	},
	{
		Guard: "TestPackageInventory_WrongScope_403", Pkg: "./internal/app/pkginv",
		File: "internal/app/pkginv/domain.go",
		Old:  "\treturn p.KeyID != \"\" && p.Scope == scopeInventory && p.OwnerRole == roleAdmin\n",
		New:  "\treturn p.KeyID != \"\" && p.Scope == scopeInventory\n",
		Why: "an inventory key whose owner was demoted from admin still submits, so demoting the owner does not " +
			"switch the key off",
	},
}

// exempt names discovered guards that are deliberately NOT mutation-verified,
// each with the reason. An entry here is a decision, not a skip: it says why a
// mechanical mutation cannot express this guard's bug, or why the function the
// discovery rule flagged is not a structural guard at all.
//
// Keep it truthful. A harness claiming full coverage while actually testing
// half is the same class of lie as the guards it audits.
var exempt = map[string]string{
	"TestConnectorSyncThroughput": "reads measured API fixture JSON to exercise real storage, not repository source; behavioral database test",
	// Asserts go.mod text. The only mutation that would make it fail is deleting
	// the ldapserver replace, which changes module resolution for the whole build
	// (go.sum carries no hash for the upstream GPL module), so the harness would
	// see a build failure, not the guard failing — a mutation can't isolate it.

	// The field this guard's mutation used to reintroduce (forget.Sweep.Partial)
	// was deleted entirely, so the regression is now structurally impossible
	// rather than merely checked — a stronger guarantee than the mutation gave.
	"TestEvaluateForget_DropsDeliveryMismatchNotConnectorPartial": "the field the mutation reintroduced (forget.Sweep.Partial) was deleted — the regression is now impossible to construct, not just checked",

	// cmd/coverage-gen behavioural tests. They read a file because the command
	// writes one; nothing about the repository's own source is derived from it.
	"TestRunOfflineWritesTheDerivableDocument":             "reads back the document coverage-gen just wrote — a behavioural test of offline mode, not a structural invariant over the tree",
	"TestRunFallsBackToOfflineWhenClickHouseIsUnreachable": "reads back the document coverage-gen just wrote — proves the degrade path, and its failure mode is a hard error rather than a silent wrong answer",

	// Not structural guards — the discovery rule flags them because they parse
	// or read files, which is what they are testing.
	"TestGoroutineGuardedForms":                    "unit test of the guard's own accept/reject predicate — it is what makes the ratchet meaningful, and it is already exhaustive",
	"TestStatementUsesFindsEveryForm":              "unit test of TestClickHouseAppGrantsMatchTheCode's statement scan, table-driven over each form it must find and each prose it must not",
	"TestSafego_RecoversPanicAndKeepsProcessAlive": "behavioural test of safego itself, not a repo-wide invariant",
	"TestSafego_RunsFn":                            "behavioural test of safego itself",
	"TestEmbeddedMigrationsAreWellFormed":          "walks the embedded migration FS; a mutation means committing a malformed migration, which the goose provider would reject at a layer below this guard",

	// This harness's own tests. Auditing the auditor with the auditor is a
	// circle; TestHarnessDetectsANonBitingGuard is the proof instead — it runs
	// the driver against a fixture module containing one real guard and one
	// deliberately toothless one and requires the two verdicts to differ.
	"TestGuardsBite":                    "the driver itself; proven by TestHarnessDetectsANonBitingGuard",
	"TestHarnessDetectsANonBitingGuard": "the harness's self-test — it IS the proof that the driver distinguishes a biting guard from a toothless one",
	"TestEveryMutationTargetsRealText":  "read-only catalogue check; its own failure mode (a rotted Old string) is what it reports, and it runs on every commit",

	// Found by the package-wide helper walk, but not structural guards: they
	// read a testdata fixture or a snapshot, or are this harness's own checks.
	"TestCollect_NodePostureOnClusterAsset":     "reads a testdata node-posture fixture; a behavioural test of the collector",
	"TestKubeletSettings_ConfigDirDropIns":      "reads a testdata kubeadm fixture; a behavioural test of kubelet setting resolution",
	"TestKubeletSettings_FlagsOverrideConfig":   "reads a testdata kubeadm fixture; a behavioural test of kubelet setting resolution",
	"TestHits_UbuntuNotice":                     "reads a recorded OSV advisory fixture; a behavioural test of Hits",
	"TestHTTPClientConstructions":               "parses inline source strings, not the tree; the table test of the detector TestNoHTTPClientConstructedOutsideSafenet runs, which carries the mutation",
	"TestCatalogueHasNoStaleEntries":            "read-only catalogue check of this harness; its failure mode (a stale row) is what it reports",
	"TestEveryDiscoveredGuardIsMutatedOrExempt": "the inventory check itself; it is what makes this catalogue demand a decision for every guard",
	"TestServerRouting_AllWritesRequireAdmin":   "integration-tagged (needs Postgres), and the harness runs untagged; the router parse it shares is mutated through TestAdminGatedRoutes_ParsesTheRouter",

	// Structural, but the bug cannot be reintroduced by a text substitution.
	"TestOptimizeAgainstRealTableShapes":       "asserts policy against realistic TableStats fixtures; the mutation is a change of belief about table shapes, not of source text",
	"TestEveryTableEventuallyGoesFirst":        "the bug is a rotate() that does not rotate; every single-token mutation of rotate either fails to compile or is caught by TestRotate first, so this guard cannot be isolated",
	"TestLiveAssetIDsAppliesEphemeralLiveness": "asserts one query embeds the shared const; the mutation (inlining a copy of the arithmetic) is a multi-line rewrite of a const this harness would have to reproduce verbatim to restore — covered in spirit by the TestEphemeralLivenessArithmetic row",
}

// extraGuards are structural guards the mechanical discovery rule cannot see,
// because they iterate a production registry rather than reading source. The
// list is ADDITIVE ONLY: it can make the inventory check demand more, never
// less, so a wrong entry here is a false alarm rather than a silent gap.
//
// It is hand-maintained, and that is this harness's known weak spot: a new
// registry-iterating guard is invisible to the inventory check until someone
// adds it. Mechanical discovery covers a guard whose marker call (see
// structuralMarkers) is reachable from it through same-package test helpers;
// a guard that reads source only through another package's function
// (keyscan.Scan) is invisible to it too and belongs here.
var extraGuards = []string{
	"TestRegistryConsistency",
	"TestReachAndInheritTypesAreCritical",
	// Iterates graphschema.EdgeTypes to check the BFS adjacency index against the
	// declared risk direction of every edge type, so mechanical discovery cannot
	// see it.
	"TestBuildAdjIndexHonoursRegistryDirections",
	"TestRegistryDerivationsMatchLegacy",
	// The label-promotion class guard and the guard on its input. Both iterate
	// registries (producerEdges, graphschema.EdgeTypes) rather than parsing
	// source, so mechanical discovery cannot see them.
	"TestProducerEdgeLabelsMatchRelTables",
	"TestProducerEdgesCoverEveryLoadedEdgeType",
	"TestEachPodOnlyConsumesQueuesItCanWork",
	"TestEveryKindIsConsumedBySomePod",
	"TestEveryJobRoutesToARegisteredQueue",
	"TestEveryQueueDeclaresItsConcurrency",
	"TestHeavyScanLanesAreSerial",
	"TestHygieneCeilingChecksAreRegistered",
	// Iterates hand-written row tables of real checks, not a production
	// registry, but its rows call production predicates no source scan reaches.
	"TestChecksNeverFireOnAbsentData",
	"TestNoCheckFiresOnEmptyMetadata",
	// Iterates the periodic job registry (buildPeriodicJobs).
	"TestEveryPeriodicIsASingleton",
	"TestUnresolvedComparandsHaveTableProbes",
	"TestEphemeralTypesMatchTheLivenessCondition",
	"TestEphemeralLivenessArithmetic",
	"TestOptimizableTablesAreKnownReplacingMergeTrees",
	"TestLogicVersionDrivesTheFingerprintPrefix",
	"TestLineageStagesReferenceTheRegistries",
	"TestScoringSeedsAreRegisteredNonReachTypes",
	// The load-digest gate's skip index (amended): iterates
	// bfsScoreLabels/nodeCSVCols rather than parsing source, so mechanical
	// discovery cannot see it.
	"TestRiskScoreColIdxMatchesLoader",
	// Iterates rpmDBPaths: every path is both classified for the layer walker
	// and read by InventoryPackages.
	"TestEveryRPMDBPathIsRead",
}
