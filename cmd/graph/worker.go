package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/app/kevwatch"
	"github.com/vulngraph/vulngraph/internal/app/llmusage"
	"github.com/vulngraph/vulngraph/internal/app/mcp"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/savedquery"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/internal/checks"
	collectgithub "github.com/vulngraph/vulngraph/internal/collect/github"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/intel/epss"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/internal/policy"
	"github.com/vulngraph/vulngraph/internal/reason"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// assetStaleMargin is how far behind a provider's own collection high-water
// mark an asset's last_seen must fall before it counts as stale for the
// graph_asset_stale gauge. Long enough that a few missed collection cycles
// do not register, short enough that a broken collector shows up within days.
const assetStaleMargin = 10 * 24 * time.Hour

// worker runs the River background workers: the periodic reconciliation sweep
// and the per-connector sync worker.
func worker(ctx context.Context, getenv func(string) string) error {
	if err := waitForMigrations(ctx, migrateStatus(getenv), migrationWaitMinBackoff, migrationWaitMaxBackoff); err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	pool, err := db.NewPool(ctx, pgDSN(getenv), int32(envInt(getenv, "PG_MAX_CONNS_WORKER", db.MaxConnsWorker)))
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	defer pool.Close()

	ch, err := db.NewCH(ctx, chDSN(getenv), envInt(getenv, "CH_MAX_CONCURRENT", 0))
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	defer func() { _ = ch.Close() }()

	cipher, err := newCipher(getenv)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	// nil when no LLM provider is configured; reasoning calls then fail with a
	// clear "not configured" error and CT triage falls back to heuristics.
	llmClient, err := newLLMClient(ctx, getenv)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	// Every consumer gets the client through llmUsage.Client with its purpose:
	// background calls are refused once the monthly budget is spent or the
	// ledger is unreadable (ADR 085 §7).
	llmUsage, err := newLLMUsage(ctx, pool, getenv)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	// Observability, off unless env-gated: OTLP tracing when
	// OTEL_EXPORTER_OTLP_ENDPOINT is set, /metrics when METRICS_PORT is set.
	shutdownTracing, err := obs.InitTracing(ctx, getenv, "worker")
	if err != nil {
		return fmt.Errorf("worker: tracing: %w", err)
	}
	defer func() { _ = shutdownTracing(context.Background()) }()
	metrics := obs.New()
	connectorSvc := connector.NewService(connector.NewPGRepo(pool), cipher).WithOrgDiscoverer(newAWSOrgDiscoverer())

	// liveAWS makes real-time AWS API calls (IAM GetRole, …) using a connector's
	// stored credentials. Mirrors the identical construction in serve.go (shared
	// with MCP/chat) — the worker pod needs its own instance for VerifyCIRoleWorker.
	liveAWS := mcp.NewLiveAWSCaller(mcp.NewConnectorServiceAdapter(
		func(ctx context.Context, id string) (map[string]string, error) {
			c, err := connectorSvc.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			return c.Config, nil
		},
	))

	assetRepo := asset.NewCHRepo(ch)
	assetSvc := asset.NewService(assetRepo).WithDeletionProofs(connectorSvc)

	// Which default-on outbound feeds this pod runs; logs once what is off. The
	// VM collectors read it too: a VM on a distribution whose advisory feed is off
	// is stamped package_cve_gap=advisory_source_disabled.
	feeds, err := intelFeeds(ctx, getenv)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	takeoverHTTP, err := takeoverProbeHTTP(ctx, getenv) // nil (source off) under TAKEOVER_PROBE_DISABLED / OFFLINE_MODE
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	registry := newCollectRegistry(feeds)
	// TF-state ingest needs live S3 reads scoped to a connector's
	// credentials, a per-bucket AWS account resolver, and the account→connector
	// lookup used elsewhere for CI-role verification — all already constructed
	// above for this pod. The bucket resolver looks up the s3_bucket asset (its
	// ID is the bucket name) and returns its own AccountID, so each Terraform
	// state bucket resolves to the account that actually owns it rather than a
	// single operator-configured account. Fetched back out of the registry
	// (rather than registered here directly) so newCollectRegistry stays the
	// one place that picks each connector type's collector.
	ghAny, err := registry.For(connector.TypeGitHub)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	ghCollector, ok := ghAny.(*collectgithub.Collector)
	if !ok {
		return fmt.Errorf("worker: registered GitHub collector is %T, not *github.Collector", ghAny)
	}
	ghCollector.SetTFStateAWS(liveAWS, func(ctx context.Context, bucket string) (string, bool, error) {
		assets, err := assetSvc.ByIDs(ctx, []string{bucket})
		if err != nil {
			return "", false, fmt.Errorf("tfstate bucket account lookup: %w", err)
		}
		if len(assets) == 0 || assets[0].AccountID == "" {
			return "", false, nil
		}
		return assets[0].AccountID, true, nil
	}, connectorSvc.ConnectorByAccountID)
	// A repo whose CODEOWNERS read fails this sweep keeps its stored rules:
	// the asset row is rewritten whole, so an absent key would erase them.
	ghCollector.SetPriorRepoMetadata(func(ctx context.Context, ids []string) (map[string]map[string]string, error) {
		assets, err := assetSvc.ByIDs(ctx, ids)
		if err != nil {
			return nil, fmt.Errorf("prior repo metadata: %w", err)
		}
		out := make(map[string]map[string]string, len(assets))
		for _, a := range assets {
			if a.Type == "github_repo" || a.Type == "github_visibility_snapshot" {
				out[a.ID] = a.Metadata
			}
		}
		return out, nil
	})

	findingSvc := finding.NewService(finding.NewCHRepo(ch)).WithResolveObserver(enrichcache.NewService(enrichcache.NewPGRepo(pool)))

	// Open the ladybug embedded graph engine. nil = disabled (LADYBUG_INTERNAL_PORT unset).
	// defer Close ensures the WAL is checkpointed on clean shutdown, preventing
	// data corruption on the PVC across pod restarts.
	graphDB, err := openGraphDB(getenv)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	if graphDB != nil {
		defer graphDB.Close()
		graphDB.WithPackageInventory(explore.NewCHRepo(ch).WithDeletionVerifier(assetSvc), assetSvc)
	}
	if msg := workerGraphOffWarning(getenv); msg != "" {
		log.FromContext(ctx).Warn().Msg(msg)
	}

	registerMetricsSources(metrics, pool, graphDB, connectorSvc, assetSvc, findingSvc, getenv)
	memorySvc := memory.NewService(memory.NewPGRepo(pool))
	// The worker only reads suppression state (enrich consults it), but wire the
	// audit sink anyway so no future worker-side write can be the one that is
	// silently untraced.
	suppressSvc := suppress.NewService(suppress.NewPGRepo(pool)).WithAudit(suppress.NewCHAuditRepo(ch))
	// EPSS exploit-probability catalog: an in-memory cache refreshed by the
	// periodic EPSS job and read by the enrich EPSS source. With the feed off it
	// stays empty and the EPSS source contributes no factor.
	epssCache := epss.NewCache()

	// The enrichment source registry — the single place new intelligence domains
	// (identity, drift, attack paths, supply chain, …) are added: implement
	// enrich.Source and append it here.
	//
	// Blast radius: ladybug (single Cypher traversal) as primary, CH BFS as
	// fallback when ladybug is unavailable.
	blastSource := enrich.BlastRadius{Provider: assetSvc}
	// Shared DNS resolver for the takeover-corroboration sources: both
	// DNSTakeover and TakeoverProbe use it so TakeoverProbe can corroborate its own
	// HTTP-layer "live and owned" finding against the DNS-layer "target resolves"
	// fact before demoting a refuted candidate — a single source's evidence alone
	// must never demote (see sources_takeover_probe.go).
	takeoverResolver := enrich.NewNetResolver(3 * time.Second)
	var respondBlast respond.BlastRadiusProvider = assetSvc
	// Peer findings for AttackPaths + ToxicCombo: ladybug node signals when available
	// (pre-computed privesc_count + exposed = zero CH reads), CH otherwise.
	var peerFindings enrich.ResourceFindings = findingSvc
	// SupplyChainExposure: ladybug Neighbors replaces 2 sequential CH edge hops
	// (deploys_to + exposed_to_internet) when ladybug is available.
	var supplyChainLadybug enrich.LadybugDeployGraph
	// Reach provider for the must-fix reachability signal: reads the
	// transitive internet_hops node signal from Ladybug. Nil when Ladybug is off → the
	// InternetReach source and must-fix classifier no-op (fail-open).
	var reachProvider enrich.ReachProvider
	if graphDB != nil {
		blastSource.Counter = graphDB // ladybug primary for scoring (single count query)
		respondBlast = &ladybugBlastProvider{graph: graphDB, assets: assetSvc}
		peerFindings = &ladybugPeerFindings{graph: graphDB, fallback: findingSvc}
		supplyChainLadybug = &ladybugDeployGraph{graph: graphDB}
		reachProvider = &ladybugGraphCtx{graph: graphDB} // only InternetHops is used
	}
	// supplyChainExposure is registered both as a scoring Source (below) and as
	// the must-fix classifier's SupplyChainReachProvider (WithSupplyChainReach):
	// package purl → dependent repos → deploys_to → internet exposure. One
	// instance, one traversal — scoring and must-fix classification read the
	// exact same package↔deployment lineage, so they can never disagree about
	// what "reachable" means for a supply-chain finding. Fleets lets it defer a
	// VM-only package to its per-fleet vm_vuln findings (one finding per host fleet).
	supplyChainExposure := enrich.SupplyChainExposure{Graph: assetSvc, Ladybug: supplyChainLadybug, Fleets: findingSvc, Reach: reachProvider}

	// SSO-graph resolver: grounds the compensating-control decision so an
	// SSO permission set that grants admin is not demoted as "SSO-gated". Shared by
	// IdentityHygiene (un-suppress) and the must-fix isControlled check.
	ssoResolver := &enrich.AssetSSOResolver{Lister: assetSvc}
	enrichSvc := enrich.NewService(findingSvc, enrich.NewSignalCHRepo(ch), []enrich.Source{
		enrich.BaseSeverity{},
		enrich.ExposureType{},                      // medium exposure findings boosted to the high band
		enrich.CriticalFloor{},                     // context-independent criticals (root access key) → page band floor
		enrich.ThreatFloor{Findings: peerFindings}, // GuardDuty/SCC active-threat findings → actionable/page (not buried in monitor); corroborated DNS-observation hits escalate too
		enrich.SignalFloor{},                       // secrets/web-vulns/IaC on edge-less resource types → out of monitor
		enrich.HygieneCeiling{},                    // IAM hygiene/optimization advisories (right-size, rotate, disable-if-unused) capped below page band
		enrich.KEV{},
		enrich.RootCauseKEV{}, // a base-image root cause pages for the KEV members it carries (their own alerts are suppressed)
		blastSource,
		enrich.TeamHistory{Provider: memorySvc},    // decaying-memory model
		enrich.AttackPaths{Findings: peerFindings}, // ladybug signals: zero CH when ladybug on
		enrich.ToxicCombo{Findings: peerFindings, Reach: reachProvider}, // + transitive reachability
		&enrich.CrossCluster{Findings: findingSvc},
		supplyChainExposure,            // ladybug: 1 call vs 3 CH hops
		enrich.EPSS{Scores: epssCache}, // exploit probability
		enrich.PrincipalClass{},        // human/non-production naming hints; role names never establish a control
		// Must-fix prioritization sources: actually-reachable promotion +
		// unreachable/compensating-control/age demotion — evidence-backed urgency.
		enrich.InternetReach{Reach: reachProvider},
		enrich.IdentityHygiene{Assets: assetSvc, Edges: assetSvc, SSO: ssoResolver},
		enrich.FindingAge{},
		// DNS-resolution source: confirms dangling subdomain-takeover
		// candidates by resolving the CNAME target (NXDOMAIN → real takeover risk).
		enrich.DNSTakeover{Assets: assetSvc, Resolver: takeoverResolver},
		// HTTP-fingerprint source: confirms the resolves-but-unclaimed
		// takeover case via a safenet (SSRF-blocked) probe for unclaimed-service
		// fingerprints.
		enrich.TakeoverProbe{
			Assets:   assetSvc,
			HTTP:     takeoverHTTP,
			Resolver: takeoverResolver,
		},
	},
		// Structural "safe to fix" signal on every enriched finding (no LLM): the
		// graph seams that answer "what depends on this / is it used / where is it
		// fixed" (see internal/app/enrich/safety.go).
		enrich.WithSafetyProvider(assetSvc),
		// Evidence-backed must-fix tier: reachability (Ladybug internet_hops) + blast
		// counter it weighs. Nil reachProvider (Ladybug off) → no-op. Wires the whole
		// blastSource (Ladybug-primary/ClickHouse-fallback), not its bare Ladybug
		// Counter — must-fix then measures blast radius through the exact same
		// traversal scoring uses, instead of going unmeasured whenever Ladybug alone
		// is down while scoring still has a working fallback.
		enrich.WithMustFixProviders(reachProvider, blastSource),
		// Must-fix for supply-chain package findings (a coverage gap): a
		// package purl is never an asset.Assets row, so the reach/blast lookups
		// above never resolve for supply_chain/package findings — they sat with
		// must_fix_class blank, even when already scored into the page band. Reuses supplyChainExposure's own
		// package→repo→deploy→exposure traversal instead of a second mechanism.
		enrich.WithSupplyChainReach(supplyChainExposure),
		// Must-fix for Kubernetes RBAC findings (a coverage gap): a Role is
		// not a graph node, so internet-hops and blast-radius never resolve for it
		// and open RBAC findings — including crit/high cluster-admin bindings —
		// sat with a blank must_fix_class. Scores on who
		// actually holds the grant, resolved over the `binds` edges.
		enrich.WithRBACBindings(assetSvc),
		// Grounded true-severity belief on every enrich.
		enrich.WithBeliefFormer(beliefFormer{svc: belief.NewService(belief.NewCHRepo(ch))}),
		// SSO grounding for the must-fix compensating-control decision.
		enrich.WithSSOResolver(ssoResolver),
		// Routing context (ADR 089): the finding's owner (tag → defined_in /
		// CODEOWNERS → unowned) and environment, stamped beside the score.
		enrich.WithOwnerResolver(assetSvc, ownerTagKeys(getenv)),
		enrich.WithPackageRunners(assetSvc), // a package finding (a purl) routes to what runs it
		// Per-finding scoring-consistency safety net: enforced (not shadow),
		// reporting each repaired invariant to the obs counter. Steady state is
		// zero violations — a nonzero rate means a bad reach signal is still
		// reaching enrich despite the source-level fixes.
		enrich.WithConsistencyGate(true, false, metrics.ObserveConsistencyViolation),
	)

	// reasonCache and respondAudit are shared between respond.Service and
	// govern.Service below — the reasoning cache is both respond's
	// gate/escalation-hotspot repeat counter AND govern's Pending source, and the audit
	// sink is both respond's and govern's Audit trail. One instance each, not
	// a second pool-backed repo per consumer.
	reasonCache := reasoncache.NewService(reasoncache.NewPGRepo(pool))
	respondAudit := respond.NewCHRepo(ch)

	// govern.Service (not just PGRepo) is constructed here purely for its
	// PatternVerdict lookup — see the WithPatternVerdicts wiring below. Every
	// dependency it needs (findingSvc, memorySvc, reasonCache, respondAudit)
	// already exists in the worker for other wiring, so building the real
	// service costs nothing extra and means a policy later added at the
	// service layer (e.g. an expiry or scope rule ahead of the PGRepo read)
	// actually reaches the worker instead of being silently bypassed by a
	// direct repo call.
	governRepo := govern.NewPGRepo(pool)
	governSvc := govern.NewService(governRepo, reasonCache, findingSvc, memorySvc, respondAudit).
		WithPatterns(governRepo)

	signalRepo := enrich.NewSignalCHRepo(ch)
	respondSvc := respond.NewService(
		reason.New(llmUsage.Client(llmClient, llmusage.PurposeReason), getenv("REASON_MODEL")),
		policy.Gate{}, memorySvc, respondBlast, respondAudit,
		reasonCache,
		findingSvc,
		assetSvc, // lineage: deploys_to / depends_on edges into a resource
	).WithFactors(signalRepo). // per-source score breakdown → reason prompt
					WithEPSS(epssCache).             // live EPSS probability for CVE findings
					WithOutEdger(assetSvc).          // identity chain + supply-chain blast path
					WithReasonCacheMetrics(metrics). // planFor cache hit/miss
		// executor.HasExecutableAction is the single source of truth for what
		// can actually run (respond never imports executor
		// directly): annotates remediate/modify plans with no wired action
		// for the resource type, so a human knows to carry them by hand.
		WithExecutorCapability(respond.ActionApplicabilityFunc(executor.HasExecutableAction)).
		// Repeat counter: the reasoning cache also tracks repeats (the
		// repeat-decision skip is never itself audited, so the
		// escalation-hotspot panel reads this counter instead of the audit
		// trail).
		WithRepeatTracker(reasonCache).
		// govern already imports respond (for respond.AuditEvent), so respond
		// cannot import govern back without cycling — this closure
		// converts govern.Verdict to the plain string respond.PatternVerdicts
		// expects, keeping respond free of the govern import.
		WithPatternVerdicts(respond.PatternVerdictsFunc(func(ctx context.Context, checkID, actionClass, resourceType string) (string, time.Time, bool, error) {
			v, decidedAt, found, err := governSvc.PatternVerdict(ctx, checkID, actionClass, resourceType)
			return string(v), decidedAt, found, err
		}))

	// Outbound alerting hub (Slack, …). Reuses the connector cipher to decrypt
	// channel secrets. Nil-safe: with no channels configured, Dispatch is a no-op.
	notifySvc := notify.NewService(notify.NewPGRepo(pool, cipher)).WithMetrics(metrics)

	// Saved-query detection-as-code: scheduled Cypher queries that alert (via
	// notify) when their result set changes. The worker holds the Ladybug primary,
	// so it executes the queries directly. Nil graph = no runner (CRUD-only in serve).
	savedQuerySvc := savedquery.NewService(savedquery.NewPGRepo(pool)).
		WithAlerter(savedQueryAlerter{notify: notifySvc})
	if graphDB != nil {
		savedQuerySvc = savedQuerySvc.
			WithRunner(savedQueryCypherAdapter{runner: graphDB}).
			// Skip scheduled detection runs while the graph is rebuilding/empty so a
			// deploy never fires a false "drift detected" alert (empty→full hash flip).
			WithReadiness(graphDB.Ready)
	}

	notifiers, err := decisionNotifiers(ctx, getenv, notifySvc)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	respondSvc.WithDecisionWebhook(notifiers)

	// Named so its PendingLiveVerify() output (unmatched AWS CI-workflow targets)
	// can be read by the correlate worker after each sweep and handed to
	// verify_ci_role — see jobs.Deps.CIAccessPending below.
	ciAccessRule := &correlate.CIAccess{}

	// The correlation rule registry — the single place new cross-asset
	// relationship families are added: implement correlate.Rule and append it.
	correlateSvc := correlate.NewService(correlate.NewCHRepo(ch), assetSvc, []correlate.Rule{
		correlate.DNSPointsTo{},
		correlate.IAMCanAssume{},
		correlate.GCPImpersonation{},   // gcp_service_account -[can_assume]-> gcp_service_account (impersonation/act-as)
		correlate.EC2InstanceProfile{}, // ec2_instance -[has_role]-> iam_role
		correlate.ExecutesAs{},         // lambda/gce/… -[executes_as]-> role/SA
		correlate.DeploysTo{},
		correlate.K8sManifestOwnership{}, // live k8s asset -[defined_in]-> repo (IaC ownership)
		correlate.TFOwnership{},          // live asset -[defined_in]-> repo (Terraform-state ownership, high confidence)
		// Generic, config-free counterpart to the two ownership rules above: joins
		// identities harvested verbatim from ANY repo file to the live identity of
		// the same ID, so a new org/repo/tool needs no configuration and no parser.
		correlate.DeclaredIdentityOwnership{},
		// container_image -[defined_in]-> repo. When an image carries no OCI
		// source/revision labels and its registry holds no build provenance, the
		// repo naming the image it pushes is the only link back to source.
		correlate.ImageOwnership{},
		correlate.SecurityGroupAllows{},
		correlate.SharedSecurityGroup{},
		correlate.GCPFirewallApplies{},
		correlate.GCPFirewallReachability{}, // gce_instance -[sg_allows_from]-> gce_instance (tag-based intra-VPC ingress)
		correlate.K8sServiceTargets{},
		correlate.InternetReachability{},
		correlate.FederationTrust{},     // GitHub OIDC → AWS IAM role (Repo -[FederatedAccess]-> IamRole)
		correlate.GCPWorkloadIdentity{}, // GKE WIF: k8s_service_account -[federated_access]-> gcp_service_account
		correlate.IRSATrust{},           // EKS IRSA: k8s_service_account -[federated_access]-> iam_role
		// k8s_pod -[executes_as]-> k8s_service_account. Both rules above depend on
		// this hop: without it an exposed pod reaches neither
		// the RBAC its ServiceAccount binds nor the cloud role that SA federates into.
		correlate.K8sPodServiceAccount{},
		ciAccessRule,                        // GH workflow declared role/SA -[federated_access]-> live iam_role/gcp_service_account
		correlate.IAMEffectivePermissions{}, // IamRole -[AllowsAction]-> IamPolicy (dangerous permission detection)
		correlate.SecretAccess{},            // IamRole -[accesses_secret]-> Secrets Manager / SSM secret
		correlate.DataClassification{},      // Asset -[ContainsData]-> DataClass (DSPM heuristic bootstrap)
		correlate.HumanIdentityFederation{}, // HumanIdentity -[Owns]-> Repo, -[FederatedAccess]-> IamRole
	}).WithViewMetrics(metrics)

	// Image-vuln scanner — gives container_image assets a CVE axis so an
	// exposed pod running a KEV image CVE can reach must_fix. CVE matching
	// reuses the OSV feed. On by default via the registry-pull source.
	imageVulnScanner, err := imageVulnSource(ctx, getenv, feeds, connectorSvc)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}
	scanWorkerOff, err := jobs.SwitchFromEnv(getenv, jobs.ScanWorkerDisabledEnv)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	// Replacement bases the base-image root-cause findings propose (ADR 088).
	// BASE_IMAGE_CATALOGUE names an operator JSON catalogue whose entries lead
	// the vendor-neutral defaults; a configured file that does not load stops
	// the worker rather than silently proposing only the defaults.
	baseCatalogue, err := imagevuln.LoadCatalogue(getenv("BASE_IMAGE_CATALOGUE"))
	if err != nil {
		return fmt.Errorf("worker: BASE_IMAGE_CATALOGUE: %w", err)
	}

	// Belief-grounded severity adjudicator: dark unless ADJUDICATOR_ENABLED.
	adjudicator, err := severityAdjudicator(ctx, getenv, ch, llmUsage.Client(llmClient, llmusage.PurposeAdjudicate))
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	// Advisory drift analysis: dark unless DRIFT_ANALYSIS_ENABLED.
	driftAnalysis, err := driftAnalysisService(ctx, getenv, pool,
		llmUsage.Client(llmClient, llmusage.PurposeDriftAnalysis), findingSvc, assetSvc)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	// Agentless VM disk scanning: dark unless DISK_SCAN_ENABLED, and then each
	// connector still opts in.
	diskScan, err := workerDiskScan(ctx, getenv, pool, connectorSvc, feeds)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	// One instance, two roles: the per-finding change-gate cache and the
	// full-pass version watermark. Sharing it keeps a single view of enrichment's
	// Postgres state.
	enrichCacheSvc := enrichcache.NewService(enrichcache.NewPGRepo(pool))

	forgetSvc, err := forgetService(ctx, getenv, pool, assetRepo, graphDB, metrics)
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	client, err := jobs.NewClient(pool, jobs.Deps{
		Metrics:            metrics,
		ImageVuln:          imageVulnScanner,
		BaseImageCatalogue: baseCatalogue,
		Connectors:         connectorSvc,
		Registry:           registry,
		Assets:             assetSvc,
		Findings:           findingSvc,
		Checks:             checks.Default(),
		Enrich:             enrichSvc,
		EnrichCache:        enrichCacheSvc,
		AlertCarriers:      supplyChainExposure,
		FullPass:           enrichCacheSvc,
		EnrichMaxAge:       enrichMaxAge(getenv),
		Forget:             forgetSvc,
		Suppress:           suppressSvc,
		Respond:            respondSvc,
		// The outbound intel feeds: each is nil when switched off (worker_feeds.go).
		KEVFetcher:   kevFetcher(feeds),
		KEVAdditions: kevwatch.NewService(kevwatch.NewPGRepo(pool)),
		OSV:          osvQuerier(feeds),
		// GITHUB_MALFEED_TOKEN is optional — unauthenticated GitHub API calls
		// (60/hour) comfortably cover this job's steady-state hourly cost; a
		// token only buys headroom against a genuine multi-hundred-package
		// wave inside one hour, or other cluster processes sharing the egress
		// IP's rate limit. See osv.NewMalFeedClient's doc.
		MalFeed:                malFeedQuerier(feeds, getenv("GITHUB_MALFEED_TOKEN")),
		DistroAdvisories:       distroAdvisoryFetcher(feeds),
		DistroAdvisorySources:  feeds.DistroAdvisorySources(),
		EPSSFetcher:            epssFetcher(feeds),
		EPSSCache:              epssCache,
		SCC:                    sccFetcher(getenv),
		Correlate:              correlateSvc,
		ScanWorkerDisabled:     scanWorkerOff,
		SyncInterval:           parseDuration(getenv("SYNC_INTERVAL")),
		CorrelateInterval:      parseDuration(getenv("CORRELATE_INTERVAL")),
		EnrichInterval:         parseDuration(getenv("ENRICH_INTERVAL")),
		ExposedAssets:          assetSvc,
		ExposedFindings:        findingSvc,
		EnrichCacheInvalidator: enrichcache.NewService(enrichcache.NewPGRepo(pool)),
		GraphContext: func() jobs.GraphContextProvider {
			if graphDB != nil {
				return &ladybugGraphCtx{
					graph:            graphDB,
					assetsFallback:   assetSvc,
					findingsFallback: findingSvc,
				}
			}
			return &graphCtxSvc{assets: assetSvc, findings: findingSvc}
		}(),
		LadybugSync:    ladybugSyncFn(graphDB, assetSvc, findingSvc, ch, epssCache, metrics),
		TopologyBumper: topologyBumperFn(ch),
		Intel:          domainMonitor(feeds, pool, ch, llmUsage.Client(llmClient, llmusage.PurposeCTTriage)),
		Notify:         notifySvc,
		SavedQueries:   savedQuerySvc,
		Adjudicator:    adjudicator,
		DriftAnalysis:  driftAnalysis,
		DiskScan:       diskScan,
		// The advisory sources the collectors were built with, so the inventory
		// overlay judges CVE-matchability against the same ones.
		InventoryAdvisory: feeds.AdvisorySources(),
		// Reads only: Latest touches the repo, so no audit, limiter or asset reads.
		InventorySources: []jobs.InventorySource{jobs.NewBYOAInventorySource(
			pkginv.NewService(pkginv.NewPGRepo(pool), nil, nil, nil, nil, nil, feeds.AdvisorySources))},
		CIAccessPending: ciAccessRule,
		LiveAWS:         liveAWS,
	})
	if err != nil {
		return fmt.Errorf("worker: %w", err)
	}

	// Initial ladybug sync: load the graph before the River client starts so the
	// readiness probe can pass. Try the PVC snapshot first (fast) to avoid
	// a full ClickHouse read (slow on a large graph) on every pod restart.
	if graphDB != nil {
		signals := &graphSignalSource{findings: findingSvc, epss: epssCache}
		syncFn := ladybugSyncFn(graphDB, assetSvc, findingSvc, ch, epssCache, metrics)
		// Warm-start: load the last good snapshot. A restart then serves in seconds
		// instead of waiting for a cold ClickHouse rebuild. The snapshot may lag the
		// current topology, so we ALWAYS refresh in the background afterwards — and
		// the load seeds the digest gate, so that refresh skips the rebuild when
		// ClickHouse still matches the snapshot.
		snapErr := graphDB.LoadFromSnapshot(ctx, signals)
		if snapErr == nil {
			log.FromContext(ctx).Info().Msg("worker: ladybug warm-started from snapshot — refreshing to current topology in background")
			safego(ctx, "ladybug-refresh-after-warm-start", func() { refreshLadybugAfterWarmStart(ctx, syncFn) })
		} else {
			// No usable snapshot (first boot, corrupt, or schema bump): do the full
			// rebuild inline so the readiness probe has a graph to serve.
			log.FromContext(ctx).Info().Err(snapErr).Msg("worker: snapshot unavailable — loading from ClickHouse")
			if err := syncFn.Sync(ctx); err != nil {
				log.FromContext(ctx).Warn().Err(err).Msg("worker: initial ladybug sync failed — retrying in background")
			}
			if !graphDB.Ready() {
				safego(ctx, "ladybug-retry-sync", func() { retryLadybugSync(ctx, graphDB, syncFn) })
			}
		}
	}

	// One boot-time full sweep (unique, so a sibling replica's or the periodic's
	// is not duplicated). A correlate left 'running' by a crashed pod is not
	// cancelled here: from this pod it is indistinguishable from a live replica's
	// sweep, and River's rescuer retries it once it outlives its Timeout.
	if err := jobs.EnqueueBootCorrelate(ctx, client); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("worker: boot correlate enqueue failed")
	}

	// If enrichment semantics changed since the corpus was last fully processed,
	// enqueue exactly one bulk pass. Without this, a bumped enrichcache.LogicVersion
	// only invalidates the change-gate — it cannot re-enqueue findings whose assets
	// never change, which is most of them.
	jobs.TriggerFullPassIfVersionChanged(ctx, pool, enrichCacheSvc)

	if err := client.Start(ctx); err != nil {
		return fmt.Errorf("worker: start: %w", err)
	}
	log.FromContext(ctx).Info().Msg("graph worker started")

	// Coalesce partial-correlate enqueues from bursty sync completions into a
	// small number of CorrelateArgs jobs per correlateCoalesceInterval instead
	// of one per completion — see internal/jobs/correlate_coalescer.go.
	//
	// coalesceStop, NOT ctx, tells the loop to do its final flush and return —
	// see RunCorrelateCoalescer's doc for why. It is closed only after
	// client.Stop(stopCtx) has returned, i.e. after every in-flight job
	// (including one still finishing inside River's grace window that can
	// still call enqueuePartialCorrelate → Add) has completed. Closing it
	// earlier — in particular on ctx.Done(), which fires immediately at
	// SIGTERM — would let the loop return before those late Adds happen,
	// losing whatever they buffered.
	//
	// coalescerDone is closed once RunCorrelateCoalescer's final flush has run
	// (deferred ahead of safego's own recover, so it always fires); the
	// shutdown wait below on this channel makes sure the process does not
	// exit before that flush's Insert has gone out.
	coalesceStop := make(chan struct{})
	coalescerDone := make(chan struct{})
	safego(ctx, "correlate-coalescer", func() {
		defer close(coalescerDone)
		jobs.RunCorrelateCoalescer(ctx, coalesceStop, client)
	})

	// Log River queue depths every 60 s so we can see backlog build-up.
	safego(ctx, "river-queue-stats", func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jobs.LogQueueStats(ctx, pool)
			}
		}
	})

	// metrics listener — env-gated, pod-internal (like pprof / the ladybug RPC port,
	// never Ingress-reachable). Set METRICS_PORT to expose Prometheus /metrics.
	if metricsPort := getenv("METRICS_PORT"); metricsPort != "" {
		safego(ctx, "metrics-listener", func() {
			if err := metrics.ListenAndServe(ctx, ":"+metricsPort); err != nil {
				log.FromContext(ctx).Error().Err(err).Msg("worker: metrics listener exited")
			}
		})
	}

	// pprof listener — env-gated and bound to loopback only: profiles expose
	// memory contents and /debug/pprof/profile burns CPU on demand, so nothing
	// else in the cluster may reach it. Set PPROF_PORT to enable, then capture
	// profiles with kubectl port-forward + go tool pprof.
	if pprofPort := getenv("PPROF_PORT"); pprofPort != "" {
		safego(ctx, "pprof-listener", func() {
			srv := newPprofServer(pprofAddr(pprofPort))
			safego(ctx, "pprof-shutdown-watch", func() { <-ctx.Done(); _ = srv.Close() })
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.FromContext(ctx).Error().Err(err).Msg("worker: pprof server exited")
			}
		})
		log.FromContext(ctx).Info().Str("port", pprofPort).Msg("worker: pprof listening")
	}

	// Start the internal ladybug RPC server so the serve pod can query the graph.
	// This MUST run after client.Start so the worker is accepting jobs when
	// the first RPC arrives. The goroutine exits when ctx is cancelled.
	if graphDB != nil {
		rpcPort := envOr(getenv, "LADYBUG_INTERNAL_PORT", "8090")
		safego(ctx, "ladybug-internal-rpc", func() {
			h := graphstore.NewHandler(graphDB)
			if err := graphstore.StartInternalServer(ctx, h, ":"+rpcPort, getenv("LADYBUG_RPC_SECRET")); err != nil {
				log.FromContext(ctx).Error().Err(err).Msg("ladybug: internal RPC server exited")
			}
		})
	}

	<-ctx.Done()
	// client.Stop must run — and fully return — BEFORE the coalescer is told
	// to do its final flush. Stop itself already waits (up to
	// workerSoftStopTimeout) for every in-flight job to finish, including a
	// sync job still running in that grace window that calls
	// enqueuePartialCorrelate → Add on its way out. Signalling coalesceStop any
	// earlier would let the coalescer stop draining before those late Adds
	// happen, silently losing them. Only once Stop has returned is it safe to
	// say "no more Adds are coming" and let the coalescer perform its last drain.
	stopCtx, cancel := context.WithTimeout(context.Background(), jobs.WorkerStopTimeout)
	defer cancel()
	stopErr := client.Stop(stopCtx)
	close(coalesceStop)
	<-coalescerDone
	if stopErr != nil {
		return fmt.Errorf("worker: stop: %w", stopErr)
	}
	return nil
}

// ownerTagKeys is the owner tag list: OWNER_TAG_KEYS (comma-separated) consulted
// before asset.DefaultOwnerTagKeys. Serve and worker both read it, so the asset
// page and the enrich-stamped finding owner name the same team.
func ownerTagKeys(getenv func(string) string) []string {
	return asset.OwnerTagKeys(splitCSV(getenv("OWNER_TAG_KEYS")))
}
