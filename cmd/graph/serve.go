package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/alertctx"
	"github.com/vulngraph/vulngraph/internal/app/apikey"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/audit"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/chat"
	"github.com/vulngraph/vulngraph/internal/app/compliance"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/costdata"
	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/findingctx"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/app/identity"
	"github.com/vulngraph/vulngraph/internal/app/intel"
	"github.com/vulngraph/vulngraph/internal/app/kevwatch"
	"github.com/vulngraph/vulngraph/internal/app/llmusage"
	"github.com/vulngraph/vulngraph/internal/app/mcp"
	"github.com/vulngraph/vulngraph/internal/app/memory"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
	"github.com/vulngraph/vulngraph/internal/app/policy"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/savedquery"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/internal/app/webhook"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/httpsrv"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/migrate"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/internal/reason"
	nuclei "github.com/vulngraph/vulngraph/internal/scanner/nuclei"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// serveSignalSource adapts finding.Service to graphstore.SignalSource for the
// serve pod's local Ladybug replica. Mirrors graphSignalSource in worker.go but
// lives here to keep worker.go self-contained.
type serveSignalSource struct {
	findings interface {
		SignalsByResource(ctx context.Context) (map[string]finding.ResourceSignals, error)
	}
	// epss is optional: when non-nil, EPSSScore is populated for package nodes.
	epss interface {
		Score(cve string) (float64, bool)
	}
}

func (s *serveSignalSource) SignalsByResource(ctx context.Context) (map[string]graphstore.NodeSignals, error) {
	raw, err := s.findings.SignalsByResource(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]graphstore.NodeSignals, len(raw))
	for id, sig := range raw {
		// Base on NewNodeSignals so InternetHops defaults to ReachUnknown, not the
		// zero value 0 (= "directly internet-exposed"). The reach overlay in
		// prewarmSignalCache is the only code that assigns a real hop count.
		ns := graphstore.NewNodeSignals()
		ns.HasKEV = sig.HasKEV
		ns.Exploitable = sig.Exploitable
		ns.MaxScore = int(sig.MaxScore)
		ns.PrivescCount = sig.PrivescCount
		ns.CveID = sig.CveID
		if s.epss != nil && sig.CveID != "" {
			if score, ok := s.epss.Score(sig.CveID); ok {
				ns.EPSSScore = score
			}
		}
		out[id] = ns
	}
	return out, nil
}

// graphStatsSource picks the graph-engine stats source for /api/graph/{status,stats}
// and MCP get_graph_stats, mirroring the Cypher tiering: with both tiers, the
// tier that is serving (TieredStats); otherwise the one that exists. Both
// arguments may be nil, and the nil-ness MUST be checked on the concrete
// pointers here rather than by assigning straight into the interface result: a
// nil *graphstore.Service stored in an interface makes MCP's `stats != nil`
// registration guard pass, so the tool registers and then panics dereferencing
// the nil receiver on every call. Returning an untyped nil interface keeps the
// tool unregistered.
func graphStatsSource(serveLadybug *graphstore.Service, ladybugRepo *explore.LadybugRPCRepo) explore.NodeStatsProvider {
	switch {
	case serveLadybug != nil && ladybugRepo != nil:
		return explore.NewTieredStats(serveLadybug, ladybugRepo)
	case serveLadybug != nil:
		return serveLadybug
	case ladybugRepo != nil:
		return ladybugRepo
	default:
		return nil
	}
}

// serveLadybugLoop owns the serve pod's local Ladybug replica lifecycle: warm-start
// from its own snapshot when available, otherwise a full ClickHouse sync with
// capped backoff (so an initial failure can't strand the replica until the next
// 30-min refresh), then periodic refresh. Until the replica is Ready(), Cypher
// transparently uses the worker RPC tier — so after a deploy the replica is
// never left empty and unretried.
func serveLadybugLoop(ctx context.Context, svc *graphstore.Service, snapPath string, assetSvc *asset.Service, signals graphstore.SignalSource) {
	// 1. Snapshot warm-start (cheap: only the signal rollup query hits CH); any
	//    topology is accepted as long as the schema version matches.
	if snapPath != "" {
		if err := svc.LoadFromSnapshot(ctx, signals); err == nil {
			log.FromContext(ctx).Info().Msg("serve-ladybug: warm-started from snapshot")
		}
	}
	// 2. Full ClickHouse sync with backoff until Ready(). A short initial delay
	//    keeps serve off ClickHouse during the worker's boot read; retries then
	//    run aggressively rather than waiting for the 30-min refresh.
	if !svc.Ready() {
		backoff := 15 * time.Second
		const maxBackoff = 2 * time.Minute
		for !svc.Ready() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if svc.Ready() {
				break
			}
			if err := svc.SyncFromSources(ctx, 0, assetSvc, assetSvc, signals); err != nil {
				log.FromContext(ctx).Warn().Err(err).Dur("next_retry", backoff).Msg("serve-ladybug: initial sync failed — will retry")
				backoff = min(backoff*2, maxBackoff)
				continue
			}
		}
	}
	// 3. Periodic refresh every 30 min (independent of worker correlate).
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := svc.SyncFromSources(ctx, 0, assetSvc, assetSvc, signals); err != nil {
				log.FromContext(ctx).Warn().Err(err).Msg("serve-ladybug: periodic sync failed")
			}
		}
	}
}

// chatConnectorAdapter adapts connector.Service to chat.ConnectorLister.
type chatConnectorAdapter struct{ svc *connector.Service }

func (a chatConnectorAdapter) ListForChat(ctx context.Context) ([]chat.ConnInfo, error) {
	all, err := a.svc.List(ctx, false)
	if err != nil {
		return nil, err
	}
	out := make([]chat.ConnInfo, len(all))
	for i, c := range all {
		out[i] = chat.ConnInfo{
			ID:   c.ID,
			Name: c.Name,
			Type: string(c.Type),
			OK:   string(c.SyncStatus) == "ok",
		}
	}
	return out, nil
}

// chatCypherAdapter adapts explore.CypherRunner to chat.CypherRunner.
// The explore interface takes explicit node/edge limits; the chat interface
// uses sensible defaults (100 nodes, 500 edges) so the AI can use it simply.
type chatCypherAdapter struct{ r explore.CypherRunner }

func (a chatCypherAdapter) RunCypher(ctx context.Context, query string) (explore.Result, error) {
	return a.r.RunCypher(ctx, query, 100, 500)
}

// governPolicyAdapter adapts policy.Service to the narrow govern.PolicyReader
// interface, translating policy.ActionMode values to their string equivalents.
type governPolicyAdapter struct{ svc *policy.Service }

func (a *governPolicyAdapter) Get(ctx context.Context) (govern.PolicySnapshot, error) {
	p, err := a.svc.Get(ctx)
	if err != nil {
		return govern.PolicySnapshot{}, fmt.Errorf("governPolicyAdapter: %w", err)
	}
	rules := make(map[string]string, len(p.ActionRules))
	for k, v := range p.ActionRules {
		rules[k] = string(v)
	}
	return govern.PolicySnapshot{SuggestThreshold: p.SuggestThreshold, ActionRules: rules}, nil
}

// remediationGuide adapts executor.GuideFor to respond's RemediationGuide seam,
// which never names an executor type (layering).
func remediationGuide(f finding.Finding, actionClass string) (respond.Remediation, bool) {
	g, ok := executor.GuideFor(f.ResourceType, f.ResourceID, f.Region, actionClass)
	if !ok {
		return respond.Remediation{}, false
	}
	return respond.Remediation{
		Action: string(g.Action), Change: g.Change, Destructive: g.Destructive,
		Reversible: g.Reversible, Rollback: g.Rollback, CLI: g.CLI,
	}, true
}

func serve(ctx context.Context, getenv func(string) string) error {
	costCollectOn, err := costCollectEnabled(getenv)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	if err := nuclei.CheckEgressEnv(getenv); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	pool, err := db.NewPool(ctx, pgDSN(getenv), int32(envInt(getenv, "PG_MAX_CONNS_SERVE", db.MaxConnsServe)))
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer pool.Close()
	ready := db.NewReadiness(pool.Config().ConnConfig)
	defer ready.Close(ctx)

	ch, err := db.NewCH(ctx, chDSN(getenv), envInt(getenv, "CH_MAX_CONCURRENT", 0))
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	defer func() { _ = ch.Close() }()

	cipher, err := newCipher(getenv)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	// nil when no LLM provider is configured; every consumer below degrades.
	llmClient, err := newLLMClient(ctx, getenv)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	// Every consumer gets the client through llmUsage.Client with its purpose,
	// so each call is budget-checked and lands in the llm_usage ledger.
	llmUsage, err := newLLMUsage(ctx, pool, getenv)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	// Observability, off unless env-gated (OTEL_EXPORTER_OTLP_ENDPOINT /
	// METRICS_PORT). Sources are registered once serveLadybug + connectorSvc exist.
	shutdownTracing, err := obs.InitTracing(ctx, getenv, "serve")
	if err != nil {
		return fmt.Errorf("serve: tracing: %w", err)
	}
	defer func() { _ = shutdownTracing(context.Background()) }()
	metrics := obs.New()

	insertClient, err := jobs.InsertClient(pool)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}

	enqueuer := jobs.NewEnqueuer(insertClient)
	authRepo := auth.NewPGRepo(pool, cipher)
	// Admin actions (sign-in and sign-out, users, API keys, connectors, alert
	// channels, the approval policy, manual finding resolves, saved queries,
	// scan profiles) are written to audit_events
	// (docs/security-hardening.md#audit-trail).
	adminAudit := audit.NewService(audit.NewCHRepo(ch))
	// REQUIRE_ADMIN_TOTP=true: an admin with no TOTP enrolled cannot sign in
	// with a password. "true" or "false" only; anything else stops serve.
	requireAdminTOTP, err := jobs.SwitchFromEnv(getenv, "REQUIRE_ADMIN_TOTP")
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	authSvc := auth.NewService(authRepo).WithAudit(adminAudit).WithRequireAdminTOTP(requireAdminTOTP)
	bypassAuth, err := bypassAuthEnabled(getenv)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	// API_KEY_MAX_LIFETIME_DAYS caps every key's life (default 90); keys
	// created without an expiry before the cap existed expire at created_at+cap.
	apiKeySvc := apikey.NewService(apikey.NewPGRepo(pool)).WithAudit(adminAudit).
		WithMaxLifetime(time.Duration(envInt(getenv, "API_KEY_MAX_LIFETIME_DAYS", 90)) * 24 * time.Hour)
	authHandler, err := newAuthHandler(ctx, getenv, authSvc, apiKeySvc, bypassAuth)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	// Expired-session reaper. Deliberately a serve-pod ticker rather than a River
	// periodic: sessions are a serve-pod concern, this is a single indexed DELETE,
	// and a periodic that never fires is a known failure mode. It runs on boot
	// (so a restart always clears any backlog of expired sessions) and hourly
	// thereafter.
	safego(ctx, "expired-session-reaper", func() {
		purge := func() {
			n, err := authSvc.PurgeExpiredSessions(ctx)
			if err != nil {
				log.FromContext(ctx).Warn().Err(err).Msg("serve: expired-session purge failed")
				return
			}
			if n > 0 {
				log.FromContext(ctx).Info().Int64("deleted", n).Msg("serve: purged expired sessions")
			}
		}
		purge()
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				purge()
			}
		}
	})

	assetCHRepo := asset.NewCHRepo(ch)
	assetSvc := asset.NewService(assetCHRepo)
	connectorSvc := connector.NewService(connector.NewPGRepo(pool), cipher).WithOrgDiscoverer(newAWSOrgDiscoverer()).
		WithAudit(adminAudit)
	findingSvc := finding.NewService(finding.NewCHRepo(ch)).
		// A resolve ends the finding's alert episode, so a regression re-alerts.
		WithResolveObserver(enrichcache.NewService(enrichcache.NewPGRepo(pool))).
		// A manual resolve is audited; on an API key it must pass the same
		// rule as MCP suppress_finding.
		WithAudit(adminAudit).WithAgentGuard(enrich.AgentRefusal)
	// PurgeAndDelete (the confirmed-dead-account admin action) needs both
	// domains; every other connector operation on this server never touches
	// them, which is why this is a separate wiring step rather than a
	// NewService parameter every caller would have to satisfy.
	connectorSvc.WithPurge(assetSvc, findingSvc)
	// Suppression state is Postgres; its audit trail is the shared ClickHouse
	// audit_events table, alongside every other audited human action.
	suppressSvc := suppress.NewService(suppress.NewPGRepo(pool)).WithAudit(suppress.NewCHAuditRepo(ch)).
		WithFindingGate(suppressAgentGate{findings: findingSvc})
	// The server only reads scan runs and enqueues scans; scanners live in the
	// worker, so a nil scanner here is correct and never invoked.
	scanSvc := scan.NewService(scan.NewPGRepo(pool), assetSvc, assetSvc, nil, findingSvc).WithAudit(adminAudit)
	// Template editor: validate + test run in the serve pod (nuclei SDK embedded).
	// Generate requires an LLM provider; nil generator returns 503 gracefully.
	templateSvc := nuclei.NewTemplateService()
	var templateGen scan.TemplateAIGenerator
	if llmClient != nil {
		templateGen = nuclei.NewTemplateGeneratorAdapter(llmUsage.Client(llmClient, llmusage.PurposeTemplateGen), getenv("TEMPLATE_GEN_MODEL"))
	}
	complianceCatalog, err := compliance.LoadCatalog()
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	complianceSvc := compliance.NewService(findingSvc, compliance.NewCHInventory(ch), checks.Default(), connectorSvc).
		WithRequirements(complianceCatalog, findingSvc)
	// Scan profile service — CRUD + triggering of named scan profiles.
	// The serve pod enqueues profile scan jobs; the scanner pod executes them.
	profileSvc := scan.NewProfileService(
		scan.NewPGProfileRepo(pool),
		scan.NewPGRepo(pool),
		nil, // ScannerRegistry — nil; serve pod only enqueues, never runs
		assetSvc,
		enqueuer,
	).WithAudit(adminAudit)

	// Serve-pod Ladybug replica — independent of the worker, syncs from ClickHouse
	// every 30 minutes. Ensures the Graph tab never goes dark when the worker pod
	// restarts (otherwise Cypher is unavailable until the worker's graph reloads).
	// Opt-in via SERVE_LADYBUG_ENABLED; disabled by default until memory limits are
	// raised in helm-values (requires ~512 MB extra on the serve pod).
	serveLadybug, bufMB, err := openServeReplica(getenv, graphstore.Open)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	if serveLadybug != nil {
		serveSnapPath := getenv("SERVE_LADYBUG_SNAPSHOT_PATH")
		// Same recorder as the worker, so a rebuild here shows on THIS pod's
		// /metrics. Without it the serve replica could rebuild unobserved.
		serveLadybug.WithSyncMetrics(metrics)
		signals := &serveSignalSource{findings: findingSvc}
		safego(ctx, "serve-ladybug-refresh-loop", func() { serveLadybugLoop(ctx, serveLadybug, serveSnapPath, assetSvc, signals) })
		log.FromContext(ctx).Info().Int("buffer_mb", bufMB).Msg("serve-ladybug: local Ladybug replica enabled")
	}

	metrics.RegisterSources(obs.Sources{
		QueueDepth: func(ctx context.Context) []obs.QueueStat { return jobs.QueueDepths(ctx, pool) },
		Graph: func() obs.GraphStats {
			if serveLadybug == nil {
				return obs.GraphStats{}
			}
			var built int64
			if t := serveLadybug.LastBuiltAt(); !t.IsZero() {
				built = t.Unix()
			}
			tableRows, _ := serveLadybug.NodeTableRows()
			return obs.GraphStats{
				Nodes: serveLadybug.NodeCount(), NodeBudget: graphstore.NodeBudget,
				LastBuiltUnix: built,
				NodeTableRows: tableRows, NodeGroupRows: graphstore.LadybugNodeGroupRows,
			}
		},
		Connectors: func(ctx context.Context) []obs.ConnectorStat {
			cs, err := connectorSvc.List(ctx, true)
			if err != nil {
				return nil
			}
			now := time.Now()
			out := make([]obs.ConnectorStat, len(cs))
			for i, c := range cs {
				out[i] = obs.ConnectorStat{Name: c.Name, Stale: c.Stale(now, connector.DefaultStaleAfter), PartialStreak: c.PartialStreak}
			}
			return out
		},
		// River queue-age and migration version: same sources as the worker pod,
		// mirrored here rather than shared, since serve has its own pool/getenv in
		// scope and no cross-pod plumbing exists to share the closures.
		QueueOldestAvailable: func(ctx context.Context) []obs.QueueAgeStat {
			return jobs.QueueOldestAvailable(ctx, pool)
		},
		// On migrate.Status error, omit the series rather than publish a
		// zero/Pending-false stat that would read as healthy — same convention as
		// QueueOldestAvailable and the worker pod's identical wiring.
		Migration: func(ctx context.Context) []obs.MigrationStat {
			statuses, err := migrate.Status(ctx, pgDSN(getenv), chDSN(getenv))
			if err != nil {
				log.FromContext(ctx).Warn().Err(err).Msg("migrate.Status failed — migration metrics skipped this scrape")
				return nil
			}
			out := make([]obs.MigrationStat, len(statuses))
			for i, s := range statuses {
				out[i] = obs.MigrationStat{DB: s.DB, Applied: s.Applied, Target: s.Target, Pending: s.Pending}
			}
			return out
		},
	})
	if metricsPort := getenv("METRICS_PORT"); metricsPort != "" {
		safego(ctx, "metrics-listener", func() {
			if err := metrics.ListenAndServe(ctx, ":"+metricsPort); err != nil {
				log.FromContext(ctx).Error().Err(err).Msg("serve: metrics listener exited")
			}
		})
	}

	// Graph engine — three-tier when both worker and serve Ladybug are active:
	//   1. Serve Ladybug  (in-process primary; ≤30 min stale, never goes down with the worker)
	//   2. Worker Ladybug RPC (network hop; covers the serve Ladybug's initial sync window,
	//      its errors and its empty answers to ID-keyed lookups)
	//   3. ClickHouse BFS (always available — no Cypher support)
	chRepo := explore.NewCHRepo(ch)
	var exploreRepo explore.Repo = chRepo
	var cypherRunner explore.CypherRunner
	var ladybugRepo *explore.LadybugRPCRepo // hoisted so serve.go can use it for NodeStats
	if url := getenv("LADYBUG_RPC_URL"); url != "" {
		ladybugRepo = explore.NewLadybugRPCRepo(url, getenv("LADYBUG_RPC_SECRET"))
		if serveLadybug != nil {
			// Serve Ladybug is PRIMARY for all Cypher queries — in-process, zero network hop.
			// Worker Ladybug RPC is SECONDARY — used during the serve Ladybug's initial sync
			// window after pod start, and when the serve Ladybug errors (or, for explore,
			// answers an ID-keyed lookup with nothing). Worker's job is to keep ClickHouse current
			// (correlate, enrich, BFS scores); the serve pod reads from CH on its own schedule.
			//
			// Priority: serve Ladybug (in-process) → worker Ladybug RPC (fresh, network hop) → CH BFS
			serveRepo := explore.NewLocalLadybugRepo(serveLadybug)
			exploreRepo = explore.NewTieredRepo(serveRepo, ladybugRepo, chRepo, metrics)
			cypherRunner = explore.NewTieredCypherRunner(serveLadybug, ladybugRepo)
		} else {
			// No serve replica — fall back to worker RPC then ClickHouse BFS.
			exploreRepo = explore.NewFallbackRepo(ladybugRepo, chRepo, metrics)
			cypherRunner = ladybugRepo
		}
	} else if serveLadybug != nil {
		// No worker RPC configured — serve replica only, ClickHouse BFS fallback.
		serveRepo := explore.NewLocalLadybugRepo(serveLadybug)
		exploreRepo = explore.NewFallbackRepo(serveRepo, chRepo, metrics)
		cypherRunner = serveLadybug
	}
	if msg := serveGraphOffWarning(getenv, serveLadybug != nil); msg != "" {
		log.FromContext(ctx).Warn().Msg(msg)
	}
	// NL→query translation only when an LLM is configured: the explore
	// service answers ErrTranslateUnavailable for a nil translator.
	var exploreOpts []explore.Option
	if llmClient != nil {
		nlClient := llmUsage.Client(llmClient, llmusage.PurposeNLQuery)
		exploreOpts = append(exploreOpts,
			explore.WithTranslator(reason.NewGraphTranslator(nlClient)),
			explore.WithCypherTranslator(reason.NewCypherTranslator(nlClient)))
	}
	exploreSvc := explore.NewService(exploreRepo, exploreOpts...)
	reasonCacheSvc := reasoncache.NewService(reasoncache.NewPGRepo(pool))
	// Finding-detail context: read-only assembler over the existing services
	// (graph context from respond, reasoning from the cache, factors from signals).
	// Blast radius uses Ladybug when available (in-memory traversal, far faster than a multi-hop CH BFS).
	signalRepo := enrich.NewSignalCHRepo(ch)
	var findingCtxBlast respond.BlastRadiusProvider = assetSvc
	if serveLadybug != nil {
		findingCtxBlast = &ladybugBlastProvider{graph: serveLadybug, assets: assetSvc}
	}
	findingCtxSvc := findingctx.NewService(
		findingSvc,
		respond.NewReadService(findingCtxBlast, findingSvc, assetSvc).
			WithFactors(signalRepo). // score breakdown in finding-detail view
			WithOutEdger(assetSvc),  // identity chain + supply-chain path in detail view
		reasonCacheSvc,
		signalRepo,
	).WithSuppressions(suppressSvc) // detail toggle reflects the real suppression standing
	// Alert context: resolves SIEM alert identifiers to assets and summarizes their
	// graph context. Same blast provider as finding detail (Ladybug when available).
	// Risk score is the Ladybug-served post-BFS one where a Ladybug tier holds the asset.
	alertCtxSvc := alertctx.NewService(alertctx.NewCHRepo(ch), assetSvc, findingCtxBlast, findingSvc)
	var riskTiers []explore.Repo
	if serveLadybug != nil {
		riskTiers = append(riskTiers, serveLadybug)
	}
	if ladybugRepo != nil {
		riskTiers = append(riskTiers, ladybugRepo)
	}
	if len(riskTiers) > 0 {
		alertCtxSvc = alertCtxSvc.WithPropagatedScores(&ladybugRiskScores{tiers: riskTiers})
	}
	// Executor — cloud remediation (executor/plan.go specs). The service
	// resolves connector credentials at call-time, so no extra deps beyond the
	// connector service itself.
	// Every cloud mutation this service performs is written to audit_events. The
	// audit sink is mandatory here, not optional: these are the only routes in
	// the product that change a customer's cloud configuration.
	// The destructive subset (ec2_stop, ec2_start, gcp_firewall_remove,
	// azure_nsg_rule_remove and the delete variant of iam_key_disable)
	// additionally needs a grant from a second admin. Without the approver
	// those actions are refused outright, so this wiring is not optional in the
	// serve pod.
	executorApprover, err := executor.NewApprover(getenv("GRAPH_SECRET_KEY"))
	if err != nil {
		return fmt.Errorf("serve: executor approvals: %w", err)
	}
	// Each grant runs at most one execution, across every serve replica.
	executorApprover.WithLedger(executor.NewPGGrantLedger(pool))
	approverMinAge := executor.DefaultMinApproverAccountAge
	if v := getenv("EXECUTOR_APPROVER_MIN_ACCOUNT_AGE"); v != "" {
		if approverMinAge, err = time.ParseDuration(v); err != nil || approverMinAge < 0 {
			return fmt.Errorf("serve: EXECUTOR_APPROVER_MIN_ACCOUNT_AGE must be a non-negative duration, got %q", v)
		}
	}
	executorSvc := executor.NewService(connectorSvc).
		WithAudit(executor.NewCHAuditRepo(ch)).
		WithApprovals(executorApprover).
		WithMinApproverAge(approverMinAge)

	// Governor queue: surfaces parked/escalated decisions for human approval and
	// feeds denials back into decaying memory (executed fixes arrive via the executor).
	governRepo := govern.NewPGRepo(pool)
	memorySvc := memory.NewService(memory.NewPGRepo(pool))
	governSvc := govern.NewService(governRepo, reasonCacheSvc, findingSvc, memorySvc, respond.NewCHRepo(ch)).
		WithConfidence(memorySvc). // teaching-value queue ordering
		// Pattern-level verdicts: the serve pod only WRITES these (via governor
		// approve/deny actions below); the worker pod is what CONSULTS them,
		// wiring its own respond.Service.WithPatternVerdicts over this same
		// govern.Service.PatternVerdict — see cmd/graph/worker.go.
		WithPatterns(governRepo)
	// Approve-and-run from the decision panel: the same executor, approval and
	// audit path as the admin endpoints, plus the decision context. Only a fix
	// that actually ran reaches govern's outcome ledger.
	executorSvc.WithDecisions(executor.DecisionDeps{
		Targets:  decisionTargets{decisions: respond.NewCHRepo(ch), findings: findingSvc},
		Owners:   connectorSvc,
		Runs:     executor.NewPGDecisionRuns(pool),
		Outcomes: decisionOutcomes{govern: governSvc},
		Audit:    executor.NewCHAuditRepo(ch),
	})
	// Outbound alerting hub (Slack, …). Reuses the connector cipher to decrypt
	// channel secrets. Nil-safe — no channels configured means Dispatch no-ops.
	notifySvc := notify.NewService(notify.NewPGRepo(pool, cipher)).WithMetrics(metrics).WithAudit(adminAudit)

	// Saved-query detection-as-code (serve side): CRUD + manual "run now". The
	// scheduled execution + change alerting runs in the worker pod (which holds
	// the Ladybug primary). A serve-side runner backs the run-now button; a
	// manual run is history only and never moves the scheduled change baseline
	// (savedquery.Service.Run), so it cannot swallow a change the next scheduled
	// run should alert on.
	savedQuerySvc := savedquery.NewService(savedquery.NewPGRepo(pool)).WithAudit(adminAudit)
	if cypherRunner != nil {
		savedQuerySvc = savedQuerySvc.WithRunner(savedQueryCypherAdapter{runner: cypherRunner})
	}

	// Approval notifiers fan out so several can fire on one approval: the
	// webhook, the JIT email link, and Slack alerts all coexist. They go through
	// one multiApprovalNotifier because WithApprovalNotifier holds a single
	// notifier, so a call per channel would let the last one silently win.
	var approvalNotifiers multiApprovalNotifier
	approvalHook, err := approvalWebhookFromEnv(ctx, getenv)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	if approvalHook != nil {
		approvalNotifiers = append(approvalNotifiers, approvalHook)
	}
	// Email approval REQUESTS are sent by the worker when a decision is parked
	// (see worker.go); serve only verifies the links, with the same secret.
	approvalTokenSecret := getenv("APPROVAL_TOKEN_SECRET")
	if approvalTokenSecret != "" {
		if err := govern.ValidateTokenSecret(approvalTokenSecret); err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		governSvc.WithLinkNonces(governRepo)
	}
	approvalNotifiers = append(approvalNotifiers, &slackApprovalNotifier{notify: notifySvc})
	governSvc.WithApprovalNotifier(approvalNotifiers)

	policySvc := policy.NewService(policy.NewPGRepo(pool)).WithAudit(adminAudit)

	// Cost data — snapshots from AWS Cost Explorer + anomaly detection.
	costdataSvc := costdata.NewService(costdata.NewPGRepo(pool))
	// Background collect: pull cost data for every AWS connector every 6h.
	// The loop body lives in serve_costcollect.go; the panic recovery stays
	// here at the `go` call site alongside every other spawned goroutine.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.FromContext(ctx).Error().Any("panic", r).Msg("cost collect loop: panic")
			}
		}()
		startCostCollectLoop(ctx, costCollectOn, connectorSvc, costdataSvc, metrics)
	}()
	governSvc.WithPolicy(&governPolicyAdapter{svc: policySvc})

	// liveAWS is shared between MCP and chat — both can make real-time cloud calls.
	liveAWS := mcp.NewLiveAWSCaller(mcp.NewConnectorServiceAdapter(
		func(ctx context.Context, id string) (map[string]string, error) {
			c, err := connectorSvc.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			return c.Config, nil
		},
	))

	// Live cloud reads (MCP and chat) are limited to LIVE_CLOUD_TOOLS_ROLE
	// (default admin) and every call is written to audit_events.
	liveRole := auth.RoleAdmin
	if v := getenv("LIVE_CLOUD_TOOLS_ROLE"); v != "" {
		if liveRole = auth.Role(v); !liveRole.Valid() {
			return fmt.Errorf("serve: LIVE_CLOUD_TOOLS_ROLE must be admin, analyst or viewer, got %q", v)
		}
	}
	liveAudit := executor.NewCHAuditRepo(ch)

	var chatHandler *chat.Handler
	if llmClient != nil {
		chatLimits, err := chatLimitsFromEnv(getenv)
		if err != nil {
			return fmt.Errorf("serve: %w", err)
		}
		chatSvc := chat.NewService(llmUsage.Client(llmClient, llmusage.PurposeChat), findingSvc, assetSvc, complianceSvc).
			WithLimits(chatLimits)
		// Graph: run Cypher queries against Ladybug.
		if cypherRunner != nil {
			chatSvc = chatSvc.WithCypher(chatCypherAdapter{cypherRunner})
		}
		// Live cloud: fall back to real-time AWS/cloud APIs when graph is inconclusive.
		chatSvc = chatSvc.WithLiveCaller(liveAWS).
			WithConnectors(chatConnectorAdapter{connectorSvc}).
			WithLiveRole(liveRole).WithAudit(liveAudit)
		chatHandler = chat.NewHandler(chatSvc)
	}

	governHandler := govern.NewHandler(governSvc)
	if approvalTokenSecret != "" {
		governHandler.WithTokenSecret(approvalTokenSecret)
	}

	graphStats := graphStatsSource(serveLadybug, ladybugRepo)

	addr := envOr(getenv, "ADDR", ":8080")
	security, err := securityConfigFromEnv(ctx, getenv, addr, bypassAuth)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	driftAnalyses, err := newDriftReader(getenv, pool)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	feeds, err := jobs.FeedsFromEnv(getenv)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	// 60 submissions an hour per key and asset, bursting 10.
	pkgInvSvc := pkginv.NewService(pkginv.NewPGRepo(pool), assetSvc, connectorSvc, forget.NewPGRepo(pool),
		adminAudit, auth.NewKeyedLimiter(1, 10), feeds.AdvisorySources)
	diskScanSvc := serveDiskScan(pool)
	srv := httpsrv.New(addr, httpsrv.Handlers{
		Security:     security,
		Auth:         authHandler,
		Asset:        asset.NewHandler(assetSvc, httpsrv.AssetRiskProvider(findingSvc)).WithOwnerTagKeys(ownerTagKeys(getenv)),
		Connector:    connector.NewHandler(connectorSvc, enqueuer),
		Finding:      finding.NewHandler(findingSvc, suppressSvc),
		FindingCtx:   findingctx.NewHandler(findingCtxSvc),
		Belief:       belief.NewHandler(belief.NewService(belief.NewCHRepo(ch))),
		Suppress:     suppress.NewHandler(suppressSvc),
		Scan:         scan.NewHandler(scanSvc, enqueuer),
		ScanProfile:  scan.NewProfileHandler(profileSvc),
		ScanTemplate: scan.NewTemplateHandler(templateSvc, templateSvc, templateGen),
		Respond: respond.NewHandler(respond.NewCHRepo(ch), findingSvc).
			WithRepeatHotspots(repeatHotspotsAdapter(reasonCacheSvc)).
			WithRemediationGuide(respond.RemediationGuideFunc(remediationGuide)),
		Refine:     respond.NewRefineHandler(respond.NewCHRepo(ch), findingSvc, llmUsage.Client(llmClient, llmusage.PurposeRefine)),
		Compliance: compliance.NewHandler(complianceSvc),
		Govern:     governHandler,
		MCP: mcp.NewHandler(assetSvc, findingSvc, findingCtxSvc, complianceSvc, exploreSvc, cypherRunner, graphStats, suppressSvc, liveAWS, connectorSvc, executorSvc).
			WithLiveRole(liveRole).WithAudit(liveAudit).WithAlertContext(alertCtxSvc).
			WithResourceResolver(alertCtxSvc, assetSvc, findingSvc).
			WithDriftAnalysis(driftAnalyses, profileSvc).WithPackageInventory(pkgInvSvc).
			WithDiskScan(diskScanSvc, diskScanStamps{assets: assetSvc}),
		DriftAnalysis: driftanalysis.NewHandler(driftAnalyses),
		PkgInv:        pkginv.NewHandler(pkgInvSvc),
		DiskScan:      newDiskScanHandler(diskScanSvc, connectorSvc, assetSvc),
		AlertCtx:      alertctx.NewHandler(alertCtxSvc),
		Explore: func() *explore.Handler {
			h := explore.NewHandler(exploreSvc, cypherRunner)
			qs := make([]explore.NamedQueryEntry, len(graphstore.NamedQueries))
			for i, q := range graphstore.NamedQueries {
				qs[i] = explore.NamedQueryEntry{Name: q.Name, Query: q.Query, Params: q.Params}
			}
			return h.WithNamedQueries(qs).WithNodeStats(graphStats)
		}(),
		Webhook:   webhook.NewHandler(connectorSvc, enqueuer),
		Executor:  executor.NewHandler(executorSvc),
		Policy:    policy.NewHandler(policySvc),
		APIKey:    apikey.NewHandler(apiKeySvc),
		Chat:      chatHandler,
		CostData:  costdata.NewHandler(costdataSvc),
		DriftData: asset.NewDriftHandlerWithPool(assetCHRepo, pool),
		Intel: intel.NewHandler(
			intel.NewService(intel.NewPGRepo(pool), intel.NewCHRepo(ch), llmUsage.Client(llmClient, llmusage.PurposeCTTriage)).
				WithNotifier(notifySvc),
		),
		Alert:      notify.NewHandler(notifySvc),
		Identity:   identity.NewHandler(identity.NewService(identity.NewCHRepo(ch))),
		SavedQuery: savedquery.NewHandler(savedQuerySvc),
		LLMUsage:   llmusage.NewHandler(llmUsage),
		KEV:        kevwatch.NewHandler(kevwatch.NewService(kevwatch.NewPGRepo(pool))),
		// Readiness: DB reachable. (Graph readiness is deliberately excluded — the
		// serve pod stays ready and falls back to ClickHouse BFS when Ladybug is down.)
		Ready: ready.Check,
	})

	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.FromContext(ctx).Error().Any("panic", rec).Msg("serve goroutine panicked")
				errCh <- fmt.Errorf("serve: panic: %v", rec)
			}
		}()
		log.FromContext(ctx).Info().Str("addr", srv.Addr).Msg("graph serving")
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: shutdown: %w", err)
		}
		return nil
	}
}
