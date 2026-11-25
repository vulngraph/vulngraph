// Package httpsrv assembles the HTTP server: routes, middleware, timeouts.
package httpsrv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/alertctx"
	"github.com/vulngraph/vulngraph/internal/app/apikey"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/chat"
	"github.com/vulngraph/vulngraph/internal/app/compliance"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/costdata"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	"github.com/vulngraph/vulngraph/internal/app/driftanalysis"
	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/findingctx"
	"github.com/vulngraph/vulngraph/internal/app/govern"
	"github.com/vulngraph/vulngraph/internal/app/identity"
	"github.com/vulngraph/vulngraph/internal/app/intel"
	"github.com/vulngraph/vulngraph/internal/app/kevwatch"
	"github.com/vulngraph/vulngraph/internal/app/llmusage"
	"github.com/vulngraph/vulngraph/internal/app/mcp"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/pkginv"
	"github.com/vulngraph/vulngraph/internal/app/policy"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/app/savedquery"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/app/suppress"
	"github.com/vulngraph/vulngraph/internal/app/webhook"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/web"
)

// Handlers carries the per-domain HTTP handlers New wires together. A struct
// (rather than positional args) keeps the signature stable as domains are added.
type Handlers struct {
	Auth         *auth.Handler
	Asset        *asset.Handler
	Connector    *connector.Handler
	Finding      *finding.Handler
	FindingCtx   *findingctx.Handler
	AlertCtx     *alertctx.Handler // POST /api/context/alert; nil skips registration
	Belief       *belief.Handler
	Suppress     *suppress.Handler
	Scan         *scan.Handler
	ScanTemplate *scan.TemplateHandler
	ScanProfile  *scan.ProfileHandler
	Respond      *respond.Handler
	Refine       *respond.RefineHandler
	Compliance   *compliance.Handler
	Govern       *govern.Handler
	MCP          *mcp.Handler
	Explore      *explore.Handler
	Webhook      *webhook.Handler
	Executor     *executor.Handler
	Policy       *policy.Handler
	APIKey       *apikey.Handler
	Chat         *chat.Handler
	CostData     *costdata.Handler
	DriftData    *asset.DriftHandler
	// DriftAnalysis serves the advisory drift verdicts; read-only, nil skips registration.
	DriftAnalysis *driftanalysis.Handler
	// PkgInv takes package inventories from a customer's own agent
	// (inventory-scoped API keys only); nil skips registration.
	PkgInv *pkginv.Handler
	// DiskScan serves agentless disk-scan results and the per-connector opt-in;
	// nil skips registration.
	DiskScan   *diskscan.Handler
	Intel      *intel.Handler
	Identity   *identity.Handler // identity census (GET /api/identity/summary); nil skips registration
	Alert      *notify.Handler
	SavedQuery *savedquery.Handler
	LLMUsage   *llmusage.Handler // GET /api/llm/usage (admin); nil skips registration
	KEV        *kevwatch.Handler // GET /api/kev/additions; nil skips registration
	// Ready, when set, backs GET /readyz: it returns an error when the process is
	// not ready to serve (e.g. DB unreachable, graph not yet built), which maps to
	// 503. Nil means /readyz always reports ready (204), matching /healthz.
	Ready func(context.Context) error
	// Security tunes the CSRF, security-header and host-allowlist middleware.
	Security SecurityConfig
}

// middleware wraps the mux in the cross-cutting chain, outermost first. The
// security headers sit outside every rejecting layer so rejections carry them.
func middleware(mux http.Handler, sec SecurityConfig) http.Handler {
	return obs.HTTPMiddleware(withRequestID(withRecover(
		withSecurityHeaders(sec.TLSProxy, withHostAllowlist(sec.AllowedHosts,
			withCSRF(sec.AllowedOrigins, withBodyLimit(withDeadline(mux))))))))
}

// New wires all routes and returns a server ready to ListenAndServe.
func New(addr string, h Handlers) *http.Server {
	authH := h.Auth
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if h.Ready != nil {
			if err := h.Ready(r.Context()); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// Guard all handler registrations so New() works with a zero-value Handlers
	// (used by TestHealthz and other tests that only exercise /healthz).
	if authH == nil {
		return newServer(addr, middleware(mux, h.Security))
	}

	// LLM-backed routes spend model tokens on every call; budget them per user.
	llmLimiter := h.Security.LLMLimiter
	if llmLimiter == nil {
		llmLimiter = auth.NewKeyedLimiter(auth.DefaultLLMPerUserPerMinute, auth.DefaultLLMPerUserPerMinute)
	}
	llm := func(next http.HandlerFunc) http.HandlerFunc { return auth.RateLimitPerUser(llmLimiter, next) }
	alertLimiter := h.Security.AlertContextLimiter
	if alertLimiter == nil {
		alertLimiter = auth.NewKeyedLimiter(DefaultAlertContextPerUserPerMinute, DefaultAlertContextPerUserPerMinute)
	}
	cypherLimiter := h.Security.CypherLimiter
	if cypherLimiter == nil {
		cypherLimiter = auth.NewKeyedLimiter(DefaultCypherPerUserPerMinute, DefaultCypherPerUserPerMinute)
	}
	cypherPool := func(next http.HandlerFunc) http.HandlerFunc { return auth.RateLimitPerUser(cypherLimiter, next) }

	mux.HandleFunc("POST /api/auth/login", authH.Login)
	mux.HandleFunc("POST /api/auth/logout", authH.RequireAuth(authH.Logout))
	mux.HandleFunc("GET /api/auth/me", authH.RequireAuth(authH.Me))
	mux.HandleFunc("GET /api/auth/providers", authH.Providers)
	mux.HandleFunc("GET /api/auth/google", authH.GoogleOAuthRedirect)
	mux.HandleFunc("GET /api/auth/google/callback", authH.GoogleOAuthCallback)
	mux.HandleFunc("GET /api/auth/okta", authH.OktaOAuthRedirect)
	mux.HandleFunc("GET /api/auth/okta/callback", authH.OktaOAuthCallback)
	// RequireSession: the admin writes an API key must never make (auth.RequireSession).
	mux.HandleFunc("GET /api/users", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, authH.ListUsers)))
	mux.HandleFunc("POST /api/users", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, authH.CreateUser))))
	mux.HandleFunc("PATCH /api/users/{id}", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, authH.UpdateUser))))
	mux.HandleFunc("DELETE /api/users/{id}", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, authH.DeleteUser))))
	mux.HandleFunc("POST /api/users/{id}/revoke-sessions", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, authH.RevokeUserSessions))))

	mux.HandleFunc("GET /api/assets", authH.RequireAuth(h.Asset.List))
	mux.HandleFunc("GET /api/assets/summary", authH.RequireAuth(h.Asset.Summary))
	mux.HandleFunc("GET /api/assets/{id}", authH.RequireAuth(h.Asset.Get))
	mux.HandleFunc("GET /api/assets/{id}/blast-radius", authH.RequireAuth(h.Asset.BlastRadius))
	mux.HandleFunc("GET /api/assets/{id}/changes", authH.RequireAuth(h.Asset.Changes))
	mux.HandleFunc("GET /api/drift/events", authH.RequireAuth(h.DriftData.Events))
	// Advisory LLM verdicts on drift batches: read-only for any role, and no
	// route turns a verdict into a scan.
	// Package inventory from a customer's own agent. An inventory-scoped key maps
	// to viewer, so the router gate admits viewer; the handler then requires the
	// inventory scope itself (a session, even an admin's, is refused with 403).
	if h.PkgInv != nil {
		mux.HandleFunc("PUT /api/assets/{id}/package-inventory", authH.RequireAuth(auth.RequireRole(auth.RoleViewer, h.PkgInv.PutForAsset)))
		mux.HandleFunc("PUT /api/package-inventory", authH.RequireAuth(auth.RequireRole(auth.RoleViewer, h.PkgInv.Put)))
	}
	// Disk scan: reads for any role; the opt-in is the standing approval for
	// reading (and creating) VM snapshots, so it is session-only and admin-only.
	if h.DiskScan != nil {
		mux.HandleFunc("GET /api/disk-scans", authH.RequireAuth(h.DiskScan.List))
		mux.HandleFunc("GET /api/assets/{id}/disk-scan", authH.RequireAuth(h.DiskScan.GetAsset))
		mux.HandleFunc("GET /api/connectors/{id}/disk-scan", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.DiskScan.GetConnector)))
		mux.HandleFunc("PUT /api/connectors/{id}/disk-scan", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, h.DiskScan.SetConnector))))
	}
	if h.DriftAnalysis != nil {
		mux.HandleFunc("GET /api/drift/analyses", authH.RequireAuth(h.DriftAnalysis.List))
		mux.HandleFunc("GET /api/drift/analyses/{batch_id}", authH.RequireAuth(h.DriftAnalysis.Get))
	}

	// Alert context for SIEM/SOC tooling: read-only, so any authenticated role
	// (API keys included) may call it despite the POST.
	if h.AlertCtx != nil {
		mux.HandleFunc("POST /api/context/alert", authH.RequireAuth(auth.RateLimitPerUser(alertLimiter, h.AlertCtx.Context)))
	}

	// Identity census: judgements over principal metadata plus executes_as
	// graph evidence, distinct from the raw asset-row counts in
	// /api/assets/summary. Nil handler (no ClickHouse wiring) skips registration.
	if h.Identity != nil {
		mux.HandleFunc("GET /api/identity/summary", authH.RequireAuth(h.Identity.Summary))
	}

	// Domain squatting / phishing monitoring (Intel). Reads are auth-only; writes
	// are admin-gated. Nil handler (no ClickHouse/intel wiring) skips registration.
	if h.Intel != nil {
		mux.HandleFunc("GET /api/intel/domains", authH.RequireAuth(h.Intel.ListDomains))
		mux.HandleFunc("POST /api/intel/domains", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Intel.AddDomain)))
		mux.HandleFunc("DELETE /api/intel/domains/{domain}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Intel.RemoveDomain)))
		mux.HandleFunc("GET /api/intel/phishing", authH.RequireAuth(h.Intel.ListCandidates))
		mux.HandleFunc("POST /api/intel/phishing/{id}/confirm", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Intel.ConfirmCandidate)))
		mux.HandleFunc("POST /api/intel/phishing/{id}/dismiss", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Intel.DismissCandidate)))
	}

	// Alerting channels (Slack, …). Reads are auth-only; writes (incl. the secret
	// bot token) are admin-gated. Nil handler skips registration.
	if h.Alert != nil {
		mux.HandleFunc("GET /api/alerts/channels", authH.RequireAuth(h.Alert.List))
		mux.HandleFunc("POST /api/alerts/channels", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Alert.Create)))
		mux.HandleFunc("PUT /api/alerts/channels/{id}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Alert.Update)))
		mux.HandleFunc("DELETE /api/alerts/channels/{id}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Alert.Delete)))
		mux.HandleFunc("POST /api/alerts/channels/{id}/test", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Alert.Test)))
	}

	// Saved Cypher queries (detection-as-code). Reads auth-only; writes admin-gated.
	// Nil handler (no graph engine) skips registration.
	if h.SavedQuery != nil {
		mux.HandleFunc("GET /api/saved-queries", authH.RequireAuth(h.SavedQuery.List))
		mux.HandleFunc("POST /api/saved-queries", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.SavedQuery.Create)))
		mux.HandleFunc("PUT /api/saved-queries/{id}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.SavedQuery.Update)))
		mux.HandleFunc("DELETE /api/saved-queries/{id}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.SavedQuery.Delete)))
		// Run executes stored Cypher and has side effects (fires AlertOnChange
		// notifications, rewrites the change-detection baseline), so it is a write
		// and must be admin-gated like Create/Update/Delete — not auth-only.
		mux.HandleFunc("POST /api/saved-queries/{id}/run", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.SavedQuery.Run)))
		mux.HandleFunc("GET /api/saved-queries/{id}/runs", authH.RequireAuth(h.SavedQuery.Runs))
	}

	mux.HandleFunc("GET /api/findings", authH.RequireAuth(h.Finding.List))
	mux.HandleFunc("GET /api/findings/summary", authH.RequireAuth(h.Finding.Summary))
	mux.HandleFunc("GET /api/findings/clusters", authH.RequireAuth(h.Finding.Clusters))
	// Cost-bearing risk: the true count of billed resources carrying findings,
	// separate from the ranked page (finding/risk.go).
	mux.HandleFunc("GET /api/findings/cost-at-risk", authH.RequireAuth(h.Finding.CostAtRisk))
	mux.HandleFunc("GET /api/findings/{id}", authH.RequireAuth(h.FindingCtx.Get))
	mux.HandleFunc("GET /api/beliefs/{finding_id}", authH.RequireAuth(h.Belief.Get))
	mux.HandleFunc("POST /api/findings/{id}/suppress", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Suppress.Suppress)))
	mux.HandleFunc("DELETE /api/findings/{id}/suppress", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Suppress.Unsuppress)))
	mux.HandleFunc("POST /api/findings/{id}/suppress/review", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Suppress.Review)))
	mux.HandleFunc("POST /api/findings/{id}/resolve", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Finding.Resolve)))
	mux.HandleFunc("POST /api/suppressions/bulk", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Suppress.BulkSuppress)))
	mux.HandleFunc("POST /api/suppressions/bulk-remove", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Suppress.BulkUnsuppress)))
	mux.HandleFunc("GET /api/suppressions", authH.RequireAuth(h.Suppress.List))

	mux.HandleFunc("GET /api/decisions", authH.RequireAuth(h.Respond.ListDecisions))
	mux.HandleFunc("GET /api/decisions/summary", authH.RequireAuth(h.Respond.DecisionsSummary))
	if h.Refine != nil {
		mux.HandleFunc("POST /api/decisions/{id}/refine", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, llm(h.Refine.Refine))))
	}

	mux.HandleFunc("GET /api/queue", authH.RequireAuth(h.Govern.Queue))
	mux.HandleFunc("POST /api/queue/resolve", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, h.Govern.Resolve))))
	// JIT email-link endpoints — NOT session-authed; the HMAC token is the credential.
	// GET renders a confirmation page only (safe against link prefetch); the POST
	// records the verdict after an explicit confirmation click.
	mux.HandleFunc("GET /api/queue/approve-link/{token}", h.Govern.ApproveLink)
	mux.HandleFunc("GET /api/queue/deny-link/{token}", h.Govern.DenyLink)
	mux.HandleFunc("POST /api/queue/approve-link/{token}", h.Govern.ApproveLinkConfirm)
	mux.HandleFunc("POST /api/queue/deny-link/{token}", h.Govern.DenyLinkConfirm)

	mux.HandleFunc("GET /api/policy", authH.RequireAuth(h.Policy.Get))
	mux.HandleFunc("PUT /api/policy", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, h.Policy.Update))))

	mux.HandleFunc("GET /api/keys", authH.RequireAuth(h.APIKey.List))
	mux.HandleFunc("POST /api/keys", authH.RequireAuth(authH.RequireSession(h.APIKey.Create)))
	mux.HandleFunc("DELETE /api/keys/{id}", authH.RequireAuth(authH.RequireSession(h.APIKey.Delete)))

	mux.HandleFunc("GET /api/compliance", authH.RequireAuth(h.Compliance.Get))
	mux.HandleFunc("GET /api/compliance/frameworks", authH.RequireAuth(h.Compliance.ListFrameworks))
	mux.HandleFunc("GET /api/compliance/frameworks/{id}", authH.RequireAuth(h.Compliance.GetFramework))
	// The auditor export is a bulk read of failing resources per requirement:
	// analysts and admins, not viewers.
	mux.HandleFunc("GET /api/compliance/frameworks/{id}/export", authH.RequireAuth(auth.RequireRole(auth.RoleAnalyst, h.Compliance.ExportFramework)))

	if h.Chat != nil {
		mux.HandleFunc("POST /api/chat", authH.RequireAuth(llm(h.Chat.Stream)))
	}
	// CVEs newly added to CISA KEV (the kev.added record). Read-only.
	if h.KEV != nil {
		mux.HandleFunc("GET /api/kev/additions", authH.RequireAuth(h.KEV.Additions))
	}
	// LLM spend against the monthly budgets: admin-only, it is cost data.
	if h.LLMUsage != nil {
		mux.HandleFunc("GET /api/llm/usage", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.LLMUsage.Summary)))
	}

	// One route, cheap and costly tools: the LLM-backed and alert-context
	// tools spend from the same per-user limiters as /api/chat and
	// /api/context/alert (mcp/limits.go).
	if h.MCP != nil {
		h.MCP.WithLimits(llmLimiter, alertLimiter).
			WithScanLimit(auth.NewKeyedLimiter(DefaultMCPScanStartPerUserPerMinute, DefaultMCPScanStartPerUserPerMinute)).
			WithCypherLimit(cypherLimiter)
	}
	mux.HandleFunc("POST /api/mcp", authH.RequireAuth(h.MCP.ServeHTTP))

	// Provider webhooks (event-driven freshness). NOT session-authed —
	// the caller is the provider; authenticity is the HMAC signature verified in
	// the handler against the connector's stored webhook secret.
	mux.HandleFunc("POST /api/webhooks/github/{id}", h.Webhook.GitHub)

	// Auth required: graph readiness and replica health are estate details; the
	// SPA only polls it once signed in, and probes use /readyz.
	mux.HandleFunc("GET /api/graph/status", authH.RequireAuth(h.Explore.Status))
	// Auth required: it runs every named query against the graph, and which ones
	// return rows is itself information about the estate.
	mux.HandleFunc("GET /api/graph/queries/health", authH.RequireAuth(cypherPool(h.Explore.QueryHealth)))
	mux.HandleFunc("GET /api/graph/stats", authH.RequireAuth(h.Explore.Stats))
	mux.HandleFunc("POST /api/graph/query", authH.RequireAuth(h.Explore.Query))
	mux.HandleFunc("POST /api/graph/translate", authH.RequireAuth(llm(h.Explore.Translate)))
	mux.HandleFunc("GET /api/graph/expand", authH.RequireAuth(h.Explore.Expand))
	mux.HandleFunc("POST /api/graph/cypher", authH.RequireAuth(cypherPool(h.Explore.Cypher)))
	mux.HandleFunc("POST /api/graph/nl", authH.RequireAuth(llm(h.Explore.NL)))

	// Data Security (DSPM). Tile counts and the worklist predicate are computed
	// server-side (explore/dspm.go) rather than as raw Cypher built in the
	// browser, so the claims are testable.
	mux.HandleFunc("GET /api/dspm/summary", authH.RequireAuth(cypherPool(h.Explore.DSPMSummary)))
	mux.HandleFunc("GET /api/dspm/stores", authH.RequireAuth(cypherPool(h.Explore.DSPMStores)))

	// Catch-all: serve the embedded SPA (login/auth is enforced client-side via
	// /api/auth/me; API routes above take precedence over this). Unmatched
	// /api/ paths get a problem response instead of index.html.
	mux.Handle(apiFallbackPattern, apiFallback(mux))
	mux.Handle("/", web.Handler())

	mux.HandleFunc("GET /api/scans", authH.RequireAuth(h.Scan.List))
	mux.HandleFunc("GET /api/scans/{id}", authH.RequireAuth(h.Scan.Get))
	mux.HandleFunc("GET /api/scans/{id}/findings", authH.RequireAuth(h.Scan.GetFindings))
	mux.HandleFunc("POST /api/scans", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Scan.Trigger)))
	mux.HandleFunc("POST /api/scans/import", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Scan.ImportFindings)))
	mux.HandleFunc("DELETE /api/scans/{id}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Scan.Cancel)))
	// Template editor — admin-only throughout: validate builds a nuclei engine
	// per call, test runs active nuclei probes against live URLs, and generate
	// makes up to three LLM calls per request.
	mux.HandleFunc("POST /api/scans/templates/validate", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.ScanTemplate.Validate)))
	mux.HandleFunc("POST /api/scans/templates/test", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.ScanTemplate.Test)))
	mux.HandleFunc("POST /api/scans/templates/generate", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, llm(h.ScanTemplate.Generate))))

	// Scan profiles — /api/scan-profiles/ (not /api/scans/profiles/ which conflicts
	// with /api/scans/{id}/findings in Go 1.22 ServeMux pattern matching).
	mux.HandleFunc("GET /api/scan-profiles", authH.RequireAuth(h.ScanProfile.ListProfiles))
	mux.HandleFunc("POST /api/scan-profiles", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.ScanProfile.CreateProfile)))
	mux.HandleFunc("GET /api/scan-profiles/{id}", authH.RequireAuth(h.ScanProfile.GetProfile))
	mux.HandleFunc("PUT /api/scan-profiles/{id}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.ScanProfile.UpdateProfile)))
	mux.HandleFunc("DELETE /api/scan-profiles/{id}", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.ScanProfile.DeleteProfile)))
	mux.HandleFunc("POST /api/scan-profiles/{id}/trigger", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.ScanProfile.TriggerProfileScan)))
	// Workflow presets — static catalog, no auth needed.
	mux.HandleFunc("GET /api/workflows/presets", scan.WorkflowPresets)

	mux.HandleFunc("GET /api/connectors", authH.RequireAuth(h.Connector.List))
	mux.HandleFunc("POST /api/connectors", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Connector.Create)))
	mux.HandleFunc("DELETE /api/connectors/{id}", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, h.Connector.Delete))))
	mux.HandleFunc("POST /api/connectors/{id}/purge", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, h.Connector.Purge))))
	mux.HandleFunc("POST /api/connectors/{id}/sync", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Connector.TriggerSync)))
	mux.HandleFunc("PUT /api/connectors/{id}/mode", authH.RequireAuth(authH.RequireSession(auth.RequireRole(auth.RoleAdmin, h.Connector.SetMode))))
	mux.HandleFunc("GET /api/connectors/{id}/org-accounts", authH.RequireAuth(h.Connector.OrgAccounts))
	// Admin-only although it writes nothing: it makes live AWS calls with the
	// org connector's credential.
	mux.HandleFunc("POST /api/connectors/{id}/test", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Connector.TestConnection)))
	mux.HandleFunc("GET /api/aws-org/templates/{name}", authH.RequireAuth(h.Connector.OrgTemplate))

	// Executor — cloud remediation actions. Admin-only.
	if h.Executor != nil {
		mux.HandleFunc("POST /api/executor/aws/sg-rule-remove", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.SGRuleRemove)))
		mux.HandleFunc("POST /api/executor/aws/iam-key-disable", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.IAMKeyDisable)))
		mux.HandleFunc("POST /api/executor/execute", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.Execute)))
		// Mints a two-person approval grant for the destructive subset of
		// executor actions. Admin-gated like the executions themselves — the
		// second person must be a second ADMIN, not merely a second session.
		mux.HandleFunc("POST /api/executor/approvals", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.Approve)))
		// Approve-and-run from the decision panel — the same executor path,
		// with the decision supplying connector, action and params. Admin-only,
		// reads included: the plan names connectors and the run's audit rows.
		mux.HandleFunc("GET /api/decisions/{id}/execution", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.PlanDecision)))
		mux.HandleFunc("POST /api/decisions/{id}/execution/dry-run", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.DryRunDecision)))
		mux.HandleFunc("POST /api/decisions/{id}/execution/request", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.RequestDecisionApproval)))
		mux.HandleFunc("POST /api/decisions/{id}/execution/run", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.RunDecision)))
		mux.HandleFunc("POST /api/decisions/{id}/execution/mark-failed", authH.RequireAuth(auth.RequireRole(auth.RoleAdmin, h.Executor.MarkStalledRunFailed)))
	}

	// Cost data — live AWS Cost Explorer snapshots and anomaly detection.
	if h.CostData != nil {
		mux.HandleFunc("GET /api/cost/snapshots", authH.RequireAuth(h.CostData.Snapshots))
		mux.HandleFunc("GET /api/cost/anomalies", authH.RequireAuth(h.CostData.Anomalies))
		// Per-connector collection outcome plus IAM permission needs, so a
		// permission denial never renders as "no cost anomalies".
		mux.HandleFunc("GET /api/cost/status", authH.RequireAuth(h.CostData.Status))
	}

	return newServer(addr, middleware(mux, h.Security))
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// withRequestID attaches the X-Request-ID header (or a generated ID) to the
// context so every log line and problem response carries it. A caller-supplied
// ID is echoed into response headers and every log line, so only a short,
// plain token is accepted; anything else is replaced rather than sanitised.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(log.WithRequestID(r.Context(), id)))
	})
}

// withRecover converts handler panics into logged 500s instead of dropped
// connections.
func withRecover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.FromContext(r.Context()).Error().Any("panic", rec).Msg("handler panicked")
				errs.WriteHTTPError(w, errs.Internal("internal error"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requestDeadline bounds a single request's context, comfortably under the
// server's WriteTimeout (60s) and the ingress's default proxy_read_timeout
// (also 60s). It leaves enough margin for a handler's own error-response
// write plus the wire round-trip after cancellation fires, so a request that
// would otherwise blow the write timeout fails as a clean RFC 9457 response
// instead of a reset connection.
const requestDeadline = 45 * time.Second

// longRequestDeadline bounds routes that legitimately outlive requestDeadline:
// nuclei template tests (the handler allows 5 minutes), LLM template
// generation (up to three model calls), streamed plan refinement, and scan
// imports (a 32 MiB upload can take longer than the server's ReadTimeout).
const longRequestDeadline = 10 * time.Minute

// isLongRunning reports whether r targets one of the longRequestDeadline routes.
func isLongRunning(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	p := r.URL.Path
	return p == "/api/scans/templates/test" || p == "/api/scans/templates/generate" ||
		p == "/api/scans/import" ||
		(strings.HasPrefix(p, "/api/decisions/") && strings.HasSuffix(p, "/refine"))
}

// extendConnDeadlines lifts the server-wide ReadTimeout/WriteTimeout for one
// long-running request, so a large upload is not cut off mid-body and the
// response can still be written. Other requests keep the short server limits.
func extendConnDeadlines(w http.ResponseWriter, r *http.Request, d time.Duration) {
	rc := http.NewResponseController(w)
	until := time.Now().Add(d)
	for _, err := range []error{rc.SetReadDeadline(until), rc.SetWriteDeadline(until)} {
		if err != nil && !errors.Is(err, http.ErrNotSupported) {
			log.FromContext(r.Context()).Warn().Err(err).Msg("httpsrv: cannot extend connection deadline")
		}
	}
}

// withDeadline caps every request's context at requestDeadline, so a handler
// whose downstream call is still running when the deadline hits gets
// ctx.Err() back and can return a normal RFC 9457 error through its existing
// error-mapping path, before WriteTimeout tears the connection down under an
// in-flight write.
//
// /api/chat is excluded: it's a text/event-stream SSE response backing a
// multi-turn agentic loop that can legitimately run well past 45s (its handler
// applies its own cap). Other long-running LLM/scan routes (isLongRunning) get
// longRequestDeadline instead, and this middleware lifts the connection
// read/write deadlines to match (extendConnDeadlines); the streaming handlers
// push the write deadline further themselves via pkg/sse.ExtendWriteDeadline.
func withDeadline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/chat" {
			next.ServeHTTP(w, r)
			return
		}
		deadline := requestDeadline
		if isLongRunning(r) {
			deadline = longRequestDeadline
			extendConnDeadlines(w, r, deadline)
		}
		ctx, cancel := context.WithTimeout(r.Context(), deadline)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validRequestID reports whether id matches [A-Za-z0-9._-]{1,64}.
func validRequestID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

func newRequestID() string {
	raw := make([]byte, 8)
	_, _ = rand.Read(raw) // crypto/rand never fails on supported platforms
	return hex.EncodeToString(raw)
}
