package httpsrv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Route is one registered mux pattern, split into method and path.
type Route struct{ Method, Path string }

func (r Route) String() string { return r.Method + " " + r.Path }

// adminGatedRoutes derives every auth.RequireRole-wrapped route straight from
// server.go, by parsing its AST rather than pattern-matching the text. A
// syntax tree finds RequireRole anywhere in the handler expression's call
// tree, at any nesting depth or line break, so it can't be fooled by gofmt
// reflowing a line the way a regex could.
//
// It is deliberately a source parse rather than runtime enumeration: routes
// registered behind a nil-handler guard (intel, alerts, saved queries, cost,
// executor, refine) are invisible to a runtime walk of a partially-wired
// server, and those are exactly the routes most likely to go unguarded.
func adminGatedRoutes(t *testing.T) []Route {
	t.Helper()
	seen := map[Route]bool{}
	var out []Route
	for _, reg := range parseRouteRegistrations(t) {
		if !reg.roleGated || seen[reg.route] {
			continue
		}
		seen[reg.route] = true
		out = append(out, reg.route)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// routeRegistration is one HandleFunc call found in server.go.
type routeRegistration struct {
	route       Route
	roleGated   bool // auth.RequireRole appears somewhere in the handler expression
	sessionOnly bool // authH.RequireSession appears somewhere in it
}

// parseRouteRegistrations returns every mux.HandleFunc("METHOD /path", handler)
// in server.go, with whether its handler expression is role-gated.
func parseRouteRegistrations(t *testing.T) []routeRegistration {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "server.go", nil, 0)
	require.NoError(t, err)

	var out []routeRegistration
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "HandleFunc" {
			return true
		}
		pattern, ok := stringLit(call.Args[0])
		if !ok {
			return true
		}
		method, path, ok := strings.Cut(pattern, " ")
		if !ok || !strings.HasPrefix(path, "/api/") {
			return true
		}
		out = append(out, routeRegistration{
			route:       Route{Method: method, Path: path},
			roleGated:   callTreeMentions(call.Args[1], "auth", "RequireRole"),
			sessionOnly: callTreeMentions(call.Args[1], "authH", "RequireSession"),
		})
		return true
	})
	return out
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// callTreeMentions reports whether pkg.name is called anywhere inside e, at any
// depth — which is what makes this immune to how the registration is wrapped or
// line-broken.
func callTreeMentions(e ast.Expr, pkg, name string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
			found = true
			return false
		}
		return true
	})
	return found
}

// concreteRoute substitutes a placeholder for every {param} segment so the
// route can actually be requested.
func concreteRoute(path string) string {
	return regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "role-gate-probe")
}

func TestAdminGatedRoutes_ParsesTheRouter(t *testing.T) {
	routes := adminGatedRoutes(t)
	require.NotEmpty(t, routes, "no auth.RequireRole routes parsed from server.go — did the registration style change? update roleGatedPattern")

	got := map[string]bool{}
	for _, r := range routes {
		got[r.String()] = true
		require.True(t, strings.HasPrefix(r.Path, "/api/"), "unexpected path %q", r.Path)
		// Every derived path must be requestable, not a literal "{id}".
		concrete := concreteRoute(r.Path)
		require.NotContains(t, concrete, "{", "unsubstituted path param in %q", r.Path)
		require.NotContains(t, concrete, "}", "unsubstituted path param in %q", r.Path)
	}

	// Pinned by name so a regression in the parser cannot quietly shrink the
	// derived set back down to a subset that happens to pass.
	for _, want := range []string{
		"POST /api/findings/{id}/suppress",
		"DELETE /api/findings/{id}/suppress",
		"POST /api/decisions/{id}/refine",
		"POST /api/connectors",
		"DELETE /api/connectors/{id}",
		"POST /api/connectors/{id}/sync",
	} {
		require.Truef(t, got[want], "%s is RequireRole-wrapped in server.go but was not derived", want)
	}
}

// ungatedWriteRoutes are the non-GET routes that deliberately carry no
// auth.RequireRole, each with the reason it is safe. This starts from every
// HandleFunc in server.go, so a write that loses its gate (or is added
// without one) has to be justified here or the test fails.
var ungatedWriteRoutes = map[string]string{
	"POST /api/auth/login":  "the login exchange itself — requiring a role to authenticate is circular",
	"POST /api/auth/logout": "ends the caller's own session; RequireAuth is the whole gate that applies",

	// Self-scoped: both resolve the subject from auth.UserFromContext
	// (apikey/handler.go:68 and :115), so a viewer can only ever create or
	// delete their OWN key. Gating on admin would stop non-admins having an
	// API key at all.
	"POST /api/keys":        "self-scoped — the caller's own key, subject taken from the session",
	"DELETE /api/keys/{id}": "self-scoped — deletes the caller's own key",

	// POST because the query travels in the body, not because anything is
	// written. All four are read paths over the caller's existing visibility.
	// chat, nl and translate spend LLM tokens and are budgeted per user
	// (auth.RateLimitPerUser), not role-gated.
	"POST /api/chat":            "read-only assistant, no state change",
	"POST /api/graph/cypher":    "read-only Cypher, validated by graphquery.IsReadOnly — write Cypher is never exposed",
	"POST /api/graph/nl":        "read-only natural-language query, compiles to the same read-only Cypher",
	"POST /api/graph/query":     "read-only named query by id",
	"POST /api/graph/translate": "read-only — translates a question to Cypher without running it",
	"POST /api/context/alert":   "read-only alert-context lookup; POST only because the identifier list travels in the body",

	// Credentials that are not a session, each carrying its own gate.
	"POST /api/mcp":                        "JSON-RPC seam behind RequireAuth; its admin-gated tools self-check the session role",
	"POST /api/queue/approve-link/{token}": "HMAC bearer token minted by the email notifier IS the credential; no session exists (security: [] in openapi/domains/govern.yaml)",
	"POST /api/queue/deny-link/{token}":    "HMAC bearer token, same contract as approve-link",
	"POST /api/webhooks/github/{id}":       "unauthenticated by design — GitHub cannot hold a session; authenticity is the HMAC signature check in Webhook.GitHub",
}

func TestEveryWriteRouteIsGatedOrExempt(t *testing.T) {
	regs := parseRouteRegistrations(t)
	require.NotEmpty(t, regs, "no HandleFunc registrations parsed from server.go")

	var writes int
	for _, reg := range regs {
		if reg.route.Method == "GET" || reg.route.Method == "HEAD" {
			continue
		}
		writes++
		if reg.roleGated {
			continue
		}
		reason, exempt := ungatedWriteRoutes[reg.route.String()]
		require.Truef(t, exempt,
			"%s changes state and is not auth.RequireRole-wrapped. Gate it, or add it to "+
				"ungatedWriteRoutes with the reason it is safe.", reg.route)
		require.NotEmptyf(t, reason, "%s is exempt with an empty reason", reg.route)
	}
	require.Greaterf(t, writes, 20, "only %d write routes found — the parse is probably broken", writes)

	// The exemption list must not rot: an entry naming a route that no longer
	// exists, or one that is now role-gated, reads as a considered decision
	// and is actually dead text — and a dead entry for a gated route would let
	// that route lose its gate without this test noticing.
	live, ungated := map[string]bool{}, map[string]bool{}
	for _, reg := range regs {
		live[reg.route.String()] = true
		if !reg.roleGated {
			ungated[reg.route.String()] = true
		}
	}
	for r := range ungatedWriteRoutes {
		require.Truef(t, live[r], "ungatedWriteRoutes names %s, which is not registered in server.go", r)
		require.Truef(t, ungated[r], "ungatedWriteRoutes names %s, which is auth.RequireRole-wrapped in server.go: delete the exemption", r)
	}
}

// sessionOnlyRoutes are the admin writes an API key must never make, refused
// with 403 and an auth.api_key_refused row by authH.RequireSession
// (docs/security-hardening.md#api-keys lists them).
var sessionOnlyRoutes = []string{
	"POST /api/users",
	"PATCH /api/users/{id}",
	"DELETE /api/users/{id}",
	"POST /api/users/{id}/revoke-sessions",
	"POST /api/keys",
	"DELETE /api/keys/{id}",
	"PUT /api/connectors/{id}/mode",
	"PUT /api/connectors/{id}/disk-scan",
	"POST /api/connectors/{id}/purge",
	"DELETE /api/connectors/{id}",
	"PUT /api/policy",
	"POST /api/queue/resolve",
}

func TestHighImpactWritesRequireSession(t *testing.T) {
	wrapped := map[string]bool{}
	for _, reg := range parseRouteRegistrations(t) {
		if reg.sessionOnly {
			wrapped[reg.route.String()] = true
		}
	}
	for _, r := range sessionOnlyRoutes {
		require.Truef(t, wrapped[r], "%s must be wrapped in authH.RequireSession", r)
		delete(wrapped, r)
	}
	require.Emptyf(t, wrapped, "RequireSession wraps routes missing from sessionOnlyRoutes (and the docs): %v", wrapped)
}
