package explore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/vulngraph/vulngraph/internal/graphquery"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// CypherRunner executes a raw Cypher query (read-only). *graphstore.Service
// satisfies this via its RunCypher method. When nil, the /api/graph/cypher
// endpoint returns 503 (Ladybug not available).
type CypherRunner interface {
	RunCypher(ctx context.Context, query string, maxNodes, maxEdges int) (Result, error)
}

// NodeStatsProvider is the graph engine's own account of its size and build
// state, behind GET /api/graph/{status,stats} and MCP get_graph_stats.
// *graphstore.Service (in-process replica), *LadybugRPCRepo (worker RPC) and
// *TieredStats satisfy it. When nil, Status reports not_configured and Stats
// answers 503.
type NodeStatsProvider interface {
	NodeCounts(ctx context.Context) (assets, roles, repos int64, err error)
	GraphHealth(ctx context.Context) (GraphHealth, error)
}

// NamedQueryEntry is a query from the catalog that QueryHealth can probe.
// Defined here to avoid importing graphstore (which imports explore).
type NamedQueryEntry struct {
	Name   string
	Query  string
	Params []string
}

type Handler struct {
	svc          *Service
	cypher       CypherRunner      // optional; nil when Ladybug is not running
	nodeStats    NodeStatsProvider // optional; nil when no graph engine is configured
	namedQueries []NamedQueryEntry
}

func NewHandler(svc *Service, cypher CypherRunner) *Handler {
	return &Handler{svc: svc, cypher: cypher}
}

// WithNodeStats wires the NodeStatsProvider behind GET /api/graph/{status,stats}.
func (h *Handler) WithNodeStats(ns NodeStatsProvider) *Handler {
	h.nodeStats = ns
	return h
}

// WithNamedQueries registers the named query catalog for QueryHealth probing.
func (h *Handler) WithNamedQueries(qs []NamedQueryEntry) *Handler {
	h.namedQueries = qs
	return h
}

// Query runs a GraphQuerySpec. Route: POST /api/graph/query.
func (h *Handler) Query(w http.ResponseWriter, r *http.Request) {
	var spec GraphQuerySpec
	if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be a GraphQuerySpec"))
		return
	}
	res, err := h.svc.Run(r.Context(), spec)
	if errors.Is(err, ErrNoSeed) || errors.Is(err, ErrInvalidSpec) {
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("graph query failed")
		errs.WriteHTTPError(w, errs.Internal("graph query failed"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, res.NonNil())
}

type translateRequest struct {
	NaturalLanguage string `json:"natural_language"`
}

// Translate turns NL into a query spec (does NOT run it). Route:
// POST /api/graph/translate. Returns the spec for the client to review + submit.
func (h *Handler) Translate(w http.ResponseWriter, r *http.Request) {
	var req translateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON"))
		return
	}
	spec, err := h.svc.Translate(r.Context(), req.NaturalLanguage)
	switch {
	case errors.Is(err, ErrTranslateUnavailable):
		errs.WriteHTTPError(w, errs.InvalidInput("query translation is not configured"))
		return
	case errors.Is(err, ErrNoSeed):
		errs.WriteHTTPError(w, errs.InvalidInput("could not derive a query from that question"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("graph translate failed")
		errs.WriteHTTPError(w, errs.Internal("translation failed"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, spec)
}

// nlRequest is the body for POST /api/graph/nl.
type nlRequest struct {
	Question string `json:"question"`
	MaxNodes int    `json:"max_nodes,omitempty"`
	MaxEdges int    `json:"max_edges,omitempty"`
}

// nlResponse wraps the graph result plus the generated Cypher so the UI can
// show the analyst exactly what query ran — inspectable and copyable.
type nlResponse struct {
	Result
	GeneratedCypher string `json:"generated_cypher"`
}

// NL handles POST /api/graph/nl — turns a natural-language question into a
// Ladybug Cypher query via the configured LLM provider and executes it against
// the graph in one step, within the requested (clamped) node/edge caps.
// The response includes the generated Cypher so analysts can see, copy, and
// refine it manually via POST /api/graph/cypher.
func (h *Handler) NL(w http.ResponseWriter, r *http.Request) {
	if h.cypher == nil {
		errs.WriteHTTPError(w, errs.Unavailable("graph engine not available"))
		return
	}
	var req nlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with a question field"))
		return
	}
	if req.Question == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("question is required"))
		return
	}

	res, cypher, err := h.svc.TranslateAndRunCypher(r.Context(), h.cypher, req.Question, req.MaxNodes, req.MaxEdges)
	switch {
	case errors.Is(err, ErrTranslateUnavailable):
		errs.WriteHTTPError(w, errs.InvalidInput("NL query translation is not configured (set an LLM provider: LLM_PROVIDER/LLM_API_KEY or ANTHROPIC_API_KEY)"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Str("question", req.Question).
			Str("cypher", cypher).Msg("nl graph query failed")
		errs.WriteHTTPError(w, errs.Internal("query failed"))
		return
	}

	writeJSON(r.Context(), w, http.StatusOK, nlResponse{Result: res.NonNil(), GeneratedCypher: cypher})
}

// Expand returns a node's neighborhood. Route: GET /api/graph/expand?id=&dir=.
func (h *Handler) Expand(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	dir := Direction(r.URL.Query().Get("dir"))
	res, err := h.svc.ExpandNode(r.Context(), id, r.URL.Query()["edge_type"], dir)
	if errors.Is(err, ErrInvalidSpec) {
		errs.WriteHTTPError(w, errs.InvalidInput("id is required"))
		return
	}
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("graph expand failed")
		errs.WriteHTTPError(w, errs.Internal("graph expand failed"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, res.NonNil())
}

// cypherRequest is the body for POST /api/graph/cypher.
type cypherRequest struct {
	Query    string `json:"query"`
	MaxNodes int    `json:"max_nodes,omitempty"`
	MaxEdges int    `json:"max_edges,omitempty"`
}

// QueryHealth probes every named query with maxNodes/maxEdges 1 and reports which pass.
// Route: GET /api/graph/queries/health — authenticated (read-only, no data
// returned; probe errors are logged, never echoed). An operator diagnostic: no
// frontend page calls it (Explore marks a library query broken only after the
// user runs it, so page load adds no Ladybug load).
//
// Healthy means "probed and did not error". That alone is not enough: a query
// whose rel table is empty parses fine and returns nothing forever, so
// `healthy: true` was reported for the three CIEM queries built on
// CanEscalateTo while zero such edges existed, and for every query traversing
// HasRole/ProtectedBy while those edges were being dropped at Ladybug load.
// Empty is therefore reported separately — a parses-but-can-never-return query
// is a real defect that must be visible, not a pass. Probed distinguishes "we
// checked" from the parameterised entries we cannot check at all, which report
// healthy: false because nothing was measured.
func (h *Handler) QueryHealth(w http.ResponseWriter, r *http.Request) {
	type result struct {
		Name    string `json:"name"`
		Healthy bool   `json:"healthy"`
		Probed  bool   `json:"probed"`
		Empty   bool   `json:"empty,omitempty"`
		Error   string `json:"error,omitempty"`
	}
	if h.cypher == nil {
		errs.WriteHTTPError(w, errs.Unavailable("graph engine not available"))
		return
	}
	results := make([]result, 0, len(h.namedQueries))
	for _, q := range h.namedQueries {
		if len(q.Params) > 0 {
			// Parameterised queries can't be probed without values.
			results = append(results, result{Name: q.Name, Healthy: false, Probed: false})
			continue
		}
		// Cap to 1 node via maxNodes — keeps the probe fast without
		// rewriting the query's own LIMIT clause.
		probeCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		res, err := h.cypher.RunCypher(probeCtx, q.Query, 1, 1)
		cancel()
		if err != nil {
			// The raw engine error can carry query text and graph internals; it
			// goes to the log, and the caller gets a fixed category.
			log.FromContext(r.Context()).Warn().Err(err).Str("query", q.Name).Msg("named query health probe failed")
			msg := "probe failed (see server logs)"
			if errors.Is(err, context.DeadlineExceeded) {
				msg = "probe timed out"
			}
			results = append(results, result{Name: q.Name, Healthy: false, Probed: true, Error: msg})
			continue
		}
		// Rows covers the scalar/tabular shape, Nodes the graph shape — a query
		// populates one or the other, so emptiness means neither produced anything.
		empty := len(res.Nodes) == 0 && len(res.Rows) == 0
		results = append(results, result{Name: q.Name, Healthy: true, Probed: true, Empty: empty})
	}
	writeJSON(r.Context(), w, http.StatusOK, results)
}

// Graph engine states reported by Status.
const (
	graphStateNotConfigured = "not_configured" // no graph engine wired: Cypher answers 503
	graphStateUnknown       = "unknown"        // the engine's build state could not be read; Cypher may still answer
	graphStateNotReady      = "not_ready"      // engine reachable, no non-empty build loaded yet
	graphStateReady         = "ready"          // a built, non-empty graph is serving
)

// statusResponse is the JSON shape returned by Status. The build fields are
// omitted when the build state is unknown, and the build time when the graph was
// never built: an absent value is unknown, never a fresh build.
type statusResponse struct {
	Ready        bool       `json:"ready"`
	State        string     `json:"state"`
	NodeCount    *int64     `json:"node_count,omitempty"`
	LastBuiltAt  *time.Time `json:"last_built_at,omitempty"`
	StaleSeconds *int       `json:"stale_seconds,omitempty"`
	// MultiHopMayBeIncomplete is absent until a loaded build recorded its
	// node-table sizes; false is a measurement, never a default.
	MultiHopMayBeIncomplete *bool                   `json:"multi_hop_may_be_incomplete,omitempty"`
	OversizedNodeTables     []nodeTableSizeResponse `json:"oversized_node_tables,omitempty"`
}

// nodeTableSizeResponse is one node table above one engine node group.
type nodeTableSizeResponse struct {
	Label string `json:"label"`
	Rows  int64  `json:"rows"`
}

// multiHopFields renders GraphHealth's multi-hop guard: nil when nothing was
// measured, and the oversized tables sorted by label.
func multiHopFields(hl GraphHealth) (*bool, []nodeTableSizeResponse) {
	incomplete, known := hl.MultiHopMayBeIncomplete()
	if !known {
		return nil, []nodeTableSizeResponse{}
	}
	tables := make([]nodeTableSizeResponse, 0, len(hl.OversizedNodeTables))
	for label, rows := range hl.OversizedNodeTables {
		tables = append(tables, nodeTableSizeResponse{Label: label, Rows: rows})
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Label < tables[j].Label })
	return &incomplete, tables
}

// Status reports whether the graph engine has a built graph to serve.
// Route: GET /api/graph/status — used by the frontend to tell "graph loading"
// (restart, snapshot restore, rebuild) and "no graph engine" apart from "query
// returned empty" (no data matches this pattern). ready is true only when a
// Cypher runner is wired AND its engine reports a completed, non-empty build;
// a wired runner alone says nothing about whether a graph is loaded, so a
// runner with no build-state source is unknown, not not_configured.
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	if h.cypher == nil {
		writeJSON(r.Context(), w, http.StatusOK, statusResponse{State: graphStateNotConfigured})
		return
	}
	if h.nodeStats == nil {
		writeJSON(r.Context(), w, http.StatusOK, statusResponse{State: graphStateUnknown})
		return
	}
	hl, err := h.nodeStats.GraphHealth(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Warn().Err(err).Msg("graph status: graph health unavailable")
		writeJSON(r.Context(), w, http.StatusOK, statusResponse{State: graphStateUnknown})
		return
	}
	resp := statusResponse{Ready: hl.Ready, State: graphStateNotReady, NodeCount: &hl.NodeCount}
	if hl.Ready {
		resp.State = graphStateReady
	}
	if t := hl.LastBuiltAt; !t.IsZero() {
		built := t.UTC()
		stale := int(time.Since(t).Seconds())
		resp.LastBuiltAt, resp.StaleSeconds = &built, &stale
	}
	resp.MultiHopMayBeIncomplete, resp.OversizedNodeTables = multiHopFields(hl)
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

// statsResponse is the JSON shape returned by Stats. LastRebuilt is null when
// the graph was never built.
type statsResponse struct {
	Nodes       statsNodes `json:"nodes"`
	LastRebuilt *time.Time `json:"last_rebuilt"`
	Ready       bool       `json:"ready"`
	// MultiHopMayBeIncomplete is null until a loaded build recorded its
	// node-table sizes.
	MultiHopMayBeIncomplete *bool                   `json:"multi_hop_may_be_incomplete"`
	OversizedNodeTables     []nodeTableSizeResponse `json:"oversized_node_tables"`
}

type statsNodes struct {
	Assets int64 `json:"assets"`
	Roles  int64 `json:"roles"`
	Repos  int64 `json:"repos"`
}

// Stats returns node counts and build state for the graph engine.
// Route: GET /api/graph/stats — auth required, no admin gate. With no graph
// engine configured, or when the engine's build state cannot be read (the
// worker is unreachable or does not serve /internal/graph/health), it answers 503
// rather than zero counts or a guessed readiness.
func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	if h.nodeStats == nil {
		errs.WriteHTTPError(w, errs.Unavailable("graph engine not configured"))
		return
	}
	hl, err := h.nodeStats.GraphHealth(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Warn().Err(err).Msg("graph stats: graph health unavailable")
		errs.WriteHTTPError(w, errs.Unavailable("graph build state unavailable"))
		return
	}
	assets, roles, repos, err := h.nodeStats.NodeCounts(r.Context())
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("graph stats: node counts failed")
		errs.WriteHTTPError(w, errs.Internal("graph stats unavailable"))
		return
	}
	resp := statsResponse{
		Nodes: statsNodes{Assets: assets, Roles: roles, Repos: repos},
		Ready: hl.Ready,
	}
	if !hl.LastBuiltAt.IsZero() {
		built := hl.LastBuiltAt.UTC()
		resp.LastRebuilt = &built
	}
	resp.MultiHopMayBeIncomplete, resp.OversizedNodeTables = multiHopFields(hl)
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

// Cypher executes a raw Cypher query and returns {nodes, edges, truncated}.
// The Ladybug graphstore backs this; returns 503 when Ladybug is unavailable.
// Route: POST /api/graph/cypher.
func (h *Handler) Cypher(w http.ResponseWriter, r *http.Request) {
	if h.cypher == nil {
		errs.WriteHTTPError(w, errs.Unavailable("graph engine not available"))
		return
	}
	var req cypherRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON with a query field"))
		return
	}
	if req.Query == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("query is required"))
		return
	}
	// A query the read-only guard rejects is the caller's error (400): refuse
	// it here, before spending an engine (or worker RPC) round trip.
	if msg := cypherRejection(req.Query); msg != "" {
		errs.WriteHTTPError(w, errs.InvalidInput(msg))
		return
	}
	maxNodes, maxEdges := cypherCaps(req.MaxNodes, req.MaxEdges)
	res, err := h.cypher.RunCypher(r.Context(), req.Query, maxNodes, maxEdges)
	var rej *QueryRejection
	switch {
	case errors.As(err, &rej):
		// Syntax/binder/catalog errors carry the engine's reason, in-process or
		// across the worker RPC; it can quote only the caller's own query.
		errs.WriteHTTPError(w, errs.InvalidInput(rej.Reason))
		return
	case errors.Is(err, ErrQueryTimeout):
		log.FromContext(r.Context()).Warn().Err(err).Msg("graph cypher timed out")
		errs.WriteHTTPError(w, errs.Timeout("graph query timed out; narrow the MATCH or add a LIMIT"))
		return
	case err != nil:
		log.FromContext(r.Context()).Error().Err(err).Msg("graph cypher failed")
		errs.WriteHTTPError(w, errs.Internal("graph cypher failed"))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, res.NonNil())
}

// cypherRejection explains why the read-only guard refuses q, or returns ""
// when q is acceptable.
func cypherRejection(q string) string {
	if graphquery.IsReadOnly(q) {
		return ""
	}
	if kw := graphquery.Forbidden(q); kw != "" {
		return fmt.Sprintf("keyword %q is not permitted: only read-only queries can run", kw)
	}
	return "only a single read-only query (MATCH/OPTIONAL MATCH/WITH/UNWIND/RETURN) is permitted"
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
