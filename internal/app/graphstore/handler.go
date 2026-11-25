package graphstore

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/graphquery"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

func badRequest(w http.ResponseWriter, msg string) {
	errs.WriteHTTPError(w, errs.InvalidInput(msg))
}

func internalErr(w http.ResponseWriter, err error) {
	errs.WriteHTTPError(w, errs.Internal(err.Error()))
}

// writeQueryError maps a Cypher failure to the problem+json status and
// err_code that explore.LadybugRPCRepo decodes back into the same sentinel on the
// serve pod: a rejected query is INVALID_INPUT (400) carrying the engine's
// reason, an engine timeout TIMEOUT (504); anything else is a 500.
func writeQueryError(w http.ResponseWriter, r *http.Request, err error, msg string) {
	var rej *explore.QueryRejection
	switch {
	case errors.As(err, &rej):
		badRequest(w, rej.Reason)
	case errors.Is(err, explore.ErrQueryTimeout):
		log.FromContext(r.Context()).Warn().Err(err).Msg(msg)
		errs.WriteHTTPError(w, errs.Timeout("graph query timed out"))
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg(msg)
		internalErr(w, err)
	}
}

// Handler exposes the graphstore service over an internal HTTP mux.
// It is mounted on the worker pod's internal listener (port 8090, not Ingress-reachable)
// and called by explore.LadybugRPCRepo in the serve pod via safenet.NewInternal.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Register mounts all internal graph routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/graph/cypher", h.Cypher)
	mux.HandleFunc("POST /internal/graph/seed", h.Seed)
	mux.HandleFunc("POST /internal/graph/neighbors", h.Neighbors)
	mux.HandleFunc("GET /internal/graph/queries", h.ListQueries)
	mux.HandleFunc("POST /internal/graph/queries/{name}", h.RunQuery)
	// Readiness: 200 once the initial graph sync has completed; 503 while still
	// loading. Used by the Kubernetes readinessProbe so the serve pod only routes
	// Ladybug traffic after the graph is actually queryable.
	mux.HandleFunc("GET /internal/graph/ready", h.Ready)
	// Stats: node counts for the serve pod's /api/graph/stats.
	mux.HandleFunc("GET /internal/graph/stats", h.Stats)
	// Health: build state (ready, node count, last build time) for the serve
	// pod's /api/graph/{status,stats}; reads swap-time state, never queries.
	mux.HandleFunc("GET /internal/graph/health", h.Health)
}

// Ready returns 200 once the Ladybug graph has completed its initial sync from
// ClickHouse, 503 otherwise. This prevents the serve pod routing Cypher
// requests to a worker that is still rebuilding its in-memory graph.
func (h *Handler) Ready(w http.ResponseWriter, r *http.Request) {
	if !h.svc.Ready() {
		errs.WriteHTTPError(w, errs.Unavailable("graph not ready"))
		return
	}
	w.WriteHeader(http.StatusOK)
}

type internalStatsResponse struct {
	Assets int64 `json:"assets"`
	Roles  int64 `json:"roles"`
	Repos  int64 `json:"repos"`
}

// Stats returns node counts for the serve pod's /api/graph/stats.
func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	assets, roles, repos, err := h.svc.NodeCounts(r.Context())
	if err != nil {
		internalErr(w, fmt.Errorf("Stats: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(internalStatsResponse{Assets: assets, Roles: roles, Repos: repos})
}

// internalHealthResponse is the worker's build state. LastBuilt is omitted
// when the graph was never built, so the serve pod cannot read a zero time as
// a build.
type internalHealthResponse struct {
	Ready     bool       `json:"ready"`
	NodeCount int64      `json:"node_count"`
	LastBuilt *time.Time `json:"last_built,omitempty"`
	// NodeTablesMeasured is false until a build is published; the serve pod
	// then reports the multi-hop guard as unknown, never as clean.
	NodeTablesMeasured  bool             `json:"node_tables_measured"`
	OversizedNodeTables map[string]int64 `json:"oversized_node_tables,omitempty"`
}

// Health returns the worker graph's build state for the serve pod.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	hl, _ := h.svc.GraphHealth(r.Context())
	resp := internalHealthResponse{
		Ready: hl.Ready, NodeCount: hl.NodeCount,
		NodeTablesMeasured: hl.NodeTablesMeasured, OversizedNodeTables: hl.OversizedNodeTables,
	}
	if t := hl.LastBuiltAt; !t.IsZero() {
		resp.LastBuilt = &t
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// cypherRequest is the body for POST /internal/graph/cypher.
type cypherRequest struct {
	Query    string `json:"query"`
	MaxNodes int    `json:"max_nodes,omitempty"`
	MaxEdges int    `json:"max_edges,omitempty"`
}

// graphResponse is the common response shape — same as the public explore API.
type graphResponse struct {
	Nodes                   []explore.Node   `json:"nodes"`
	Edges                   []explore.Edge   `json:"edges"`
	Truncated               bool             `json:"truncated"`
	Columns                 []string         `json:"columns,omitempty"`
	Rows                    []map[string]any `json:"rows,omitempty"`
	MultiHopMayBeIncomplete bool             `json:"multi_hop_may_be_incomplete"`
}

// Cypher handles POST /internal/graph/cypher.
func (h *Handler) Cypher(w http.ResponseWriter, r *http.Request) {
	var req cypherRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid request body")
		return
	}

	// Safety: allowlist read-only Cypher (see graphquery.IsReadOnly). This is
	// defense-in-depth — the service chokepoint validates again.
	if !graphquery.IsReadOnly(req.Query) {
		if kw := graphquery.Forbidden(req.Query); kw != "" {
			badRequest(w, fmt.Sprintf("keyword %q is not permitted: write, DDL and file/IO operations are not allowed via this endpoint", kw))
			return
		}
		badRequest(w, "only single read-only queries are permitted via this endpoint")
		return
	}

	budget := QueryBudget{MaxNodes: req.MaxNodes, MaxEdges: req.MaxEdges}.Clamp()
	res, err := h.svc.RunCypher(r.Context(), req.Query, budget.MaxNodes, budget.MaxEdges)
	if err != nil {
		writeQueryError(w, r, err, "graphstore: cypher failed")
		return
	}

	writeJSON(w, graphResponse{
		Nodes:                   coalesceNodes(res.Nodes),
		Edges:                   coalesceEdges(res.Edges),
		Truncated:               res.Truncated,
		Columns:                 res.Columns,
		Rows:                    res.Rows,
		MultiHopMayBeIncomplete: res.MultiHopMayBeIncomplete,
	})
}

// seedRequest is the body for POST /internal/graph/seed.
type seedRequest struct {
	IDs      []string `json:"ids,omitempty"`
	Types    []string `json:"types,omitempty"`
	Provider string   `json:"provider,omitempty"`
	Limit    int      `json:"limit,omitempty"`
}

// Seed handles POST /internal/graph/seed.
func (h *Handler) Seed(w http.ResponseWriter, r *http.Request) {
	var req seedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid request body")
		return
	}
	if req.Limit <= 0 || req.Limit > 2000 {
		req.Limit = 500
	}
	nodes, err := h.svc.MatchSeed(r.Context(), explore.NodeMatch{
		IDs: req.IDs, Types: req.Types, Provider: req.Provider,
	}, req.Limit)
	if err != nil {
		internalErr(w, err)
		return
	}
	writeJSON(w, graphResponse{Nodes: coalesceNodes(nodes)})
}

// neighborsRequest is the body for POST /internal/graph/neighbors.
type neighborsRequest struct {
	IDs       []string `json:"ids"`
	EdgeTypes []string `json:"edge_types,omitempty"`
	Direction string   `json:"direction,omitempty"` // "out" | "in" | "both"
}

// Neighbors handles POST /internal/graph/neighbors.
func (h *Handler) Neighbors(w http.ResponseWriter, r *http.Request) {
	var req neighborsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		badRequest(w, "invalid request body")
		return
	}
	dir := explore.Direction(req.Direction)
	if dir == "" {
		dir = explore.DirectionOut
	}
	edges, nodes, truncated, err := h.svc.Neighbors(r.Context(), req.IDs, req.EdgeTypes, dir)
	if err != nil {
		internalErr(w, err)
		return
	}
	writeJSON(w, graphResponse{
		Nodes:     coalesceNodes(nodes),
		Edges:     coalesceEdges(edges),
		Truncated: truncated,
	})
}

// StartInternalServer starts the internal RPC listener on addr (e.g. ":8090").
// Called from cmd/graph/worker.go. secret is the shared secret required on every
// route except the readiness probe. Empty secret is fail-closed: the listener
// refuses to start unless LADYBUG_RPC_INSECURE=true explicitly opts into an
// unauthenticated RPC (dev/docker-compose) — mirroring the BYPASS_AUTH pattern.
// An unauthenticated RPC lets any in-cluster pod query the graph.
func StartInternalServer(ctx context.Context, h *Handler, addr, secret string) error {
	mux := http.NewServeMux()
	h.Register(mux)
	if secret == "" {
		if os.Getenv("LADYBUG_RPC_INSECURE") != "true" {
			return errors.New("graphstore: LADYBUG_RPC_SECRET unset — refusing to serve an unauthenticated internal RPC; set the secret or explicitly set LADYBUG_RPC_INSECURE=true (dev only)")
		}
		log.FromContext(ctx).Warn().Msg(
			"SECURITY: LADYBUG_RPC_INSECURE=true — internal RPC is unauthenticated; any in-cluster pod can query the graph")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("StartInternalServer: listen %s: %w", addr, err)
	}
	srv := newInternalServer(requireRPCSecret(secret, mux))
	// Deferred recover, not cmd/graph's safego: safego is package main and this is
	// a library package. A panic here would kill the whole single-binary worker
	// pod — this goroutine outlives every request, so an unrecovered panic in it is
	// a restart loop, not a degraded subsystem. Same shape as the shutdown watcher
	// in cmd/graph/worker.go, which safego already covers.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.FromContext(ctx).Error().Str("goroutine", "graphstore-rpc-shutdown").
					Interface("panic", r).Msg("background goroutine panicked — recovered, subsystem is now stopped")
			}
		}()
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	log.FromContext(ctx).Info().Str("addr", ln.Addr().String()).Msg("graphstore: internal RPC listening")
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("StartInternalServer: %w", err)
	}
	return nil
}

// Internal RPC server timeouts. The secret check runs only after net/http has
// read the request header, so without a header deadline a client that never
// finishes one holds a goroutine and a socket without knowing the secret. The
// write deadline spans the whole handler, so it outlasts the longest engine
// budget any route runs and the longest the serve pod waits for a reply; a
// shorter one would cut off a legitimate long query mid-response.
const (
	rpcReadHeaderTimeout = 5 * time.Second
	rpcReadTimeout       = 10 * time.Second
	rpcWriteTimeout      = max(defaultQueryTimeout, blastRadiusTimeout,
		explore.LadybugRPCTimeout, explore.LadybugRPCCypherTimeout) + 10*time.Second
	// Longer than the serve side's idle-connection timeout (safenet, 60s), so
	// the client retires an idle connection before the server closes it under
	// a request that is already on the wire.
	rpcIdleTimeout = 2 * time.Minute
)

func newInternalServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: rpcReadHeaderTimeout,
		ReadTimeout:       rpcReadTimeout,
		WriteTimeout:      rpcWriteTimeout,
		IdleTimeout:       rpcIdleTimeout,
	}
}

// requireRPCSecret enforces the shared secret on every route except the
// readiness probe (the kubelet cannot send the header). Empty secret =
// enforcement disabled (the startup warning already fired). Constant-time
// compare so a wrong secret can't be timing-probed.
func requireRPCSecret(secret string, next http.Handler) http.Handler {
	if secret == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/graph/ready" {
			next.ServeHTTP(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(explore.LadybugRPCAuthHeader)), []byte(secret)) != 1 {
			errs.WriteHTTPError(w, errs.Forbidden("internal RPC: invalid or missing auth"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// queryMeta is the list-queries response shape for a single entry.
type queryMeta struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Params      []string `json:"params,omitempty"`
}

// ListQueries handles GET /internal/graph/queries — returns the named query catalog.
func (h *Handler) ListQueries(w http.ResponseWriter, _ *http.Request) {
	out := make([]queryMeta, len(NamedQueries))
	for i, q := range NamedQueries {
		out[i] = queryMeta{Name: q.Name, Description: q.Description, Params: q.Params}
	}
	writeJSON(w, out)
}

// runQueryRequest is the body for POST /internal/graph/queries/{name}.
type runQueryRequest struct {
	Params   map[string]string `json:"params,omitempty"`
	MaxNodes int               `json:"max_nodes,omitempty"`
	MaxEdges int               `json:"max_edges,omitempty"`
}

// RunQuery handles POST /internal/graph/queries/{name}.
func (h *Handler) RunQuery(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		badRequest(w, "query name required")
		return
	}

	var req runQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Body is optional — params may be empty for queries with no placeholders.
		req = runQueryRequest{}
	}

	res, err := h.svc.RunNamedQuery(r.Context(), name, req.Params)
	if err != nil {
		writeQueryError(w, r, err, "graphstore: named query "+name+" failed")
		return
	}

	writeJSON(w, graphResponse{
		Nodes:                   coalesceNodes(res.Nodes),
		Edges:                   coalesceEdges(res.Edges),
		Truncated:               res.Truncated,
		MultiHopMayBeIncomplete: res.MultiHopMayBeIncomplete,
	})
}

func coalesceNodes(nodes []explore.Node) []explore.Node {
	if nodes == nil {
		return []explore.Node{}
	}
	return nodes
}

func coalesceEdges(edges []explore.Edge) []explore.Edge {
	if edges == nil {
		return []explore.Edge{}
	}
	return edges
}
