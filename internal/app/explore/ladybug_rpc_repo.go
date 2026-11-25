package explore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// LadybugRPCAuthHeader is the shared-secret header the serve pod sends and the
// worker's internal RPC verifies. Defined here (the reader side) because the
// import direction is graphstore → explore, never the reverse.
const LadybugRPCAuthHeader = "X-Ladybug-Auth"

// How long the serve pod waits for each kind of internal RPC. The worker's
// RPC server derives its write deadline from these, so raising one here
// cannot cut a reply off on the worker side.
const (
	// LadybugRPCTimeout bounds the structured seed/neighbors/stats/health
	// calls: short, because those fall back to ClickHouse when Ladybug is down.
	LadybugRPCTimeout = 5 * time.Second
	// LadybugRPCCypherTimeout bounds raw Cypher / NL calls: generous, because
	// Ladybug is the only source for Cypher and a read can queue briefly
	// behind worker writes (single-writer).
	LadybugRPCCypherTimeout = 25 * time.Second
)

// LadybugRPCRepo implements Repo by calling the graphstore internal RPC on the
// worker pod. It is wired into explore.Service in cmd/graph/serve.go when
// LADYBUG_RPC_URL is set; otherwise the ClickHouse BFS repo is used as fallback.
type LadybugRPCRepo struct {
	baseURL string
	secret  string       // LADYBUG_RPC_SECRET; sent as LadybugRPCAuthHeader when non-empty
	client  *http.Client // LadybugRPCTimeout
	cypher  *http.Client // LadybugRPCCypherTimeout
}

// NewLadybugRPCRepo builds the RPC client. secret is the shared secret for the
// worker's internal RPC; empty sends no auth header (matches a worker with
// enforcement disabled).
func NewLadybugRPCRepo(baseURL, secret string) *LadybugRPCRepo {
	return &LadybugRPCRepo{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		secret:  secret,
		client:  safenet.NewInternal(LadybugRPCTimeout),
		cypher:  safenet.NewInternal(LadybugRPCCypherTimeout),
	}
}

// setAuth adds the shared-secret header when a secret is configured.
func (r *LadybugRPCRepo) setAuth(req *http.Request) {
	if r.secret != "" {
		req.Header.Set(LadybugRPCAuthHeader, r.secret)
	}
}

func (r *LadybugRPCRepo) MatchSeed(ctx context.Context, m NodeMatch, limit int) ([]Node, error) {
	body, _ := json.Marshal(map[string]any{
		"ids": m.IDs, "types": m.Types, "provider": m.Provider, "limit": limit,
	})
	var resp graphResp
	if err := r.post(ctx, r.client, "/internal/graph/seed", body, &resp); err != nil {
		return nil, fmt.Errorf("LadybugRPCRepo.MatchSeed: %w", err)
	}
	return resp.Nodes, nil
}

func (r *LadybugRPCRepo) Neighbors(ctx context.Context, ids, edgeTypes []string, dir Direction) ([]Edge, []Node, bool, error) {
	body, _ := json.Marshal(map[string]any{
		"ids": ids, "edge_types": edgeTypes, "direction": string(dir),
	})
	var resp graphResp
	if err := r.post(ctx, r.client, "/internal/graph/neighbors", body, &resp); err != nil {
		return nil, nil, false, fmt.Errorf("LadybugRPCRepo.Neighbors: %w", err)
	}
	return resp.Edges, resp.Nodes, resp.Truncated, nil
}

func (r *LadybugRPCRepo) post(ctx context.Context, client *http.Client, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	r.setAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return rpcError(path, resp)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// rpcError decodes the worker's problem+json failure back into the sentinel
// the worker classified it as (graphstore's writeQueryError), keyed on the
// typed err_code rather than the message: a rejected query stays the caller's
// 400 and an engine timeout stays a timeout across the pod boundary.
func rpcError(path string, resp *http.Response) error {
	var p errs.ErrorResponse
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&p)
	switch p.ErrCode {
	case errs.CodeInvalidInput.String():
		return &QueryRejection{Reason: p.Detail}
	case errs.CodeTimeout.String():
		return fmt.Errorf("RPC %s: %w", path, ErrQueryTimeout)
	}
	return fmt.Errorf("RPC %s: HTTP %d", path, resp.StatusCode)
}

// RunCypher implements explore.CypherRunner — forwards to worker's internal Cypher endpoint.
func (r *LadybugRPCRepo) RunCypher(ctx context.Context, query string, maxNodes, maxEdges int) (Result, error) {
	body, _ := json.Marshal(map[string]any{
		"query": query, "max_nodes": maxNodes, "max_edges": maxEdges,
	})
	var resp graphResp
	if err := r.post(ctx, r.cypher, "/internal/graph/cypher", body, &resp); err != nil {
		return Result{}, fmt.Errorf("LadybugRPCRepo.RunCypher: %w", err)
	}
	return Result(resp), nil
}

type graphResp struct {
	Nodes                   []Node           `json:"nodes"`
	Edges                   []Edge           `json:"edges"`
	Truncated               bool             `json:"truncated"`
	Columns                 []string         `json:"columns"`
	Rows                    []map[string]any `json:"rows"`
	MultiHopMayBeIncomplete bool             `json:"multi_hop_may_be_incomplete"`
}

// rpcStatsResp mirrors graphstore.internalStatsResponse.
type rpcStatsResp struct {
	Assets int64 `json:"assets"`
	Roles  int64 `json:"roles"`
	Repos  int64 `json:"repos"`
}

// rpcHealthResp mirrors graphstore.internalHealthResponse. LastBuilt is absent
// when the worker's graph was never built.
type rpcHealthResp struct {
	Ready               bool             `json:"ready"`
	NodeCount           int64            `json:"node_count"`
	LastBuilt           *time.Time       `json:"last_built"`
	NodeTablesMeasured  bool             `json:"node_tables_measured"`
	OversizedNodeTables map[string]int64 `json:"oversized_node_tables"`
}

// NodeCounts implements explore.NodeStatsProvider via the worker's internal stats endpoint.
func (r *LadybugRPCRepo) NodeCounts(ctx context.Context) (assets, roles, repos int64, err error) {
	var s rpcStatsResp
	if err := r.get(ctx, "/internal/graph/stats", &s); err != nil {
		return 0, 0, 0, fmt.Errorf("LadybugRPCRepo.NodeCounts: %w", err)
	}
	return s.Assets, s.Roles, s.Repos, nil
}

// GraphHealth implements explore.NodeStatsProvider: the worker's own build state
// (ready, node count, last build time), read without running a query.
func (r *LadybugRPCRepo) GraphHealth(ctx context.Context) (GraphHealth, error) {
	var s rpcHealthResp
	if err := r.get(ctx, "/internal/graph/health", &s); err != nil {
		return GraphHealth{}, fmt.Errorf("LadybugRPCRepo.GraphHealth: %w", err)
	}
	h := GraphHealth{
		Ready: s.Ready, NodeCount: s.NodeCount,
		NodeTablesMeasured: s.NodeTablesMeasured, OversizedNodeTables: s.OversizedNodeTables,
	}
	if s.LastBuilt != nil {
		h.LastBuiltAt = *s.LastBuilt
	}
	return h, nil
}

func (r *LadybugRPCRepo) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	r.setAuth(req)
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("GET %s: decode: %w", path, err)
	}
	return nil
}
