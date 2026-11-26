package graphstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/graphquery"
)

// ─── Query timeouts ───────────────────────────────────────────────────────────

const (
	// defaultQueryTimeout caps ordinary Cypher queries (named queries, RunCypher).
	// Prevents a runaway traversal from holding the Ladybug read pool indefinitely.
	defaultQueryTimeout = 10 * time.Second

	// blastRadiusTimeout is used for known-expensive blast_radius* named queries
	// that fan out across many hops. 3× the default gives headroom without
	// blocking the pool as long as a hung query would.
	blastRadiusTimeout = 30 * time.Second
)

// ─── Query methods ────────────────────────────────────────────────────────────

// MatchSeed implements explore.Repo.MatchSeed.
func (s *Service) MatchSeed(ctx context.Context, m explore.NodeMatch, limit int) ([]explore.Node, error) {
	var nodes []explore.Node
	err := s.withRead(ctx, defaultQueryTimeout, func(conn *ladybug.Connection) error {
		var e error
		nodes, e = matchSeed(conn, m.IDs, m.Types, m.Provider, limit)
		return e
	})
	return nodes, err
}

// Neighbors implements explore.Repo.Neighbors.
func (s *Service) Neighbors(ctx context.Context, ids, edgeTypes []string, dir explore.Direction) ([]explore.Edge, []explore.Node, bool, error) {
	var edges []explore.Edge
	var nodes []explore.Node
	var truncated bool
	err := s.withRead(ctx, defaultQueryTimeout, func(conn *ladybug.Connection) error {
		var e error
		edges, nodes, truncated, e = neighbors(conn, ids, edgeTypes, string(dir), DefaultBudget)
		return e
	})
	return edges, nodes, truncated, err
}

// RunCypherBudget executes raw Cypher with an explicit budget struct.
//
// Read-only enforcement lives HERE, at the service chokepoint, not only in the
// worker RPC handler: when the serve pod runs an in-process Ladybug replica its
// cypher runner is wired straight to this Service, bypassing the RPC handler's
// guard. Validating here means every transport (RPC and in-process) rejects
// writes, so an authenticated user cannot DETACH DELETE / SET the graph via the
// public /api/graph/cypher endpoint.
func (s *Service) RunCypherBudget(ctx context.Context, query string, budget QueryBudget) (explore.Result, error) {
	if !graphquery.IsReadOnly(query) {
		reason := "only single read-only queries are permitted"
		if kw := graphquery.Forbidden(query); kw != "" {
			reason = fmt.Sprintf("keyword %q is not permitted", kw)
		}
		return explore.Result{}, fmt.Errorf("RunCypherBudget: %w: %w", ErrReadOnly, &explore.QueryRejection{Reason: reason})
	}
	var res explore.Result
	err := s.withCypher(ctx, func(conn *ladybug.Connection) error {
		var e error
		res, e = execCypher(conn, query, budget.Clamp())
		return e
	})
	// Running out of time waiting for a connection, or before the engine's own
	// timeout fired, is the same outcome to the caller as an engine interrupt.
	if errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, explore.ErrQueryTimeout) {
		err = fmt.Errorf("%w: %w", explore.ErrQueryTimeout, err)
	}
	return res, err
}

// BlastRadiusCount returns reachable asset count from seedID in depth hops.
// Replaces the sequential ClickHouse BFS in enrich.BlastRadius.
// Results are memoised in blastRadiusCache for the current graph snapshot —
// the same asset ID recurs across many findings, so repeated lookups are served
// from the cache.
func (s *Service) BlastRadiusCount(ctx context.Context, seedID string, depth int) (int, error) {
	key := seedID + ":" + strconv.Itoa(depth)
	if v, ok := s.blastRadiusCache.Load(key); ok {
		return v.(int), nil
	}
	var count int
	err := s.withRead(ctx, blastRadiusTimeout, func(conn *ladybug.Connection) error {
		var e error
		count, e = blastRadiusCount(conn, seedID, depth)
		return e
	})
	if err == nil {
		s.blastRadiusCache.Store(key, count)
	}
	return count, err
}

// RunCypher implements explore.CypherRunner: executes raw Cypher with simple
// integer budget parameters (max_nodes, max_edges).
func (s *Service) RunCypher(ctx context.Context, query string, maxNodes, maxEdges int) (explore.Result, error) {
	queryCtx, cancel := context.WithTimeout(ctx, defaultQueryTimeout)
	defer cancel()
	return s.RunCypherBudget(queryCtx, query, QueryBudget{MaxNodes: maxNodes, MaxEdges: maxEdges}.Clamp())
}

// NodeCounts returns the count of Asset, IamRole, and Repo nodes in the graph.
// Called by the explore handler's GET /api/graph/stats endpoint.
func (s *Service) NodeCounts(ctx context.Context) (assets, roles, repos int64, err error) {
	err = s.withRead(ctx, defaultQueryTimeout, func(conn *ladybug.Connection) error {
		for _, entry := range []struct {
			query string
			dst   *int64
		}{
			{`MATCH (n:Asset) RETURN count(n) AS c LIMIT 1`, &assets},
			{`MATCH (n:IamRole) RETURN count(n) AS c LIMIT 1`, &roles},
			{`MATCH (n:Repo) RETURN count(n) AS c LIMIT 1`, &repos},
		} {
			res, qErr := conn.Query(entry.query)
			if qErr != nil {
				return fmt.Errorf("NodeCounts: %w", qErr)
			}
			n, cErr := scanCount(res)
			res.Close()
			if cErr != nil {
				return fmt.Errorf("NodeCounts %q: %w", entry.query, cErr)
			}
			*entry.dst = n
		}
		return nil
	})
	return assets, roles, repos, err
}

// scanCount reads the single `c` column of a count query. A missing row, a row
// or map error, or an unexpected type is an error: a count of 0 must mean the
// engine counted zero, never that the read failed.
func scanCount(res *ladybug.QueryResult) (int64, error) {
	if !res.HasNext() {
		return 0, errors.New("count query returned no row")
	}
	row, err := res.Next()
	if err != nil {
		return 0, fmt.Errorf("read count row: %w", err)
	}
	m, err := row.GetAsMap()
	row.Close()
	if err != nil {
		return 0, fmt.Errorf("map count row: %w", err)
	}
	switch v := m["c"].(type) {
	case int64:
		return v, nil
	case int32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("count column has type %T", m["c"])
	}
}

// RunNamedQuery executes a pre-built named query from the NamedQueries catalog.
// Params are validated (ID-safe chars only) and substituted into the template.
// Named queries are curated to return graph shape, so the result carries
// nodes, edges, truncation and the multi-hop flag, never scalar rows.
func (s *Service) RunNamedQuery(ctx context.Context, name string, params map[string]string) (explore.Result, error) {
	var q *NamedQuery
	for i := range NamedQueries {
		if NamedQueries[i].Name == name {
			q = &NamedQueries[i]
			break
		}
	}
	if q == nil {
		return explore.Result{}, fmt.Errorf("graphstore: unknown query %q", name)
	}

	// blast_radius and full_blast_radius_3hop are Go-orchestrated — see
	// runBlastRadiusNamedQuery (repo_cypher.go) for why. Their walk is one hop
	// per query, which ladybug#1341 does not affect, so they carry no flag.
	if handled, ns, es, tr, rerr := s.runBlastRadiusNamedQuery(ctx, name, params); handled {
		return explore.Result{Nodes: ns, Edges: es, Truncated: tr}, rerr
	}

	cypher, err := substituteParams(q.Name, q.Query, q.Params, params)
	if err != nil {
		return explore.Result{}, err
	}

	var res explore.Result
	err = s.withRead(ctx, defaultQueryTimeout, func(conn *ladybug.Connection) error {
		var e error
		res, e = execCypher(conn, cypher, HardBudget)
		return e
	})
	return explore.Result{
		Nodes: res.Nodes, Edges: res.Edges, Truncated: res.Truncated,
		MultiHopMayBeIncomplete: res.MultiHopMayBeIncomplete,
	}, err
}

// substituteParams replaces $name placeholders in a query template with
// caller-supplied values, validating each value is ID-safe before substitution.
// queryName is used only in error messages to help callers identify which query
// requires the missing parameter.
func substituteParams(queryName, query string, required []string, provided map[string]string) (string, error) {
	for _, name := range required {
		val, ok := provided[name]
		if !ok || val == "" {
			gotKeys := paramKeyList(provided)
			if gotKeys == "" {
				gotKeys = "none"
			}
			return "", fmt.Errorf("graphstore: query %q requires param %q, got: %s", queryName, name, gotKeys)
		}
		if !safeQueryParam(val) {
			return "", fmt.Errorf("graphstore: param %q contains unsafe characters in query %q", name, queryName)
		}
		query = replaceQueryParam(query, name, val)
	}
	return query, nil
}

// paramKeyList returns a comma-separated list of keys in m, or empty string
// when m is nil/empty. Used to build human-readable "got: key1, key2" error messages.
func paramKeyList(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Sort for deterministic output (aids tests and error messages).
	sortStrings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(k)
	}
	return b.String()
}

// sortStrings is a minimal insertion sort so graphstore needn't import "sort".
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		key := ss[i]
		j := i - 1
		for j >= 0 && ss[j] > key {
			ss[j+1] = ss[j]
			j--
		}
		ss[j+1] = key
	}
}

// safeQueryParam validates that a query parameter value is safe for literal
// substitution into a Cypher query (no Cypher metacharacters).
func safeQueryParam(v string) bool {
	for _, c := range v {
		if !isIDChar(c) {
			return false
		}
	}
	return len(v) > 0
}

func isIDChar(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == ':' || c == '/' || c == '_' ||
		c == '-' || c == '.' || c == '@'
}

func replaceQueryParam(query, name, val string) string {
	placeholder := "$" + name
	var b strings.Builder
	for i := 0; i < len(query); {
		if i+len(placeholder) <= len(query) && query[i:i+len(placeholder)] == placeholder {
			b.WriteByte('\'')
			b.WriteString(val)
			b.WriteByte('\'')
			i += len(placeholder)
		} else {
			b.WriteByte(query[i])
			i++
		}
	}
	return b.String()
}

// IsExposedEdge reports whether id has an ExposedToInternet edge.
// Used by the enrichment fingerprint for cache invalidation.
func (s *Service) IsExposedEdge(ctx context.Context, id string) (bool, error) {
	var exposed bool
	err := s.withRead(ctx, defaultQueryTimeout, func(conn *ladybug.Connection) error {
		var e error
		exposed, e = internetReachable(conn, id)
		return e
	})
	return exposed, err
}

// NodeSignals returns the finding-derived signal columns for an asset: whether
// it is internet-exposed, its highest finding score, and its privilege-escalation
// finding count. These are pre-computed during Ladybug sync from the finding rollup
// so this is a single in-memory point lookup with no ClickHouse reads.
// Returns zero-values when the node is not found (best-effort).
//
// Results are cached in nodeSignalsCache for the lifetime of the current graph.
// This eliminates redundant Ladybug mutex serialisation when the same resourceID is
// looked up multiple times per finding enrichment (fingerprint + AttackPaths +
// ToxicCombo all call this for the same ID). Cache is cleared on SyncFromSources.
//
// Uses nodeSignalByID (an id point lookup on Asset, then IamRole) rather than
// matchSeed, which runs one query for every seedable label.
func (s *Service) NodeSignals(ctx context.Context, id string) (NodeSignals, error) {
	if v, ok := s.nodeSignalsCache.Load(id); ok {
		return v.(NodeSignals), nil
	}
	sig := NodeSignals{InternetHops: ReachUnknown}
	err := s.withRead(ctx, defaultQueryTimeout, func(conn *ladybug.Connection) error {
		n, ok, err := nodeSignalByID(conn, id)
		if err != nil || !ok {
			return err
		}
		sig = NodeSignals{
			Exposed:      n.Exposed,
			HasKEV:       n.HasKEV,
			Exploitable:  n.Exploitable,
			ToxicCombo:   n.ToxicCombo,
			MaxScore:     n.MaxScore,
			PrivescCount: n.PrivescCount,
			InternetHops: n.InternetHops,
		}
		return nil
	})
	if err == nil {
		s.nodeSignalsCache.Store(id, sig)
	}
	return sig, err
}

// TryNodeSignals is the non-blocking variant of NodeSignals: it returns
// ErrPoolBusy immediately when every Ladybug connection is in use, instead of
// blocking. The enrichment fingerprint path uses it so 16 enrich workers can't
// saturate the 8-connection pool and stall the enrich queue for minutes — on
// ErrPoolBusy the caller falls back to ClickHouse (authoritative anyway). Cache
// hits (the common case post-sync) never touch the pool.
func (s *Service) TryNodeSignals(_ context.Context, id string) (NodeSignals, error) {
	if v, ok := s.nodeSignalsCache.Load(id); ok {
		return v.(NodeSignals), nil
	}
	sig := NodeSignals{InternetHops: ReachUnknown}
	err := s.withTryRead(func(conn *ladybug.Connection) error {
		n, ok, err := nodeSignalByID(conn, id)
		if err != nil || !ok {
			return err
		}
		sig = NodeSignals{
			Exposed:      n.Exposed,
			HasKEV:       n.HasKEV,
			Exploitable:  n.Exploitable,
			ToxicCombo:   n.ToxicCombo,
			MaxScore:     n.MaxScore,
			PrivescCount: n.PrivescCount,
			InternetHops: n.InternetHops,
		}
		return nil
	})
	if err == nil {
		s.nodeSignalsCache.Store(id, sig)
	}
	return sig, err
}

// DeployedWorkloadExposed checks whether any workload deployed from the given
// repo IDs is internet-exposed. A repo deploys to a k8s workload via the
// DeploysTo rel (Repo→K8sWorkload) OR to a managed service (ECS/Lambda/Cloud
// Run/Azure WebApp) via DeploysToService (Repo→Asset) — buildEdgeRows reroutes
// non-k8s deploy_to edges to the latter. Both must be checked, or serverless
// deploy targets are silently missed (the CH fallback sees both because the raw
// edge_type is deploys_to for either). Two separate queries so the second is
// skipped once the first finds an exposed workload.
func (s *Service) DeployedWorkloadExposed(ctx context.Context, repoIDs []string) (anyDeployed, anyExposed bool, err error) {
	if !s.synced.Load() || len(repoIDs) == 0 {
		return false, false, fmt.Errorf("ladybug not ready or no repos")
	}
	err = s.withRead(ctx, defaultQueryTimeout, func(conn *ladybug.Connection) error {
		ids := repoIDs
		if len(ids) > maxQueryItems {
			ids = ids[:maxQueryItems]
		}
		idList := make([]any, len(ids))
		for i, id := range ids {
			idList[i] = id
		}
		scan := func(q string) error {
			prepared, prepErr := conn.Prepare(q)
			if prepErr != nil {
				return prepErr
			}
			defer prepared.Close()
			res, execErr := conn.Execute(prepared, map[string]any{"ids": idList})
			if execErr != nil {
				return execErr
			}
			defer res.Close()
			for res.HasNext() {
				row, rowErr := res.Next()
				if rowErr != nil {
					break
				}
				m, _ := row.GetAsMap()
				row.Close()
				if strVal(m["wid"]) != "" {
					anyDeployed = true
					if intVal(m["wexposed"]) != 0 {
						anyExposed = true
						return nil // short-circuit this query
					}
				}
			}
			return nil
		}
		if qErr := scan(`MATCH (r:Repo)-[:DeploysTo]->(w:K8sWorkload) WHERE r.id IN $ids RETURN w.id AS wid, w.exposed AS wexposed LIMIT 200`); qErr != nil {
			return qErr
		}
		if anyExposed {
			return nil
		}
		return scan(`MATCH (r:Repo)-[:DeploysToService]->(w:Asset) WHERE r.id IN $ids RETURN w.id AS wid, w.exposed AS wexposed LIMIT 200`)
	})
	return
}
