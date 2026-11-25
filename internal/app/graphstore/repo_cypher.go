package graphstore

import (
	"context"
	"fmt"
	"sort"
	"strings"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/explore"
)

// runBlastRadiusNamedQuery dispatches "blast_radius" and "full_blast_radius_3hop"
// to blastRadiusGraph instead of executing their catalog Query string: that
// string seeds only the generic Asset label (MATCH (seed:Asset {id: $id})),
// which returns empty for any k8s_*/subnet seed id — the same class of gap
// matchSeed already fixes for structured GraphQuerySpec seeding. The Query
// field stays on both catalog entries as documentation of the approximated
// shape, not executed text. handled=false means the caller should fall
// through to the generic substituteParams→execCypher path for any other
// query name.
func (s *Service) runBlastRadiusNamedQuery(ctx context.Context, name string, params map[string]string) (handled bool, nodes []explore.Node, edges []explore.Edge, truncated bool, err error) {
	if name != "blast_radius" && name != "full_blast_radius_3hop" {
		return false, nil, nil, false, nil
	}
	id, ok := params["id"]
	if !ok || id == "" || !safeQueryParam(id) {
		return true, nil, nil, false, fmt.Errorf("graphstore: query %q requires param %q", name, "id")
	}
	hops := 1
	if name == "full_blast_radius_3hop" {
		hops = 3
	}
	// The deadline bounds the whole multi-query walk; blastRadiusTimeout passed
	// to withRead additionally bounds each engine query.
	queryCtx, cancel := context.WithTimeout(ctx, blastRadiusTimeout)
	defer cancel()
	var res explore.Result
	runErr := s.withRead(queryCtx, blastRadiusTimeout, func(conn *ladybug.Connection) error {
		var e error
		res, e = blastRadiusGraph(conn, id, hops, HardBudget)
		return e
	})
	return true, res.Nodes, res.Edges, res.Truncated, runErr
}

// engineRejectionPrefixes start liblbug's message for a query refused before
// it ran: unparseable, naming an unknown label/property/variable, or calling an
// unknown function. liblbug returns bare message strings (no error codes), so
// this prefix match is the one place the engine's wording is interpreted;
// TestExecCypher_ClassifiesEngineErrors pins it against the linked library.
var engineRejectionPrefixes = []string{"Parser exception:", "Binder exception:", "Catalog exception:"}

// engineInterrupted is liblbug's message when the per-connection query
// timeout (or an Interrupt) stops a running query.
const engineInterrupted = "Interrupted"

// classifyEngineError maps a raw liblbug error to the explore sentinels the
// transports turn into statuses: a rejection is the caller's 400, an interrupt
// a timeout. Anything else (runtime, conversion, buffer exhaustion) is
// returned unchanged — an engine failure.
func classifyEngineError(err error) error {
	msg := err.Error()
	for _, p := range engineRejectionPrefixes {
		if strings.HasPrefix(msg, p) {
			return &explore.QueryRejection{Reason: msg}
		}
	}
	if strings.HasPrefix(msg, engineInterrupted) {
		return fmt.Errorf("%w: %s", explore.ErrQueryTimeout, msg)
	}
	return err
}

// execCypher runs a validated Cypher query and maps the result to explore types.
// It handles Node and Relationship columns (graph shape) AND scalar/tabular
// columns (aggregates like count/sum, or bare-property RETURNs) — the latter are
// collected into Result.Rows/Columns so "how many …?" queries return a value
// instead of an empty graph. Column order is the sorted union of scalar keys.
//
// The query is prepared first and refused unless the engine itself planned it
// as read-only. graphquery.IsReadOnly stays the primary gate (it also blocks
// IO such as LOAD FROM and EXPORT DATABASE, which the engine counts as reads);
// this check means a guard/lexer divergence cannot turn into a write.
func execCypher(conn *ladybug.Connection, query string, budget QueryBudget) (explore.Result, error) {
	stmt, err := conn.Prepare(query)
	if err != nil {
		if stmt != nil {
			stmt.Close()
		}
		return explore.Result{}, fmt.Errorf("execCypher [%.120s...]: %w", query, classifyEngineError(err))
	}
	defer stmt.Close()
	if !stmt.IsReadOnly() {
		return explore.Result{}, fmt.Errorf("execCypher: %w: %w", ErrReadOnly,
			&explore.QueryRejection{Reason: "the engine plans this query as a write; only read-only queries are permitted"})
	}
	res, err := conn.Execute(stmt, nil)
	if err != nil {
		if res != nil {
			res.Close()
		}
		return explore.Result{}, fmt.Errorf("execCypher [%.120s...]: %w", query, classifyEngineError(err))
	}
	defer res.Close()

	seenNodes := map[string]bool{}
	nodeByInternalID := map[string]string{} // internal ladybug ID → asset ID
	var nodes []explore.Node
	var edges []explore.Edge
	var rows []map[string]any
	scalarCols := map[string]bool{}
	truncated := false

	for res.HasNext() {
		if len(nodes) >= budget.MaxNodes || len(edges) >= budget.MaxEdges || len(rows) >= budget.MaxNodes {
			truncated = true
			break
		}
		// A row error is returned, never read as end-of-results: a partial graph
		// presented as complete is indistinguishable from a real answer.
		row, err := res.Next()
		if err != nil {
			return explore.Result{}, fmt.Errorf("execCypher: next row: %w", err)
		}
		m, err := row.GetAsMap()
		row.Close()
		if err != nil {
			return explore.Result{}, fmt.Errorf("execCypher: read row: %w", err)
		}
		m = flattenPaths(m)
		// Two passes per row: collect every node first so nodeByInternalID is fully
		// populated before any relationship in the SAME row is resolved. GetAsMap
		// returns columns in random order, so a single pass would leave an edge's
		// src/dst empty whenever the relationship column came before its endpoints.
		for _, v := range m {
			typed, ok := v.(ladybug.Node)
			if !ok {
				continue
			}
			id := strVal(typed.Properties["id"])
			if id == "" || seenNodes[id] {
				continue
			}
			seenNodes[id] = true
			nodeByInternalID[fmt.Sprintf("%d:%d", typed.ID.TableID, typed.ID.Offset)] = id
			n := explore.Node{
				ID:        id,
				Name:      strVal(typed.Properties["name"]),
				Type:      strVal(typed.Properties["type"]),
				Provider:  strVal(typed.Properties["provider"]),
				Region:    strVal(typed.Properties["region"]),
				AccountID: strVal(typed.Properties["account_id"]),
				Score:     intVal(typed.Properties["score"]),
			}
			readSignals(&n, typed.Properties)
			nodes = append(nodes, n)
		}
		for _, v := range m {
			typed, ok := v.(ladybug.Relationship)
			if !ok {
				continue
			}
			srcIntID := fmt.Sprintf("%d:%d", typed.SourceID.TableID, typed.SourceID.Offset)
			dstIntID := fmt.Sprintf("%d:%d", typed.DestinationID.TableID, typed.DestinationID.Offset)
			// Generic Edge table stores the semantic type in the edge_type property.
			edgeLabel := typed.Label
			if edgeLabel == "Edge" {
				if et, ok := typed.Properties["edge_type"].(string); ok && et != "" {
					edgeLabel = et
				}
			}
			// confidence rides along when the rel table declares it (ContainsData,
			// FederatedAccess, the IaC ownership edges). Projecting it here is what
			// makes "asserted vs guessed" visible at the point of display instead of
			// being recomputed or silently lost.
			confidence, _ := typed.Properties["confidence"].(string)
			edges = append(edges, explore.Edge{
				SrcID:      nodeByInternalID[srcIntID],
				DstID:      nodeByInternalID[dstIntID],
				EdgeType:   edgeLabel,
				Confidence: confidence,
			})
		}
		// Third pass: scalar/tabular columns (anything that isn't a node or
		// relationship) — aggregates and bare-property RETURNs. Without this a
		// query like `RETURN count(r)` produced an empty graph.
		scalarRow := map[string]any{}
		for k, v := range m {
			if _, isNode := v.(ladybug.Node); isNode {
				continue
			}
			if _, isRel := v.(ladybug.Relationship); isRel {
				continue
			}
			scalarRow[k] = v
			scalarCols[k] = true
		}
		if len(scalarRow) > 0 {
			rows = append(rows, scalarRow)
		}
	}

	columns := make([]string, 0, len(scalarCols))
	for c := range scalarCols {
		columns = append(columns, c)
	}
	sort.Strings(columns)

	return explore.Result{Nodes: nodes, Edges: edges, Rows: rows, Columns: columns, Truncated: truncated}, nil
}

// blastRadiusCountCap is the node budget for blast-radius counting.
// Covers all blastPoints() band thresholds (max meaningful band = 50+ nodes).
const blastRadiusCountCap = 500

// blastHop runs one blast-walk hop from frontier over every blastHopQueries
// entry and returns each newly reached id (marking it in seen), stopping early
// once seen holds limit ids. capped reports that the limit cut the hop short.
// A row-iteration error is returned, never treated as the end of the rows: a
// short read here is an UNDER-count of blast radius, the unsafe direction for
// the gate it feeds.
func blastHop(conn *ladybug.Connection, frontier []string, seen map[string]bool, limit int) (next []string, capped bool, err error) {
	idList := make([]any, len(frontier))
	for i, id := range frontier {
		idList[i] = id
	}
	args := map[string]any{"ids": idList}
	for _, q := range blastHopQueries {
		prepared, err := conn.Prepare(q)
		if err != nil {
			return nil, false, fmt.Errorf("prepare: %w", err)
		}
		res, err := conn.Execute(prepared, args)
		prepared.Close()
		if err != nil {
			return nil, false, fmt.Errorf("execute: %w", err)
		}
		for res.HasNext() {
			row, rowErr := res.Next()
			if rowErr != nil {
				res.Close()
				return nil, false, fmt.Errorf("next row: %w", rowErr)
			}
			// Each hop query projects a single column (m.id), read by index.
			vals, sliceErr := row.GetAsSlice()
			row.Close()
			if sliceErr != nil {
				res.Close()
				return nil, false, fmt.Errorf("read row: %w", sliceErr)
			}
			if len(vals) == 0 {
				continue
			}
			id := strVal(vals[0])
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			next = append(next, id)
			if len(seen) >= limit {
				res.Close()
				return next, true, nil
			}
		}
		res.Close()
	}
	return next, false, nil
}

// blastRadiusCount returns how many nodes seedID reaches in depth hops, capped
// at blastRadiusCountCap (a capped count is still a lower bound, and the cap
// sits above every blastPoints band).
func blastRadiusCount(conn *ladybug.Connection, seedID string, depth int) (int, error) {
	if depth <= 0 || depth > 5 {
		depth = 2
	}
	seen := map[string]bool{seedID: true}
	frontier := []string{seedID}
	for d := 0; d < depth && len(frontier) > 0; d++ {
		// The frontier never exceeds maxQueryItems uncapped: seen would have
		// reached blastRadiusCountCap (== maxQueryItems) first.
		next, capped, err := blastHop(conn, frontier, seen, blastRadiusCountCap+1)
		if err != nil {
			return 0, fmt.Errorf("blastRadiusCount hop %d: %w", d+1, err)
		}
		if capped {
			return blastRadiusCountCap, nil
		}
		frontier = next
	}
	return len(seen) - 1, nil
}

// blastRadiusGraph is the Go-orchestrated implementation of the blast_radius and
// full_blast_radius_3hop named queries: it seeds and traverses across every
// Ladybug node label, not just the generic Asset label — a Cypher form
// hardcoded to Asset would silently return empty for a
// k8s_*/subnet/ec2_instance/security_group seed id. Each edge is walked in its attacker
// direction (blastWalkDir).
//
// Edge types are captured in a typed second pass (blastRadiusEdges) once the
// visited node set is final: the hop queries return ids only, and the label is
// always known in Go from ladybugRelSpec, exactly like neighbors() does for the
// structured expand view.
func blastRadiusGraph(conn *ladybug.Connection, seedID string, hops int, budget QueryBudget) (explore.Result, error) {
	if hops <= 0 || hops > 5 {
		hops = 1
	}
	budget = budget.Clamp()
	nodeCap := budget.MaxNodes

	seedNodes, err := matchSeed(conn, []string{seedID}, nil, "", 1)
	if err != nil {
		return explore.Result{}, fmt.Errorf("blastRadiusGraph: seed: %w", err)
	}
	if len(seedNodes) == 0 {
		// No match under any label — fail open like matchSeed, not an error.
		return explore.Result{}, nil
	}

	seen := map[string]bool{seedID: true}
	frontier := []string{seedID}
	truncated := false
	for d := 0; d < hops && len(frontier) > 0 && len(seen) < nodeCap; d++ {
		if len(frontier) > maxQueryItems {
			frontier = frontier[:maxQueryItems]
			truncated = true
		}
		next, capped, err := blastHop(conn, frontier, seen, nodeCap)
		if err != nil {
			return explore.Result{}, fmt.Errorf("blastRadiusGraph hop %d: %w", d+1, err)
		}
		truncated = truncated || capped
		frontier = next
	}

	visitedIDs := make([]string, 0, len(seen))
	for id := range seen {
		visitedIDs = append(visitedIDs, id)
	}
	if len(visitedIDs) > maxQueryItems {
		truncated = true
	}

	// Batch node hydration: one bounded pass over the final visited set, not
	// per-hop — matchSeed already fans out per label with the right column set
	// for each (seedCols vs seedColsBasic).
	nodes, err := matchSeed(conn, visitedIDs, nil, "", nodeCap)
	if err != nil {
		return explore.Result{}, fmt.Errorf("blastRadiusGraph: hydrate: %w", err)
	}

	edges, err := blastRadiusEdges(conn, visitedIDs, budget.MaxEdges)
	if err != nil {
		return explore.Result{}, fmt.Errorf("blastRadiusGraph: edges: %w", err)
	}

	truncated = truncated || len(seen) >= nodeCap || len(edges) >= budget.MaxEdges
	return explore.Result{Nodes: nodes, Edges: edges, Truncated: truncated}, nil
}

// blastRadiusEdges resolves typed edges between nodes in the visited set,
// one bounded query per loaded rel table (ladybugRelSpec — every rel actually
// loaded into Ladybug, not just the curated Expand-flagged subset neighbors()
// uses for the structured UI: blast radius needs to be as comprehensive as
// the untyped hop-BFS that found these nodes in the first place). Endpoints
// are constrained to the visited id set on both sides so this stays a bounded
// lookup, not a full traversal — safe because the rel table (and therefore its
// From/To labels) is always known in Go, never inferred via type()/label().
func blastRadiusEdges(conn *ladybug.Connection, ids []string, limit int) ([]explore.Edge, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > maxQueryItems {
		ids = ids[:maxQueryItems]
	}
	idList := make([]any, len(ids))
	for i, id := range ids {
		idList[i] = id
	}
	args := map[string]any{"ids": idList}

	var edges []explore.Edge
	for relTable, spec := range ladybugRelSpec {
		if len(edges) >= limit {
			break
		}
		q := fmt.Sprintf(
			`MATCH (n:%s)-[:%s]->(m:%s) WHERE n.id IN $ids AND m.id IN $ids RETURN n.id AS src_id, m.id AS dst_id LIMIT %d`,
			quoteLabel(spec.from), relTable, quoteLabel(spec.to), limit)
		prepared, err := conn.Prepare(q)
		if err != nil {
			return nil, fmt.Errorf("blastRadiusEdges prepare %s: %w", relTable, err)
		}
		res, err := conn.Execute(prepared, args)
		prepared.Close()
		if err != nil {
			return nil, fmt.Errorf("blastRadiusEdges execute %s: %w", relTable, err)
		}
		for res.HasNext() {
			row, rowErr := res.Next()
			if rowErr != nil {
				res.Close()
				return nil, fmt.Errorf("blastRadiusEdges %s: next row: %w", relTable, rowErr)
			}
			m, mapErr := row.GetAsMap()
			row.Close()
			if mapErr != nil {
				res.Close()
				return nil, fmt.Errorf("blastRadiusEdges %s: read row: %w", relTable, mapErr)
			}
			edges = append(edges, explore.Edge{
				SrcID: strVal(m["src_id"]), DstID: strVal(m["dst_id"]), EdgeType: relTable,
			})
			if len(edges) >= limit {
				break
			}
		}
		res.Close()
	}
	return edges, nil
}

func internetReachable(conn *ladybug.Connection, id string) (bool, error) {
	prepared, err := conn.Prepare(
		`MATCH (a:Asset {id: $id})-[:ExposedToInternet]->(:Asset {id: 'internet'}) RETURN count(*) AS n LIMIT 1`)
	if err != nil {
		return false, nil
	}
	defer prepared.Close()
	res, err := conn.Execute(prepared, map[string]any{"id": id})
	if err != nil {
		return false, nil
	}
	defer res.Close()
	if !res.HasNext() {
		return false, nil
	}
	row, err := res.Next()
	if err != nil {
		return false, err
	}
	defer row.Close()
	m, _ := row.GetAsMap()
	n, _ := m["n"].(int64)
	return n > 0, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func strVal(v any) string {
	s, _ := v.(string)
	return s
}

// intVal coerces a Ladybug numeric value (INT32 surfaces as int64/int32) to int.
func intVal(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int32:
		return int(n)
	case int:
		return n
	default:
		return 0
	}
}

func minLen(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Read-only Cypher enforcement lives in the shared graphquery package (an
// allowlist, not a keyword denylist) so every entry point — this service, the
// RPC handler, explore, mcp and savedquery — validates identically. See
// graphquery.IsReadOnly.

// flattenPaths replaces each path column (MATCH p = …, RETURN p) with its nodes
// and relationships as separate entries, so a returned path renders as the
// graph it walks rather than being skipped as an unknown value.
func flattenPaths(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for col, v := range m {
		path, ok := v.(ladybug.RecursiveRelationship)
		if !ok {
			out[col] = v
			continue
		}
		for i, n := range path.Nodes {
			out[fmt.Sprintf("%s.node%d", col, i)] = n
		}
		for i, r := range path.Relationships {
			out[fmt.Sprintf("%s.rel%d", col, i)] = r
		}
	}
	return out
}
