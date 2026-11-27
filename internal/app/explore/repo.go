package explore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

const (
	// nodeCols is the asset projection used for result nodes (FINAL deduplicates).
	nodeCols = `id, name, type, provider, region, account_id`

	// edgesOut/edgesIn fetch one hop; %s is the db.CHIn placeholder list.
	// Freshness: same window every graph_edges reader applies — a stale edge the
	// Ladybug graph does not load must not resurface through the fallback.
	// Grouped by edge_type too: two nodes joined by several edge types (an
	// instance that both has_role and executes_as the same role) are several
	// edges, as they are in Ladybug — grouping by the pair alone would keep one
	// arbitrary type and drop the rest.
	edgesOut = `SELECT src_id, dst_id, edge_type
		FROM graph_edges WHERE src_id IN (%s) %s AND ` + graphschema.EdgeFreshnessCond + `
		GROUP BY src_id, dst_id, edge_type`
	edgesIn = `SELECT src_id, dst_id, edge_type
		FROM graph_edges WHERE dst_id IN (%s) %s AND ` + graphschema.EdgeFreshnessCond + `
		GROUP BY src_id, dst_id, edge_type`
)

// Both seed reads apply asset.InventoryReadCond: the ClickHouse
// fallback is taken routinely (any node Ladybug pruned, not just outages), and
// without the gate it resurrects dead pods/containers and IaC declared_* rows
// as live graph nodes — the same rule every UI-facing assets reader applies.
// The predicate references the assets table's own type/last_seen columns,
// which both queries expose raw (WHERE runs pre-GROUP BY / pre-FINAL).
//
// seedByIDs uses argMax, not FINAL: skip indexes don't apply under FINAL
// (use_skip_indexes_if_final defaults off), so FINAL WHERE id IN would
// full-scan assets instead of pruning via idx_id. Runs per
// traversal hop. Same fix as asset.assetArgMaxSelect.
//
// Vars, not consts, only because asset.InventoryReadCond is a package var.
var (
	seedByIDs = `SELECT id, argMax(name, synced_at), argMax(type, synced_at),
		argMax(provider, synced_at), argMax(region, synced_at), argMax(account_id, synced_at)
		FROM assets WHERE id IN (%s) AND ` + asset.InventoryReadCond + ` GROUP BY id LIMIT ?`

	seedByMatch = `SELECT ` + nodeCols + ` FROM assets FINAL
		WHERE %s AND ` + asset.InventoryReadCond + `
		LIMIT ?`
)

// idChunkSize bounds every CHIn(ids) call in this file. ClickHouse's ?-placeholder
// binding substitutes values into the query TEXT client-side (no true bind-parameter
// form for a plain IN list over CH's native/HTTP protocol), so a large id slice can
// exceed max_query_size (256 KiB by default — see
// internal/app/asset/optimize.go's VerifyExpiredEphemeral). Explore's
// ids are commonly AWS ARNs (80-120+ bytes, e.g. "arn:aws:iam::123456789012:role/x"),
// and the traversal frontier this file receives is capped at hardMaxNodes=2000
// (explore/service.go) — 2000 ARNs alone is 160-240KB before the query template and
// any edge_type IN clause, uncomfortably close to the ceiling. 500 matches the
// existing convention for ARN-shaped id batches elsewhere in this codebase
// (asset.maxNodeBudget, finding.resourceIDBatchSize, correlate.go's batchSize).
const idChunkSize = 500

type CHRepo struct {
	ch        *db.CH
	deletions DeletionVerifier
}

func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

// WithDeletionVerifier preserves unknown references while excluding endpoints
// whose deletion is proven and has no newer observation.
func (r *CHRepo) WithDeletionVerifier(v DeletionVerifier) *CHRepo { r.deletions = v; return r }

func (r *CHRepo) MatchSeed(ctx context.Context, m NodeMatch, limit int) ([]Node, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var (
		query string
		args  []any
	)
	switch {
	case len(m.IDs) > 0:
		ph, a := dbutil.CHIn(m.IDs)
		query = fmt.Sprintf(seedByIDs, ph)
		args = append(a, limit)
	default:
		conds, condArgs := matchConds(m)
		if len(conds) == 0 {
			return nil, ErrInvalidSpec // refuse an unbounded "match everything"
		}
		query = fmt.Sprintf(seedByMatch, strings.Join(conds, " AND "))
		args = append(condArgs, limit)
	}

	nodes, err := r.scanNodes(qCtx, query, args)
	if err != nil {
		return nil, err
	}
	return r.withoutDeletedNodes(qCtx, nodes)
}

// chEdgeTypes translates the caller's edge filters into the snake_case
// edge_type values graph_edges actually stores. Callers (the NL spec prompt,
// frontend presets) pass PascalCase rel-table names — untranslated, a typed
// traversal on the ClickHouse fallback matches ZERO rows. Unrecognised
// names pass through so a caller already using snake_case keeps working.
func chEdgeTypes(edgeTypes []string) []string {
	var out []string
	for _, t := range edgeTypes {
		if mapped := graphschema.EdgeTypesForRel(t); len(mapped) > 0 {
			out = append(out, mapped...)
			continue
		}
		out = append(out, t)
	}
	return out
}

// expandEdgeTypes is the snake_case equivalent of the Ladybug expand view: the
// edge types feeding Expand-flagged rels. Applied when the caller sets no edge
// filter, so an untyped expand answers the SAME question on both engines —
// walking ALL edge types (a superset) on the ClickHouse path would return a
// different neighbourhood than Ladybug.
var expandEdgeTypes = func() []string {
	var out []string
	for _, rel := range graphschema.ExpandRels() {
		out = append(out, graphschema.EdgeTypesForRel(rel.Name)...)
	}
	out = append(out, graphschema.OnDemandEdgeTypes()...)
	return out
}()

func (r *CHRepo) Neighbors(ctx context.Context, ids, edgeTypes []string, dir Direction) ([]Edge, []Node, bool, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if len(edgeTypes) == 0 {
		edgeTypes = expandEdgeTypes
	} else {
		edgeTypes = chEdgeTypes(edgeTypes)
	}

	var edges []Edge
	if dir == DirectionOut || dir == DirectionBoth {
		out, err := r.edges(qCtx, edgesOut, ids, edgeTypes)
		if err != nil {
			return nil, nil, false, fmt.Errorf("Neighbors: out: %w", err)
		}
		edges = append(edges, out...)
	}
	if dir == DirectionIn || dir == DirectionBoth {
		in, err := r.edges(qCtx, edgesIn, ids, edgeTypes)
		if err != nil {
			return nil, nil, false, fmt.Errorf("Neighbors: in: %w", err)
		}
		edges = append(edges, in...)
	}

	edges, err := r.withoutDeletedEdges(qCtx, edges)
	if err != nil {
		return nil, nil, false, err
	}

	// Fetch the asset rows for every endpoint we don't already have on the
	// frontier, so result nodes carry names/types.
	endpointSet := map[string]bool{}
	for _, e := range edges {
		endpointSet[e.SrcID] = true
		endpointSet[e.DstID] = true
	}
	var endpoints []string
	for id := range endpointSet {
		endpoints = append(endpoints, id)
	}
	nodes, err := r.nodesByID(qCtx, endpoints)
	if err != nil {
		return nil, nil, false, fmt.Errorf("Neighbors: nodes: %w", err)
	}
	return edges, nodes, false, nil
}

func (r *CHRepo) edges(ctx context.Context, tmpl string, ids, edgeTypes []string) ([]Edge, error) {
	var edges []Edge
	for _, chunk := range chunkIDs(ids) {
		idPh, args := dbutil.CHIn(chunk)
		etClause := ""
		if len(edgeTypes) > 0 {
			etPh, etArgs := dbutil.CHIn(edgeTypes)
			etClause = "AND edge_type IN (" + etPh + ")"
			args = append(args, etArgs...)
		}
		query := fmt.Sprintf(tmpl, idPh, etClause)

		err := r.ch.Select(ctx, func(rows driver.Rows) error {
			for rows.Next() {
				var e Edge
				if err := rows.Scan(&e.SrcID, &e.DstID, &e.EdgeType); err != nil {
					return fmt.Errorf("scan edge: %w", err)
				}
				edges = append(edges, e)
			}
			return nil
		}, query, args...)
		if err != nil {
			return nil, err
		}
	}
	return edges, nil
}

func (r *CHRepo) nodesByID(ctx context.Context, ids []string) ([]Node, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var nodes []Node
	for _, chunk := range chunkIDs(ids) {
		ph, args := dbutil.CHIn(chunk)
		n, err := r.scanNodes(ctx, fmt.Sprintf(seedByIDs, ph), append(args, len(chunk)))
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, n...)
	}
	return nodes, nil
}

// chunkIDs splits ids into idChunkSize-sized batches — see idChunkSize's doc
// comment for why an unbounded batch risks ClickHouse's max_query_size.
func chunkIDs(ids []string) [][]string {
	if len(ids) == 0 {
		return nil
	}
	chunks := make([][]string, 0, (len(ids)+idChunkSize-1)/idChunkSize)
	for start := 0; start < len(ids); start += idChunkSize {
		end := start + idChunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunks = append(chunks, ids[start:end])
	}
	return chunks
}

func (r *CHRepo) scanNodes(ctx context.Context, query string, args []any) ([]Node, error) {
	var nodes []Node
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var n Node
			if err := rows.Scan(&n.ID, &n.Name, &n.Type, &n.Provider, &n.Region, &n.AccountID); err != nil {
				return fmt.Errorf("scan node: %w", err)
			}
			nodes = append(nodes, n)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("scanNodes: %w", err)
	}
	return nodes, nil
}

// matchConds builds WHERE conditions for a type/provider seed match, read via
// seedByMatch's FINAL (above). That is a filtered FINAL, listed in CLAUDE.md's
// known exceptions beside the type-filtered reads in identity/repo.go, and for
// the same reason: what FINAL costs a filtered read is the skip index it disables (e.g.
// seedByIDs' id lookup needs idx_id, a bloom filter on a non-leading sort
// column, hence its argMax form). type is the LEADING column of assets'
// ORDER BY (type, id), so primary-key granule pruning still applies under
// FINAL, and provider is a plain column filter that never used a skip index.
// An argMax rewrite would read the same rows and add the aggregation, and
// with GROUP BY id the LIMIT no longer stops the read early. Re-measure
// against a realistically sized table before changing it.
func matchConds(m NodeMatch) (conds []string, args []any) {
	if len(m.Types) > 0 {
		ph, a := dbutil.CHIn(m.Types)
		conds = append(conds, "type IN ("+ph+")")
		args = append(args, a...)
	}
	if m.Provider != "" {
		conds = append(conds, "provider = ?")
		args = append(args, m.Provider)
	}
	return conds, args
}
