package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// These reads return distinct endpoints, not every edge/version on the way to
// them. DISTINCT LIMIT can stop while streaming; a LIMIT after argMax would
// still aggregate the entire fan-out. One extra endpoint proves truncation.
const (
	lineageSources = `SELECT DISTINCT src_id, src_type FROM graph_edges
		WHERE dst_id IN (%s) AND edge_type = ? AND ` + graphschema.EdgeFreshnessCond + ` LIMIT ?`
	lineageTargets = `SELECT DISTINCT dst_id, dst_type FROM graph_edges
		WHERE src_id IN (%s) AND edge_type = ? AND ` + graphschema.EdgeFreshnessCond + ` LIMIT ?`
	confirmedExposure = `SELECT src_id FROM graph_edges
		WHERE src_id IN (%s) AND edge_type = 'exposed_to_internet' AND ` + graphschema.EdgeFreshnessCond + `
		GROUP BY src_id, dst_id
		HAVING JSONExtractString(argMax(properties, synced_at), 'public_access') != 'possible' LIMIT 1`
)

func (r *CHRepo) lineageContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	return r.ch.WithQuerySettings(ctx, map[string]any{
		"max_execution_time": 5, "max_memory_usage": 128 << 20,
		"max_rows_to_read": 50_000_000, "read_overflow_mode": "throw",
	}), cancel
}

func (r *CHRepo) LineageSources(ctx context.Context, ids []string, edgeType string, limit int) ([]Edge, bool, error) {
	return r.lineageEndpoints(ctx, ids, edgeType, limit, true)
}

func (r *CHRepo) LineageTargets(ctx context.Context, ids []string, edgeType string, limit int) ([]Edge, bool, error) {
	return r.lineageEndpoints(ctx, ids, edgeType, limit, false)
}

func (r *CHRepo) lineageEndpoints(ctx context.Context, ids []string, edgeType string, limit int, incoming bool) ([]Edge, bool, error) {
	if len(ids) > 1000 || limit < 1 || limit > 1000 || edgeType == "" {
		return nil, false, fmt.Errorf("lineage: invalid read bounds")
	}
	if len(ids) == 0 {
		return nil, false, nil
	}
	ctx, cancel := r.lineageContext(ctx)
	defer cancel()
	in, args := dbutil.CHIn(ids)
	args = append(args, edgeType, limit+1)
	query := lineageTargets
	if incoming {
		query = lineageSources
	}
	var edges []Edge
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			e := Edge{EdgeType: edgeType}
			id, typ := &e.DstID, &e.DstType
			if incoming {
				id, typ = &e.SrcID, &e.SrcType
			}
			if err := rows.Scan(id, typ); err != nil {
				return err
			}
			edges = append(edges, e)
		}
		return nil
	}, fmt.Sprintf(query, in), args...)
	if err != nil {
		return nil, false, fmt.Errorf("lineage: %w", err)
	}
	truncated := len(edges) > limit
	return edges[:min(len(edges), limit)], truncated, nil
}

func (r *CHRepo) AnyConfirmedExposure(ctx context.Context, ids []string) (bool, error) {
	if len(ids) > 1000 {
		return false, fmt.Errorf("AnyConfirmedExposure: too many endpoints")
	}
	if len(ids) == 0 {
		return false, nil
	}
	ctx, cancel := r.lineageContext(ctx)
	defer cancel()
	in, args := dbutil.CHIn(ids)
	exposed := false
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		exposed = rows.Next()
		return nil
	}, fmt.Sprintf(confirmedExposure, in), args...)
	if err != nil {
		return false, fmt.Errorf("AnyConfirmedExposure: %w", err)
	}
	return exposed, nil
}
