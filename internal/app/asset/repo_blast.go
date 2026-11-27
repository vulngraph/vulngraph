package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

const attackOutgoingEdges = `SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
	FROM graph_edges WHERE src_id IN (%s) AND edge_type NOT IN (%s) AND ` + graphschema.EdgeFreshnessCond + `
	GROUP BY src_id, src_type, dst_id, dst_type, edge_type`
const attackIncomingEdges = `SELECT src_id, src_type, dst_id, dst_type, edge_type, argMax(properties, synced_at)
	FROM graph_edges WHERE dst_id IN (%s) AND edge_type IN (%s) AND ` + graphschema.EdgeFreshnessCond + `
	GROUP BY src_id, src_type, dst_id, dst_type, edge_type`

var attackOutgoingExcluded, attackIncomingIncluded = attackDirectionTypes()

func attackDirectionTypes() (outgoingExcluded, incomingIncluded []string) {
	for _, edge := range graphschema.EdgeTypes {
		direction := graphschema.AttackDirection(edge.Type)
		if direction == graphschema.DirReverse {
			outgoingExcluded = append(outgoingExcluded, edge.Type)
		}
		if direction == graphschema.DirReverse || direction == graphschema.DirBoth {
			incomingIncluded = append(incomingIncluded, edge.Type)
		}
	}
	return outgoingExcluded, incomingIncluded
}

// EdgesForAttack applies the existing attacker-direction rules before grouping
// or transmitting rows. A shared image may have thousands of incoming runs_image
// edges, none of which can advance this walk. Unknown types remain forward.
func (r *CHRepo) EdgesForAttack(ctx context.Context, ids []string) ([]Edge, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = r.ch.WithQuerySettings(ctx, map[string]any{
		"max_execution_time": 10, "max_memory_usage": 128 << 20,
		"max_rows_to_read": 50_000_000, "read_overflow_mode": "throw",
	})
	keys, keyArgs := dbutil.CHIn(ids)
	var edges []Edge
	for _, direction := range []struct {
		query string
		types []string
	}{{attackOutgoingEdges, attackOutgoingExcluded}, {attackIncomingEdges, attackIncomingIncluded}} {
		types, typeArgs := dbutil.CHIn(direction.types)
		args := append(append([]any(nil), keyArgs...), typeArgs...)
		err := r.ch.Select(ctx, func(rows driver.Rows) error {
			for rows.Next() {
				var e Edge
				var properties string
				if err := rows.Scan(&e.SrcID, &e.SrcType, &e.DstID, &e.DstType, &e.EdgeType, &properties); err != nil {
					return fmt.Errorf("scan attack edge: %w", err)
				}
				e.Properties = decodeMap(properties)
				edges = append(edges, e)
			}
			return rows.Err()
		}, fmt.Sprintf(direction.query, keys, types), args...)
		if err != nil {
			return nil, fmt.Errorf("EdgesForAttack: %w", err)
		}
	}
	return edges, nil
}
