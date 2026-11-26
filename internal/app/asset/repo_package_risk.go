package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

const packageRiskByRunner = `SELECT e.src_id, max(p.score)
 FROM graph_edges AS e
 INNER JOIN (
  SELECT id, argMax(risk_score, synced_at) AS score FROM assets
  WHERE type = 'package' AND ` + EphemeralLivenessCond + ` GROUP BY id HAVING score > 0
 ) AS p ON e.dst_id = p.id
 WHERE e.edge_type IN ('runs_package', 'depends_on') AND ` + graphschema.EdgeFreshnessCond + `
 GROUP BY e.src_id
 SETTINGS max_memory_usage = 536870912, max_bytes_before_external_group_by = 67108864`

// PackageRiskByRunner reduces package memberships in ClickHouse. Only one
// score per runtime/repository crosses into the worker, regardless of package
// inventory size. Failure aborts the graph refresh rather than dropping risk.
func (r *CHRepo) PackageRiskByRunner(ctx context.Context) (map[string]uint8, error) {
	qctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	out := map[string]uint8{}
	err := r.ch.Select(qctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			var score uint8
			if err := rows.Scan(&id, &score); err != nil {
				return fmt.Errorf("scan package risk: %w", err)
			}
			out[id] = score
		}
		return rows.Err()
	}, packageRiskByRunner)
	if err != nil {
		return nil, fmt.Errorf("PackageRiskByRunner: %w", err)
	}
	return out, nil
}
