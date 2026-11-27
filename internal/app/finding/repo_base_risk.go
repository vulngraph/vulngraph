package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// A complete raw-severity rollup, independent of enrichment. FINAL is a full
// table read here. An error cannot be converted to an empty published snapshot.
const baseRiskByResource = `SELECT resource_id,
 max(multiIf(severity='critical',toUInt8(80),severity='high',toUInt8(60),toUInt8(0)))
 FROM findings FINAL WHERE resource_id!='' AND resolved_at<toDateTime('2000-01-01 00:00:00')
 GROUP BY resource_id HAVING max(multiIf(severity='critical',toUInt8(80),severity='high',toUInt8(60),toUInt8(0)))>0`

func (r *CHRepo) BaseRiskByResource(ctx context.Context) (map[string]uint8, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out := map[string]uint8{}
	err := r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			var score uint8
			if err := rows.Scan(&id, &score); err != nil {
				return err
			}
			out[id] = score
		}
		return rows.Err()
	}, baseRiskByResource)
	if err != nil {
		return nil, fmt.Errorf("BaseRiskByResource: %w", err)
	}
	return out, nil
}
