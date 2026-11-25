package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// openResourcesByCheck lists, per check_id, the distinct resources with an
// open finding, under exactly distinctCheckIDs' definition of open and alive
// (shared CTE and liveness gate): a compliance export counting failing
// resources must not disagree with the rollup that called the check failing.
// The check filter sits in the inner WHERE, before the argMax grouping, so
// only the requested checks' findings are aggregated.
const openResourcesByCheck = openFindingsCTE + `
	SELECT check_id, groupUniqArray(resource_id) FROM open_findings
	WHERE resource_id != '' AND ` + notVerifiedDead + `
	GROUP BY check_id`

// openResourcesTimeout bounds the export read: it aggregates every open
// finding of the requested checks.
const openResourcesTimeout = 30 * time.Second

// OpenResourcesByCheck returns check_id → distinct resource IDs with an open
// finding, for the given checks. A check with no open resource-bearing
// finding is absent from the map.
func (r *CHRepo) OpenResourcesByCheck(ctx context.Context, checkIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(checkIDs) == 0 {
		return out, nil
	}
	qCtx, cancel := context.WithTimeout(ctx, openResourcesTimeout)
	defer cancel()
	ph, args := dbutil.CHIn(checkIDs)
	query := fmt.Sprintf(openResourcesByCheck, "WHERE findings.check_id IN ("+ph+") AND")
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			var resources []string
			if err := rows.Scan(&id, &resources); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out[id] = resources
		}
		return rows.Err()
	}, query, args...)
	if err != nil {
		return nil, fmt.Errorf("OpenResourcesByCheck: %w", err)
	}
	return out, nil
}
