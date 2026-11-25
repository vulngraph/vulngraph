package alertctx

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// Both queries only SELECT ids; the service hydrates them through the asset
// service's argMax read, so the unindexed attribute scan reads just the columns
// it filters on. Rows are prefilters over possibly-stale versions: the service
// re-checks every match against the current row. No FINAL: a filtered FINAL
// bypasses skip indexes and full-scans the table (CLAUDE.md).
var (
	// liveAssetIDsByID keeps ids that are live inventory (asset.InventoryReadCond),
	// so a dead pod or an IaC declaration never resolves as a real resource.
	// idx_id (bloom) prunes the granules.
	liveAssetIDsByID = `SELECT id FROM assets
		WHERE id IN (%s) AND ` + asset.InventoryReadCond + `
		GROUP BY id`

	// liveAssetIDsByAttribute finds ids by IP, name, domain or endpoint — none
	// has a skip index, so this is a column scan bounded by LIMIT.
	liveAssetIDsByAttribute = `SELECT id FROM assets
		WHERE (%s) AND ` + asset.InventoryReadCond + `
		GROUP BY id
		LIMIT ?`
)

// CHRepo selects candidate asset ids from ClickHouse.
type CHRepo struct {
	ch *db.CH
}

func NewCHRepo(ch *db.CH) *CHRepo { return &CHRepo{ch: ch} }

// LiveIDs returns the subset of ids that are live inventory assets.
func (r *CHRepo) LiveIDs(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	ph, args := dbutil.CHIn(ids)
	out, err := r.selectIDs(ctx, fmt.Sprintf(liveAssetIDsByID, ph), args)
	if err != nil {
		return nil, fmt.Errorf("LiveIDs: %w", err)
	}
	return out, nil
}

// IDsByAttribute returns up to candidateIDLimit live asset ids whose public_ip
// or private_ip is in ips, or whose name, domain or endpoint is in names. The
// bool is true when the limit cut the result off.
func (r *CHRepo) IDsByAttribute(ctx context.Context, ips, names []string) ([]string, bool, error) {
	var conds []string
	var args []any
	if len(ips) > 0 {
		ph, a := dbutil.CHIn(ips)
		conds = append(conds, "public_ip IN ("+ph+")", "private_ip IN ("+ph+")")
		args = append(args, a...)
		args = append(args, a...)
	}
	if len(names) > 0 {
		ph, a := dbutil.CHIn(names)
		for _, col := range []string{"name", "domain", "endpoint"} {
			conds = append(conds, col+" IN ("+ph+")")
			args = append(args, a...)
		}
	}
	if len(conds) == 0 {
		return nil, false, nil
	}
	args = append(args, candidateIDLimit+1)
	out, err := r.selectIDs(ctx, fmt.Sprintf(liveAssetIDsByAttribute, strings.Join(conds, " OR ")), args)
	if err != nil {
		return nil, false, fmt.Errorf("IDsByAttribute: %w", err)
	}
	if len(out) > candidateIDLimit {
		return out[:candidateIDLimit], true, nil
	}
	return out, false, nil
}

func (r *CHRepo) selectIDs(ctx context.Context, query string, args []any) ([]string, error) {
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	qCtx = r.ch.WithQuerySettings(qCtx, map[string]any{"max_execution_time": 8})

	var out []string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
			out = append(out, id)
		}
		return nil
	}, query, args...)
	if err != nil {
		return nil, err
	}
	return out, nil
}
