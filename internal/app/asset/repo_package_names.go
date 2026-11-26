package asset

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

const packageVersionsByName = assetArgMaxSelect + ` WHERE type = 'package' AND name = ? AND ` + EphemeralLivenessCond + ` GROUP BY id ORDER BY id LIMIT ?`

func (r *CHRepo) FindPackageVersions(ctx context.Context, name string, limit int) ([]Asset, error) {
	if name == "" || limit < 1 || limit > 501 {
		return nil, fmt.Errorf("FindPackageVersions: invalid name or limit")
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var out []Asset
	err := r.ch.Select(qctx, func(rows driver.Rows) error {
		for rows.Next() {
			a, err := scanAsset(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	}, packageVersionsByName, name, limit)
	if err != nil {
		return nil, fmt.Errorf("FindPackageVersions: %w", err)
	}
	return out, nil
}
