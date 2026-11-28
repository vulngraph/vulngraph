package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// EnrichmentCandidates preserves the selection key without a second hydration read.
func (r *CHRepo) EnrichmentCandidates(ctx context.Context, f Filter) (EnrichmentPage, error) {
	f.StaleFirst = true
	f.SortByScore = false
	f.OldestFirst = false
	query, args, err := listKeyProjectionQuery(f, true)
	if err != nil {
		return EnrichmentPage{}, fmt.Errorf("EnrichmentCandidates: query: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, batchReadTimeout)
	defer cancel()
	var out EnrichmentPage
	var lastAt time.Time
	err = r.ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			var id string
			var at time.Time
			if err := rows.Scan(&id, &at); err != nil {
				return fmt.Errorf("scan enrichment key: %w", err)
			}
			out.IDs = append(out.IDs, id)
			lastAt = at
		}
		return rows.Err()
	}, query, args...)
	if err != nil {
		return EnrichmentPage{}, fmt.Errorf("EnrichmentCandidates: %w", err)
	}
	if len(out.IDs) > 0 {
		out.Cursor = EncodeStaleCursor(Finding{ID: out.IDs[len(out.IDs)-1], EnrichedAt: lastAt})
	}
	return out, nil
}
