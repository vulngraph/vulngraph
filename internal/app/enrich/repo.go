package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// insertSignals writes one row per finding holding the aggregate score plus the
// per-source factor breakdown (JSON). id = finding id so the ReplacingMergeTree
// (ORDER BY id) upserts in place on re-enrich.
const insertSignals = `INSERT INTO signals
	(id, finding_id, asset_id, source, score, severity, factors, created_at, synced_at)`

// selectFactors reads the latest per-source factor breakdown for a finding.
// argMax collapses the ReplacingMergeTree versions without FINAL; id = finding id.
const selectFactors = `SELECT argMax(factors, synced_at)
	FROM signals WHERE id = ? GROUP BY id`

// SignalCHRepo persists the score breakdown to the ClickHouse signals table.
type SignalCHRepo struct {
	ch *db.CH
}

func NewSignalCHRepo(ch *db.CH) *SignalCHRepo { return &SignalCHRepo{ch: ch} }

func (r *SignalCHRepo) WriteFactors(ctx context.Context, findingID, assetID string, score Score) error {
	factors, err := json.Marshal(score.Factors)
	if err != nil {
		return fmt.Errorf("WriteFactors: marshal factors: %w", err)
	}
	now := time.Now()
	// Concurrent single-row writes share a bounded native batch. Completion is
	// synchronous: decisions must be able to read these factors immediately.
	ctx, cancel := db.WithWriteBudget(ctx, 5*time.Minute)
	defer cancel()
	err = r.ch.BatchSingle(ctx, insertSignals, len(factors)+2*len(findingID)+len(assetID)+64, func(b driver.Batch) error {
		return b.Append(
			findingID, findingID, assetID, "enrich",
			score.Value, string(score.Band), string(factors), now, now,
		)
	})
	if err != nil {
		return fmt.Errorf("WriteFactors: %w", err)
	}
	return nil
}

// Factors returns the latest per-source score breakdown for a finding, or nil
// if it has not been enriched yet.
func (r *SignalCHRepo) Factors(ctx context.Context, findingID string) ([]Factor, error) {
	start := time.Now()
	defer func() {
		if elapsed := time.Since(start); elapsed > 20*time.Millisecond {
			log.FromContext(ctx).Debug().Str("finding_id", findingID).Dur("elapsed", elapsed).
				Msg("factors: slow CH read")
		}
	}()
	qCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var factorsJSON string
	err := r.ch.Select(qCtx, func(rows driver.Rows) error {
		for rows.Next() {
			if err := rows.Scan(&factorsJSON); err != nil {
				return fmt.Errorf("scan: %w", err)
			}
		}
		return nil
	}, selectFactors, findingID)
	if err != nil {
		return nil, fmt.Errorf("Factors: %w", err)
	}
	if factorsJSON == "" {
		return nil, nil
	}
	var factors []Factor
	if err := json.Unmarshal([]byte(factorsJSON), &factors); err != nil {
		return nil, fmt.Errorf("Factors: unmarshal: %w", err)
	}
	return factors, nil
}
