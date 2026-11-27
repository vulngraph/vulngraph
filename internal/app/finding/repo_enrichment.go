package finding

import (
	"context"
	"fmt"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"

	"github.com/vulngraph/vulngraph/internal/db"
)

// insertEnrichment writes finding_enrichment: the ten
// enrich:"output" fields plus the enrich-stamped routing context (owner,
// environment; ADR 089), no lifecycle/producer columns — the split's point.
const insertEnrichment = `INSERT INTO finding_enrichment
	(id, score, score_band, known_exploited, dependents, unused,
	 safety_class, fix_target, must_fix_class, must_fix_reason, enriched_at,
	 owner_team, owner_source, owner_confidence, environment)`

// UpsertEnrichment writes enrichment outputs to finding_enrichment.
// No producer/lifecycle writer touches this table, so unlike
// Upsert there is no full-row-vs-partial-row hazard: every column is
// enrich-owned. Batching/write-budget mirror Upsert (repo.go) for the same
// reasons — a large enrich sweep can produce enough rows to blow an
// unchunked batch's deadline.
func (r *CHRepo) UpsertEnrichment(ctx context.Context, enrichments []Enrichment) error {
	if len(enrichments) == 0 {
		return nil
	}
	ctx, cancel := db.WithWriteBudget(ctx, findingWriteBudget)
	defer cancel()
	for start := 0; start < len(enrichments); start += findingBatchSize {
		end := min(start+findingBatchSize, len(enrichments))
		chunk := enrichments[start:end]
		write := r.ch.Batch
		if len(chunk) == 1 {
			write = func(ctx context.Context, query string, appendRow func(driver.Batch) error) error {
				return r.ch.BatchSingle(ctx, query, enrichmentWriteBytes(chunk[0]), appendRow)
			}
		}
		err := write(ctx, insertEnrichment, func(b driver.Batch) error {
			for _, e := range chunk {
				if err := b.Append(
					e.ID, e.Score, e.ScoreBand, boolToUint8(e.KnownExploited),
					e.Dependents, boolToUint8(e.Unused), e.SafetyClass, e.FixTarget,
					e.MustFixClass, e.MustFixReason, e.EnrichedAt,
					e.OwnerTeam, e.OwnerSource, e.OwnerConfidence, e.Environment,
				); err != nil {
					return fmt.Errorf("append enrichment %s: %w", e.ID, err)
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("UpsertEnrichment: %w", err)
		}
	}
	return nil
}

func enrichmentWriteBytes(e Enrichment) int {
	return 64 + len(e.ID) + len(e.ScoreBand) + len(e.SafetyClass) + len(e.FixTarget) + len(e.MustFixClass) + len(e.MustFixReason) + len(e.OwnerTeam) + len(e.OwnerSource) + len(e.OwnerConfidence) + len(e.Environment)
}
