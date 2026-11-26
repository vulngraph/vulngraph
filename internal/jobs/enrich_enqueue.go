package jobs

import (
	"context"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type enrichBatchInserter interface {
	InsertMany(context.Context, []river.InsertManyParams) ([]*rivertype.JobInsertResult, error)
}

// Preserve priority and args-level uniqueness while bounding allocation and each
// transaction. A failed batch is retried by the periodic finding sweep.
func insertEnrichBatches(ctx context.Context, client enrichBatchInserter, found []finding.Finding, priority int) {
	const batchSize = 500
	opts := &river.InsertOpts{Priority: priority}
	for start := 0; start < len(found); start += batchSize {
		if ctx.Err() != nil {
			return
		}
		batch := found[start:min(start+batchSize, len(found))]
		params := make([]river.InsertManyParams, 0, len(batch))
		for _, f := range batch {
			params = append(params, river.InsertManyParams{Args: EnrichArgs{FindingID: f.ID}, InsertOpts: opts})
		}
		if _, err := client.InsertMany(ctx, params); err != nil {
			log.FromContext(ctx).Error().Err(err).Int("findings", len(batch)).Msg("enqueue enrich batch failed; periodic sweep will retry")
		}
	}
}
