package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"
	"github.com/vulngraph/vulngraph/pkg/log"
)

type InventoryRetirementArgs struct{}

func (InventoryRetirementArgs) Kind() string { return "inventory_retirement" }
func (InventoryRetirementArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueDangling, 2)
}

type retirementProofs interface {
	PendingAssetRetirements(context.Context, int) (map[string]time.Time, error)
	CompleteAssetRetirements(context.Context, map[string]time.Time) error
}
type inventoryRetirer interface {
	RetireAssets(context.Context, map[string]time.Time) ([]string, error)
}
type InventoryRetirementWorker struct {
	river.WorkerDefaults[InventoryRetirementArgs]
	proofs   retirementProofs
	assets   inventoryRetirer
	findings findingLifecycler
}

func (InventoryRetirementWorker) Timeout(*river.Job[InventoryRetirementArgs]) time.Duration {
	return 5 * time.Minute
}
func (w *InventoryRetirementWorker) Work(ctx context.Context, _ *river.Job[InventoryRetirementArgs]) error {
	retired := 0
	for batch := 0; batch < 10; batch++ {
		pending, err := w.proofs.PendingAssetRetirements(ctx, 200)
		if err != nil {
			return fmt.Errorf("inventory retirement: proofs: %w", err)
		}
		if len(pending) == 0 {
			break
		}
		ids, err := w.assets.RetireAssets(ctx, pending)
		if err != nil {
			return fmt.Errorf("inventory retirement: %w", err)
		}
		if err := resolveFindingsForDeletedAssets(ctx, w.findings, ids); err != nil {
			return fmt.Errorf("inventory retirement: %w", err)
		}
		// A failed acknowledgement leaves the exact proof pending; conditional,
		// idempotent deletes retry without touching a newer observation.
		if err := w.proofs.CompleteAssetRetirements(ctx, pending); err != nil {
			return fmt.Errorf("inventory retirement: acknowledge: %w", err)
		}
		retired += len(ids)
	}
	log.FromContext(ctx).Info().Int("assets", retired).Msg("inventory: applied confirmed deletions")
	return nil
}
