package asset

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type cancelledHistoryRepo struct {
	Repo
	cancel context.CancelFunc
}

func (r cancelledHistoryRepo) ByIDs(ctx context.Context, _ []string) ([]Asset, error) {
	r.cancel()
	return nil, ctx.Err()
}

func TestCancelledInventoryCannotOverwriteHistory(t *testing.T) {
	for _, mode := range []string{"assets", "assets and edges"} {
		t.Run(mode, func(t *testing.T) {
			repo := newFakeRepo()
			repo.assets["asset"] = Asset{ID: "asset", Name: "original"}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			svc := NewService(cancelledHistoryRepo{repo, cancel})
			assets := []Asset{{ID: "asset", Name: "changed"}}
			var err error
			if mode == "assets" {
				err = svc.IngestAssets(ctx, assets)
			} else {
				err = svc.Ingest(ctx, assets, []Edge{{SrcID: "asset", DstID: "target", EdgeType: "runs_image"}})
			}
			require.ErrorIs(t, err, context.Canceled)
			require.Equal(t, "original", repo.assets["asset"].Name)
			require.Empty(t, repo.edges)
		})
	}
}
