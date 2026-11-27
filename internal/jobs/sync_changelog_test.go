package jobs

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type changeLogCaptureRepo struct {
	asset.Repo
	readIDs     []string
	connectorID string
	changes     []asset.FieldChange
}

func (r *changeLogCaptureRepo) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	r.readIDs = append(r.readIDs, ids...)
	out := make([]asset.Asset, len(ids))
	for i, id := range ids {
		out[i] = asset.Asset{ID: id, Name: "before"}
	}
	return out, nil
}
func (r *changeLogCaptureRepo) WriteChangeLog(_ context.Context, connectorID string, changes []asset.FieldChange) error {
	r.connectorID = connectorID
	r.changes = append(r.changes, changes...)
	return nil
}

func TestSyncChangeLogLimitsHydrationDuringMassChanges(t *testing.T) {
	repo := &changeLogCaptureRepo{}
	worker := &SyncWorker{assets: asset.NewService(repo)}
	ids := make([]string, 1200)
	current := make([]asset.Asset, len(ids))
	for i := range ids {
		ids[i] = fmt.Sprintf("changed-%04d", i)
		current[i] = asset.Asset{ID: ids[i], Name: "after"}
	}
	worker.writeAssetChangeLog(t.Context(), "connector", current, ids)
	require.Equal(t, ids[:200], repo.readIDs, "observability hydration stays bounded independently of correlation job size")
	require.Equal(t, "connector", repo.connectorID)
	require.Len(t, repo.changes, 200)
	for i, change := range repo.changes {
		require.Equal(t, asset.FieldChange{AssetID: ids[i], Field: "name", OldValue: "before", NewValue: "after"}, change)
	}
}
