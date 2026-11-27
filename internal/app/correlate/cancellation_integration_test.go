//go:build integration

package correlate

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
)

type cancelledEdgeRule struct {
	edge   asset.Edge
	cancel context.CancelFunc
}

func (r cancelledEdgeRule) Name() string           { return "cancelled-edge" }
func (r cancelledEdgeRule) InterestedIn() []string { return []string{"k8s_pod"} }
func (r cancelledEdgeRule) Correlate(Graph) []asset.Edge {
	if r.cancel != nil {
		r.cancel()
	}
	return []asset.Edge{r.edge}
}

func TestCancelledCorrelationPreservesStoredEdges(t *testing.T) {
	if os.Getenv("TEST_CLICKHOUSE_URL") == "" {
		t.Skip("requires isolated migrated ClickHouse")
	}
	ctx := t.Context()
	ch, err := db.NewCH(ctx, os.Getenv("TEST_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer ch.Close()
	repo := asset.NewCHRepo(ch)
	for _, partial := range []bool{false, true} {
		seed := "cancel-correlate-" + uuid.NewString()
		edge := asset.Edge{SrcID: seed, SrcType: "k8s_pod", DstID: seed + "-target", DstType: "k8s_pod", EdgeType: "targets", Properties: map[string]string{"observation": "previous"}}
		require.NoError(t, repo.UpsertEdges(ctx, []asset.Edge{edge}))
		defer func() {
			require.NoError(t, ch.Exec(ctx, "DELETE FROM graph_edges WHERE src_id=? SETTINGS mutations_sync=1", seed))
		}()
		edge.Properties = map[string]string{"observation": "replacement"}
		interrupted, cancel := context.WithCancel(ctx)
		rule := cancelledEdgeRule{edge: edge, cancel: cancel}
		service := NewService(fakeLoader{assets: []asset.Asset{{ID: seed, Type: "k8s_pod"}}}, asset.NewService(repo), []Rule{rule})
		run := func(runCtx context.Context) error {
			if partial {
				_, err = service.PartialCorrelate(runCtx, []string{seed})
			} else {
				_, err = service.Correlate(runCtx)
			}
			return err
		}
		require.ErrorIs(t, run(interrupted), context.Canceled)
		cancel()
		stored, err := repo.EdgesFrom(ctx, []string{seed})
		require.NoError(t, err)
		require.Len(t, stored, 1)
		require.Equal(t, "previous", stored[0].Properties["observation"])
		service.rules = []Rule{cancelledEdgeRule{edge: edge}}
		require.NoError(t, run(ctx))
		stored, err = repo.EdgesFrom(ctx, []string{seed})
		require.NoError(t, err)
		require.Len(t, stored, 1)
		require.Equal(t, "replacement", stored[0].Properties["observation"])
	}
}
