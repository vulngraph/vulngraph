//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	"golang.org/x/sync/errgroup"
)

func TestEnvelopeDerivedAtomicPublication(t *testing.T) {
	if os.Getenv("PERF_ENVELOPE_ISOLATED") != "1" {
		t.Skip("isolated concurrent publication replay")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	chA, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer chA.Close()
	chB, err := db.NewCH(ctx, os.Getenv("PERF_APP_CLICKHOUSE_URL"), 4)
	require.NoError(t, err)
	defer chB.Close()
	a, b := asset.NewService(asset.NewCHRepo(chA)), asset.NewService(asset.NewCHRepo(chB))
	ids := []string{"atomic-risk-a", "atomic-risk-b"}
	require.NoError(t, a.Ingest(ctx, []asset.Asset{
		{ID: ids[0], Name: "observation-a", Type: "ec2_instance", Provider: asset.ProviderAWS, RiskScore: 5, LastSeen: time.Now()},
		{ID: ids[1], Name: "observation-b", Type: "ec2_instance", Provider: asset.ProviderAWS, RiskScore: 5, LastSeen: time.Now()},
	}, nil))
	initial, err := a.BeginDerivedUpdate(ctx)
	require.NoError(t, err)
	require.NoError(t, a.PublishFindingRisk(ctx, initial, map[string]uint8{ids[0]: 60, ids[1]: 80}))
	group, workCtx := errgroup.WithContext(ctx)
	ready, done := make(chan struct{}), make(chan struct{})
	var reads atomic.Int64
	group.Go(func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("publication reader panic: %v", p)
			}
		}()
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		close(ready)
		for {
			select {
			case <-done:
				return nil
			case <-workCtx.Done():
				return workCtx.Err()
			case <-ticker.C:
			}
			rows, e := a.ByIDs(workCtx, ids)
			if e != nil {
				return e
			}
			scores := map[string]uint8{}
			for _, row := range rows {
				scores[row.ID] = row.RiskScore
			}
			validPair := (scores[ids[0]] == 60 && scores[ids[1]] == 80) || (scores[ids[0]] == 80 && scores[ids[1]] == 60)
			if len(rows) != 2 || !validPair {
				return fmt.Errorf("mixed or missing published generation: %v", scores)
			}
			reads.Add(1)
		}
	})
	group.Go(func() (err error) {
		defer close(done)
		defer func() {
			if p := recover(); p != nil {
				err = fmt.Errorf("publication writer panic: %v", p)
			}
		}()
		<-ready
		for i := 0; i < 40; i++ {
			version, e := b.BeginDerivedUpdate(workCtx)
			if e != nil {
				return e
			}
			left, right := uint8(60), uint8(80)
			if i%2 == 0 {
				left, right = right, left
			}
			if e := b.PublishFindingRisk(workCtx, version, map[string]uint8{ids[0]: left, ids[1]: right}); e != nil {
				return fmt.Errorf("publish generation %d: %w", i, e)
			}
		}
		return nil
	})
	err = group.Wait()
	evidence, encodeErr := json.MarshalIndent(map[string]any{"passed": err == nil, "concurrent_readbacks": reads.Load(), "attempted_generations": 40,
		"scope": "two independent services; each two-asset read must match one complete published pair; not a cross-table inventory snapshot proof"}, "", "  ")
	require.NoError(t, encodeErr)
	require.NoError(t, os.WriteFile(filepath.Join(os.Getenv("PERF_ENVELOPE_DIR"), "derived-publication-replay.json"), evidence, 0600))
	require.NoError(t, err)
	require.Positive(t, reads.Load())
}
