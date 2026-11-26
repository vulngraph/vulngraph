package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeRetirementProofs struct {
	pending         map[string]time.Time
	readErr, ackErr error
	acks            int
}

func (f *fakeRetirementProofs) PendingAssetRetirements(context.Context, int) (map[string]time.Time, error) {
	return f.pending, f.readErr
}
func (f *fakeRetirementProofs) CompleteAssetRetirements(context.Context, map[string]time.Time) error {
	if f.ackErr != nil {
		return f.ackErr
	}
	f.pending = nil
	f.acks++
	return nil
}

type fakeRetirementInventory struct {
	calls int
	ids   []string
	err   error
}

func (f *fakeRetirementInventory) RetireAssets(context.Context, map[string]time.Time) ([]string, error) {
	f.calls++
	return f.ids, f.err
}
func TestInventoryRetirement_RetriesUntilAcknowledged(t *testing.T) {
	for _, stage := range []string{"proof", "inventory", "finding read", "finding resolve", "ack"} {
		t.Run(stage, func(t *testing.T) {
			boom := errors.New(stage)
			p := &fakeRetirementProofs{pending: map[string]time.Time{"gone": time.Now()}}
			a := &fakeRetirementInventory{ids: []string{"gone"}}
			f := &fakeLifecycler{stored: []finding.Finding{{ID: "finding", ResourceID: "gone", Source: "cspm"}}}
			switch stage {
			case "proof":
				p.readErr = boom
			case "inventory":
				a.err = boom
			case "finding read":
				f.readErr = boom
			case "finding resolve":
				f.resolveErr = boom
			case "ack":
				p.ackErr = boom
			}
			w := &InventoryRetirementWorker{proofs: p, assets: a, findings: f}
			require.ErrorIs(t, w.Work(context.Background(), &river.Job[InventoryRetirementArgs]{}), boom)
			require.NotEmpty(t, p.pending)
			require.Zero(t, p.acks)
			if stage == "proof" {
				require.Zero(t, a.calls)
			}
			p.readErr = nil
			p.ackErr = nil
			a.err = nil
			f.readErr = nil
			f.resolveErr = nil
			require.NoError(t, w.Work(context.Background(), &river.Job[InventoryRetirementArgs]{}))
			require.Empty(t, p.pending)
			require.Equal(t, 1, p.acks)
		})
	}
}
