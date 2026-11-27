package correlate

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type cancellationRule struct {
	calls  *int
	cancel context.CancelFunc
}

func (c cancellationRule) Name() string           { return "cancellation-test" }
func (c cancellationRule) InterestedIn() []string { return []string{"k8s_pod"} }
func (c cancellationRule) Correlate(Graph) []asset.Edge {
	*c.calls++
	if c.cancel != nil {
		c.cancel()
	}
	return []asset.Edge{{SrcID: "pod", DstID: "target", EdgeType: "targets"}}
}

func TestInterruptedCorrelationStopsRulesAndPublication(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, cancelAt := range []int{0, 1, 2} {
			t.Run(fmt.Sprintf("partial=%v/cancel=%d", partial, cancelAt), func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				calls := 0
				rules := []Rule{cancellationRule{calls: &calls}, cancellationRule{calls: &calls}}
				if cancelAt == 0 {
					cancel()
				} else {
					rules[cancelAt-1] = cancellationRule{calls: &calls, cancel: cancel}
				}
				writer := &fakeWriter{}
				service := NewService(fakeLoader{assets: []asset.Asset{{ID: "pod", Type: "k8s_pod"}}}, writer, rules)
				var err error
				if partial {
					_, err = service.PartialCorrelate(ctx, []string{"pod"})
				} else {
					_, err = service.Correlate(ctx)
				}
				require.ErrorIs(t, err, context.Canceled)
				require.Equal(t, cancelAt, calls, "do not start another rule after cancellation")
				require.Empty(t, writer.got, "an interrupted sweep must not publish edges through detached write budgets")
			})
		}
	}
}
