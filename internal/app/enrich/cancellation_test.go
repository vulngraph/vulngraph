package enrich

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type cancellingSource struct{ cancel context.CancelFunc }

func (c cancellingSource) Name() string { return "cancelled_source" }
func (c cancellingSource) Evaluate(ctx context.Context, _ finding.Finding) (Factor, bool, error) {
	c.cancel()
	return Factor{}, false, ctx.Err()
}

type cancellingSafety struct {
	*fakeSafetyProvider
	cancel context.CancelFunc
}

func (c cancellingSafety) Get(ctx context.Context, _ string) (asset.Asset, error) {
	c.cancel()
	return asset.Asset{}, ctx.Err()
}

func TestEnrichCancellationCannotPublishDegradedOutput(t *testing.T) {
	for _, stage := range []string{"sources", "assessment"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writer, signals := &fakeFindingWriter{}, &fakeSignalRepo{}
			svc := NewService(writer, signals, []Source{BaseSeverity{}})
			if stage == "sources" {
				svc.sources = append(svc.sources, cancellingSource{cancel})
			} else {
				svc.safety = cancellingSafety{&fakeSafetyProvider{}, cancel}
			}
			_, err := svc.Enrich(ctx, sampleFinding())
			require.ErrorIs(t, err, context.Canceled)
			require.Empty(t, writer.recorded, "cancelled measurements must never reach durable writers")
			require.False(t, signals.wrote)
		})
	}
}
