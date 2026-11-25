package httpsrv

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// findingRisk is the slice of finding.Service the asset list needs to show each
// asset's finding rollup. finding.Service implements it.
type findingRisk interface {
	RiskByResource(ctx context.Context, ids []string) (map[string]finding.Risk, error)
	RiskiestResources(ctx context.Context, limit int) ([]finding.ResourceRisk, error)
}

// assetRiskAdapter bridges the finding domain to asset.RiskProvider, converting
// finding's risk types to asset-local ones so the asset package stays decoupled
// from the finding package. This composition lives in the HTTP layer.
type assetRiskAdapter struct{ f findingRisk }

// AssetRiskProvider adapts a finding service into the risk provider the asset
// handler consumes.
func AssetRiskProvider(f findingRisk) asset.RiskProvider { return assetRiskAdapter{f: f} }

func (a assetRiskAdapter) RiskByResource(ctx context.Context, ids []string) (map[string]asset.AssetRisk, error) {
	in, err := a.f.RiskByResource(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[string]asset.AssetRisk, len(in))
	for id, r := range in {
		out[id] = asset.AssetRisk{Count: r.Count, MaxScore: r.MaxScore, Band: r.WorstBand}
	}
	return out, nil
}

func (a assetRiskAdapter) RiskiestResources(ctx context.Context, limit int) ([]asset.RankedRisk, error) {
	in, err := a.f.RiskiestResources(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]asset.RankedRisk, len(in))
	for i, rr := range in {
		out[i] = asset.RankedRisk{
			ResourceID: rr.ResourceID,
			AssetRisk:  asset.AssetRisk{Count: rr.Count, MaxScore: rr.MaxScore, Band: rr.WorstBand},
		}
	}
	return out, nil
}
