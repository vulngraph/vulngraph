package main

import (
	"context"

	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// repeatHotspotsAdapter wires reasoncache.Service.TopEscalatedRepeats as the
// respond Decisions-summary panel's hotspot source. respond's RepeatHotspots
// seam deliberately doesn't name reasoncache.Entry (mirrors
// ActionApplicability/PatternVerdicts — respond's seams never carry another
// package's types), so this converter lives here, at the wiring layer.
func repeatHotspotsAdapter(cache *reasoncache.Service) respond.RepeatHotspotsFunc {
	return func(ctx context.Context, limit int) ([]respond.RepeatHotspot, error) {
		entries, err := cache.TopEscalatedRepeats(ctx, limit)
		if err != nil {
			return nil, err
		}
		out := make([]respond.RepeatHotspot, len(entries))
		for i, e := range entries {
			out[i] = respond.RepeatHotspot{FindingID: e.FindingID, Count: e.RepeatCount, Latest: e.LastRepeatedAt}
		}
		return out, nil
	}
}
