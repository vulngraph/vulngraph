package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
)

// ladybugRiskScores implements alertctx.PropagatedScores over the Ladybug tiers of
// the explore seam only. The ClickHouse tier is deliberately absent: its node
// score is the stored, pre-propagation value, and a tiered repo that fell
// through to it would label that value as propagated.
//
// Tiers are asked in order for the ids the previous tiers did not hold; a tier
// that reports not ready (serve Ladybug during its initial sync) is skipped.
type ladybugRiskScores struct {
	tiers []explore.Repo
}

func (w *ladybugRiskScores) PropagatedRiskScores(ctx context.Context, ids []string) (map[string]uint8, error) {
	out := make(map[string]uint8, len(ids))
	remaining := ids
	var errs []error
	asked := 0
	for _, tier := range w.tiers {
		if len(remaining) == 0 {
			break
		}
		if r, ok := tier.(interface{ Ready() bool }); ok && !r.Ready() {
			continue
		}
		asked++
		nodes, err := tier.MatchSeed(ctx, explore.NodeMatch{IDs: remaining}, len(remaining))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, n := range nodes {
			// Package's score column is a finding severity, not a risk score.
			if graphstore.CarriesRiskScore(n.Type) {
				out[n.ID] = uint8(min(max(n.Score, 0), 100))
			}
		}
		remaining = missing(remaining, out)
	}
	if asked > 0 && len(errs) == asked {
		return nil, fmt.Errorf("PropagatedRiskScores: every Ladybug tier failed: %w", errors.Join(errs...))
	}
	return out, nil
}

func missing(ids []string, have map[string]uint8) []string {
	var out []string
	for _, id := range ids {
		if _, ok := have[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}
