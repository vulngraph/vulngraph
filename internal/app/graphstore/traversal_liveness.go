package graphstore

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// liveTraversalEdges removes confirmed departed endpoints before any consumer
// derives reach, risk, digests or snapshots. It does not infer deletion from a
// missing node: an absent endpoint can also be a partial fetch or collector gap.
func liveTraversalEdges(ctx context.Context, assets []asset.Asset, edges []asset.Edge, verify expiredEphemeralVerifier) ([]asset.Edge, error) {
	if verify == nil {
		return edges, nil
	}
	loaded := make(map[string]bool, len(assets))
	for _, a := range assets {
		loaded[a.ID] = true
	}
	loaded[InternetNodeID] = true
	loaded[secretWildcardID] = true
	for _, id := range dataClassSentinelIDs {
		loaded[id] = true
	}
	candidates := map[string]bool{}
	for _, e := range edges {
		if !loaded[e.SrcID] {
			candidates[e.SrcID] = true
		}
		if !loaded[e.DstID] {
			candidates[e.DstID] = true
		}
	}
	if len(candidates) == 0 {
		return edges, nil
	}
	ids := make([]string, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	expired, err := verify(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("verify departed traversal endpoints: %w", err)
	}
	// Accept only requested, absent IDs. A concurrent observation may have
	// restored an endpoint that this load already contains.
	for id := range expired {
		if !candidates[id] {
			delete(expired, id)
		}
	}
	if len(expired) == 0 {
		return edges, nil
	}
	out := edges[:0]
	for _, e := range edges {
		if !expired[e.SrcID] && !expired[e.DstID] {
			out = append(out, e)
		}
	}
	dropped := len(edges) - len(out)
	clear(edges[len(out):])
	if dropped > 0 {
		log.FromContext(ctx).Info().Int("edges", dropped).Msg("graphstore: excluded edges through confirmed departed resources")
	}
	return out, nil
}
