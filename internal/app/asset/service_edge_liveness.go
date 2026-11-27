package asset

import "context"

func (s *Service) withoutDeletedEndpoints(ctx context.Context, edges []Edge) ([]Edge, error) {
	if s.deletionProofs == nil || len(edges) == 0 {
		return edges, nil
	}
	seen := map[string]bool{}
	var ids []string
	for _, e := range edges {
		for _, id := range []string{e.SrcID, e.DstID} {
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	deleted, err := s.VerifyDeletedAssets(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := edges[:0]
	for _, edge := range edges {
		if !deleted[edge.SrcID] && !deleted[edge.DstID] {
			out = append(out, edge)
		}
	}
	return out, nil
}
