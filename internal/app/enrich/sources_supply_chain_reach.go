package enrich

import "context"

// workloadExposure consults runtime nodes, so package reachability does not
// require projecting every installed package membership into Ladybug.
func (s SupplyChainExposure) workloadExposure(ctx context.Context, ids []string) (exposed, unknown bool, err error) {
	direct, err := s.Graph.AnyConfirmedExposure(ctx, ids)
	if err != nil {
		return false, true, err
	}
	if direct {
		return true, false, nil
	}
	if s.Reach == nil {
		return false, true, nil
	}
	for _, id := range ids {
		hops, known, err := s.Reach.InternetHops(ctx, id)
		if err != nil || !known {
			unknown = true
			continue
		}
		if hops >= 0 {
			return true, false, nil
		}
	}
	return false, unknown, nil
}
