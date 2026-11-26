package connector

import (
	"context"
	"fmt"
	"time"
)

// ObserveDeletionCandidates records the exact absent set from a complete,
// audited enumeration. Empty input resets confirmation (also used for partial
// listings). Only repeated absence older than confirmedBefore can be returned.
func (s *Service) ObserveDeletionCandidates(ctx context.Context, connectorID string, ids []string, at, confirmedBefore time.Time, limit int) ([]string, error) {
	if at.IsZero() || !confirmedBefore.Before(at) || limit <= 0 || limit > 5000 {
		return nil, fmt.Errorf("ObserveDeletionCandidates: invalid confirmation bounds")
	}
	confirmed, err := s.repo.ObserveDeletionCandidates(ctx, connectorID, ids, at, confirmedBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("ObserveDeletionCandidates: %w", err)
	}
	return confirmed, nil
}
