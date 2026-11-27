package finding

import (
	"context"
	"time"
)

// The storage implementation can project observation dates without hydrating
// payloads. Repositories without that projection retain the full-read path.
type observationHistoryReader interface {
	FirstObservationsByIDs(context.Context, []string) (map[string]time.Time, error)
}

func (s *Service) firstObservationTimes(ctx context.Context, ids []string) (map[string]time.Time, error) {
	if reader, ok := s.repo.(observationHistoryReader); ok {
		return reader.FirstObservationsByIDs(ctx, ids)
	}
	existing, err := s.repo.ByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	dates := make(map[string]time.Time, len(existing))
	for _, row := range existing {
		dates[row.ID] = earliest(row.FirstDetectedAt, row.DetectedAt)
	}
	return dates, nil
}
