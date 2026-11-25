package costdata

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	collectaws "github.com/vulngraph/vulngraph/internal/collect/aws"
)

// Repo is the storage interface the Service depends on.
type Repo interface {
	SaveSnapshots(ctx context.Context, snaps []CostSnapshot) error
	ListRecent(ctx context.Context, connectorID string, days int) ([]CostSnapshot, error)
	DetectAnomalies(ctx context.Context, connectorID string) ([]CostAnomaly, error)
	SnapshotCounts(ctx context.Context) (map[string]SnapshotCount, error)
}

// Service provides cost data collection and anomaly detection.
type Service struct {
	repo   Repo
	status *statusStore
	now    func() time.Time
}

func NewService(repo Repo) *Service {
	return &Service{repo: repo, status: newStatusStore(), now: time.Now}
}

// Collect fetches the last 30 days of daily cost data from AWS Cost Explorer and
// persists them as snapshots for the given connector/account.
//
// It returns the classified CollectStatus as well as the error, and records that
// status internally, so a caller cannot accidentally reduce a permission denial
// to "nothing happened". A nil error with Outcome == OutcomeEmpty is a real
// outcome, not a success: SaveSnapshots is a no-op on an empty batch, so before
// this the "the API returned nothing" case was indistinguishable from a healthy
// collection.
func (s *Service) Collect(ctx context.Context, connectorID, accountID string, awsCfg awssdk.Config) (CollectStatus, error) {
	st := CollectStatus{
		ConnectorID: connectorID,
		AccountID:   accountID,
		AttemptAt:   s.now(),
	}

	entries, err := collectaws.FetchCostByService(ctx, awsCfg, 30)
	if err != nil {
		st.Outcome = ClassifyCollectError(err)
		st.Detail = err.Error()
		s.status.record(st)
		return st, fmt.Errorf("Collect: %w", err)
	}
	st.Fetched = len(entries)

	snaps := make([]CostSnapshot, 0, len(entries))
	for _, e := range entries {
		snaps = append(snaps, CostSnapshot{
			ConnectorID: connectorID,
			AccountID:   accountID,
			Service:     e.Service,
			CostUSD:     e.CostUSD,
			PeriodDate:  e.Date,
		})
	}

	if err := s.repo.SaveSnapshots(ctx, snaps); err != nil {
		st.Outcome = OutcomeStoreError
		st.Detail = err.Error()
		s.status.record(st)
		return st, fmt.Errorf("Collect: %w", err)
	}

	st.Outcome = OutcomeOK
	if len(snaps) == 0 {
		st.Outcome = OutcomeEmpty
		st.Detail = "Cost Explorer returned no cost entries for the last 30 days"
	}
	s.status.record(st)
	return st, nil
}

// RecordStatus stores a collection outcome the Service could not observe itself
// — a connector whose config never produced an AWS config, so Collect was never
// reached. Without this the config-error skip left no trace anywhere.
func (s *Service) RecordStatus(st CollectStatus) {
	if st.AttemptAt.IsZero() {
		st.AttemptAt = s.now()
	}
	s.status.record(st)
}

// GetSnapshots returns recent cost snapshots for a connector.
func (s *Service) GetSnapshots(ctx context.Context, connectorID string, days int) ([]CostSnapshot, error) {
	if days <= 0 {
		days = 30
	}
	out, err := s.repo.ListRecent(ctx, connectorID, days)
	if err != nil {
		return nil, fmt.Errorf("GetSnapshots: %w", err)
	}
	return out, nil
}

// GetAnomalies returns spending anomalies for a connector: the repository's
// rolling-average rule (see the package doc), plus detectResourceAnomalies
// over the last 30 days of snapshots for services the first rule did not flag.
// A failed snapshot read is returned as an error rather than reported as
// "no further anomalies".
func (s *Service) GetAnomalies(ctx context.Context, connectorID string) ([]CostAnomaly, error) {
	out, err := s.repo.DetectAnomalies(ctx, connectorID)
	if err != nil {
		return nil, fmt.Errorf("GetAnomalies: %w", err)
	}
	snaps, err := s.repo.ListRecent(ctx, connectorID, 30)
	if err != nil {
		return nil, fmt.Errorf("GetAnomalies: %w", err)
	}
	covered := make(map[string]bool, len(out))
	for _, a := range out {
		covered[a.ConnectorID+"|"+a.Service] = true
	}
	for _, a := range detectResourceAnomalies(snaps) {
		if !covered[a.ConnectorID+"|"+a.Service] {
			out = append(out, a)
		}
	}
	return out, nil
}

// detectResourceAnomalies compares each service's latest day's cost against
// the mean and standard deviation of its earlier days. The latest day is not
// part of its own baseline, and a service needs at least two earlier days.
// Thresholds tighten as the baseline grows (fewer points: more sigmas and a
// larger minimum dollar delta). Results are sorted by connector, then service.
func detectResourceAnomalies(snapshots []CostSnapshot) []CostAnomaly {
	type series struct {
		connectorID, service string
		points               []CostSnapshot
	}
	byService := make(map[string]*series)
	for _, s := range snapshots {
		key := s.ConnectorID + "|" + s.Service
		if byService[key] == nil {
			byService[key] = &series{connectorID: s.ConnectorID, service: s.Service}
		}
		byService[key].points = append(byService[key].points, s)
	}

	var anomalies []CostAnomaly
	for _, sr := range byService {
		latestIdx := 0
		for i, p := range sr.points {
			if p.PeriodDate.After(sr.points[latestIdx].PeriodDate) {
				latestIdx = i
			}
		}
		latest := sr.points[latestIdx]
		baseline := make([]float64, 0, len(sr.points)-1)
		for i, p := range sr.points {
			if i != latestIdx && p.PeriodDate.Before(latest.PeriodDate) {
				baseline = append(baseline, p.CostUSD)
			}
		}
		n := len(baseline)
		if n < 2 {
			continue
		}
		var sum float64
		for _, v := range baseline {
			sum += v
		}
		mean := sum / float64(n)
		var variance float64
		for _, v := range baseline {
			d := v - mean
			variance += d * d
		}
		stddev := math.Sqrt(variance / float64(n))

		var sigmaMultiplier, minDelta float64
		switch {
		case n <= 3:
			sigmaMultiplier, minDelta = 5.0, 5.0
		case n <= 7:
			sigmaMultiplier, minDelta = 4.0, 3.0
		case n <= 14:
			sigmaMultiplier, minDelta = 3.5, 2.0
		default:
			sigmaMultiplier, minDelta = 3.0, 1.0
		}

		delta := latest.CostUSD - mean
		if latest.CostUSD > mean+sigmaMultiplier*stddev && delta >= minDelta {
			anomalies = append(anomalies, CostAnomaly{
				ConnectorID:   sr.connectorID,
				Service:       sr.service,
				LatestCostUSD: latest.CostUSD,
				RollingAvgUSD: mean,
				DeltaUSD:      delta,
				PeriodDate:    latest.PeriodDate,
			})
		}
	}
	slices.SortFunc(anomalies, func(a, b CostAnomaly) int {
		return cmp.Or(strings.Compare(a.ConnectorID, b.ConnectorID), strings.Compare(a.Service, b.Service))
	})
	return anomalies
}
