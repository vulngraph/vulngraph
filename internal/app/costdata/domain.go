// Package costdata stores and surfaces AWS Cost Explorer snapshots and
// spending anomalies. Snapshots are daily per-service cost points. Two rules
// flag a service: its latest day cost is more than 2× its 7-day rolling
// average AND the absolute delta exceeds $5 (the repository query); or its
// latest day cost exceeds the mean of its earlier days in the last 30 by
// several standard deviations and by at least $1 to $5, depending on how many
// earlier days there are (detectResourceAnomalies).
package costdata

import (
	"context"
	"errors"
	"time"
)

// CostSnapshot is one (connector, service, date) cost data point.
type CostSnapshot struct {
	ID          string
	ConnectorID string
	AccountID   string
	Service     string
	CostUSD     float64
	PeriodDate  time.Time
	CollectedAt time.Time
}

// CostAnomaly describes a service whose spending spiked unexpectedly.
type CostAnomaly struct {
	ConnectorID   string
	Service       string
	LatestCostUSD float64
	RollingAvgUSD float64
	DeltaUSD      float64
	PeriodDate    time.Time
}

// SnapshotCount is what is durably stored for one connector: how many snapshot
// rows, and when the newest was written. It answers "has cost collection EVER
// worked for this account", which no in-memory attempt log can.
type SnapshotCount struct {
	Rows            int
	LastCollectedAt time.Time
}

// Repository is the storage interface costdata.Service depends on.
type Repository interface {
	SaveSnapshots(ctx context.Context, snaps []CostSnapshot) error
	ListRecent(ctx context.Context, connectorID string, days int) ([]CostSnapshot, error)
	DetectAnomalies(ctx context.Context, connectorID string) ([]CostAnomaly, error)
	SnapshotCounts(ctx context.Context) (map[string]SnapshotCount, error)
}

var ErrNotFound = errors.New("costdata: not found")
