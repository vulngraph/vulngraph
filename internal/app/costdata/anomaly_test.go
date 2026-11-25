package costdata

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var day0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// series builds one service's daily snapshots, oldest first.
func series(service string, costs ...float64) []CostSnapshot {
	out := make([]CostSnapshot, len(costs))
	for i, c := range costs {
		out[i] = CostSnapshot{ConnectorID: "c1", Service: service, CostUSD: c, PeriodDate: day0.AddDate(0, 0, i)}
	}
	return out
}

func TestDetectResourceAnomalies(t *testing.T) {
	tests := []struct {
		name  string
		snaps []CostSnapshot
		want  []CostAnomaly
	}{
		{name: "no data", snaps: nil, want: nil},
		{name: "one earlier day is not a baseline", snaps: series("ec2", 1, 100), want: nil},
		{name: "flat spend", snaps: series("ec2", 10, 10, 10, 10, 10), want: nil},
		{name: "small spike under the dollar floor", snaps: series("ec2", 1, 1, 4), want: nil},
		{
			name:  "spike against two earlier days",
			snaps: series("ec2", 10, 10, 50),
			want:  []CostAnomaly{{ConnectorID: "c1", Service: "ec2", LatestCostUSD: 50, RollingAvgUSD: 10, DeltaUSD: 40, PeriodDate: day0.AddDate(0, 0, 2)}},
		},
		{
			// With the latest day in its own baseline the mean is 20 and the
			// stddev ~17.3, so 50 never clears 5 sigma and the spike is missed.
			name:  "latest day is excluded from its own baseline",
			snaps: series("s3", 10, 10, 10, 50),
			want:  []CostAnomaly{{ConnectorID: "c1", Service: "s3", LatestCostUSD: 50, RollingAvgUSD: 10, DeltaUSD: 40, PeriodDate: day0.AddDate(0, 0, 3)}},
		},
		{
			name:  "sorted by service, regardless of input order",
			snaps: append(series("s3", 10, 10, 50), series("ec2", 10, 10, 60)...),
			want: []CostAnomaly{
				{ConnectorID: "c1", Service: "ec2", LatestCostUSD: 60, RollingAvgUSD: 10, DeltaUSD: 50, PeriodDate: day0.AddDate(0, 0, 2)},
				{ConnectorID: "c1", Service: "s3", LatestCostUSD: 50, RollingAvgUSD: 10, DeltaUSD: 40, PeriodDate: day0.AddDate(0, 0, 2)},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, detectResourceAnomalies(tc.snaps))
		})
	}
}

// A failed snapshot read is an error, not "no statistical anomalies".
func TestGetAnomalies_SnapshotReadErrorIsReturned(t *testing.T) {
	svc := NewService(&fakeRepo{recentErr: errors.New("pg down")})
	_, err := svc.GetAnomalies(context.Background(), "c1")
	require.Error(t, err)
}

// Both detectors' anomalies reach the wire with a real baseline, delta and
// date; a service the repository rule already flagged is not listed twice.
func TestAnomaliesHandler_MergesWithoutZeroFields(t *testing.T) {
	repo := &fakeRepo{
		anomalies: []CostAnomaly{{ConnectorID: "c1", Service: "s3", LatestCostUSD: 50, RollingAvgUSD: 10, DeltaUSD: 40, PeriodDate: day0.AddDate(0, 0, 2)}},
		recent:    append(series("s3", 10, 10, 50), series("ec2", 10, 10, 60)...),
	}
	rec := httptest.NewRecorder()
	NewHandler(NewService(repo)).Anomalies(rec, httptest.NewRequest(http.MethodGet, "/api/cost/anomalies?connector_id=c1", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Items []anomalyResponse `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Items, 2)
	for _, a := range body.Items {
		require.Equal(t, "2026-10-03", a.PeriodDate, a.Service)
		require.Positive(t, a.RollingAvgUSD, a.Service)
		require.Positive(t, a.DeltaUSD, a.Service)
	}
}
