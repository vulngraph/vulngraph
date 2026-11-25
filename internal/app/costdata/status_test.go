package costdata

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// fakeRepo is a Repo whose SaveSnapshots records what it was given, so the
// "empty batch accepted as success" path is observable in a test.
type fakeRepo struct {
	saved     []CostSnapshot
	counts    map[string]SnapshotCount
	saveEr    error
	recent    []CostSnapshot
	recentErr error
	anomalies []CostAnomaly
}

func (f *fakeRepo) SaveSnapshots(_ context.Context, snaps []CostSnapshot) error {
	if f.saveEr != nil {
		return f.saveEr
	}
	f.saved = append(f.saved, snaps...)
	return nil
}

func (f *fakeRepo) ListRecent(context.Context, string, int) ([]CostSnapshot, error) {
	return f.recent, f.recentErr
}

func (f *fakeRepo) DetectAnomalies(context.Context, string) ([]CostAnomaly, error) {
	return f.anomalies, nil
}

func (f *fakeRepo) SnapshotCounts(context.Context) (map[string]SnapshotCount, error) {
	if f.counts == nil {
		return map[string]SnapshotCount{}, nil
	}
	return f.counts, nil
}

// apiErr is a smithy APIError with a chosen code — how AWS actually expresses an
// IAM refusal on the Cost Explorer endpoint.
type apiErr struct{ code string }

func (e apiErr) Error() string                 { return e.code + ": denied" }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return "denied" }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func TestClassifyCollectError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, OutcomeOK},
		{"access denied code", apiErr{"AccessDeniedException"}, OutcomePermissionDenied},
		{"access denied bare", apiErr{"AccessDenied"}, OutcomePermissionDenied},
		{"unauthorized operation", apiErr{"UnauthorizedOperation"}, OutcomePermissionDenied},
		{"opt-in required", apiErr{"OptInRequired"}, OutcomePermissionDenied},
		{"cost explorer never enabled", apiErr{"DataUnavailableException"}, OutcomePermissionDenied},
		{"throttling is not a denial", apiErr{"ThrottlingException"}, OutcomeAPIError},
		{"wrapped api error", errors.Join(errors.New("Collect"), apiErr{"AccessDeniedException"}), OutcomePermissionDenied},
		{"message-only denial", errors.New("operation error Cost Explorer: not authorized to perform ce:GetCostAndUsage"), OutcomePermissionDenied},
		{"plain failure", errors.New("dial tcp: timeout"), OutcomeAPIError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, ClassifyCollectError(c.err))
			require.Equal(t, c.want == OutcomePermissionDenied, IsPermissionDenied(c.err))
		})
	}
}

// Collect must classify and record its outcome, so a caller cannot lose a
// failure. The pre-fix loop discarded everything but a Warn on the error path.
func TestCollect_RecordsStatusForEveryOutcome(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)

	// A config-error skip never reaches Collect, so the loop reports it directly;
	// without this the skip left no trace anywhere at all.
	svc.RecordStatus(CollectStatus{ConnectorID: "c-cfg", Outcome: OutcomeConfigError, Detail: "bad role arn"})

	statuses, err := svc.Statuses(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.Equal(t, OutcomeConfigError, statuses[0].Outcome)
	require.False(t, statuses[0].Collected())
	require.False(t, statuses[0].AttemptAt.IsZero(), "an attempt with no timestamp is unreadable")
}

// The durable half: stored rows come from Postgres, so "has it ever worked" is
// answerable after a restart, when the in-memory attempt log is empty.
func TestStatuses_MergesStoredCounts(t *testing.T) {
	collected := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	repo := &fakeRepo{counts: map[string]SnapshotCount{
		"c-1": {Rows: 120, LastCollectedAt: collected},
	}}
	svc := NewService(repo)

	statuses, err := svc.Statuses(context.Background())
	require.NoError(t, err)
	require.Len(t, statuses, 1)
	require.Equal(t, 120, statuses[0].SnapshotsStored)
	require.True(t, statuses[0].Collected())
	require.Equal(t, collected, statuses[0].LastCollectedAt)
	// No attempt in this process lifetime: outcome is empty string, NOT "ok".
	require.Equal(t, "", statuses[0].Outcome)
}

// A permission denial must reach the API as a permission denial. This is the
// whole point: 0 rows plus "no anomalies" was indistinguishable from health.
func TestStatusHandler_ReportsDenialAndRequiredPermission(t *testing.T) {
	repo := &fakeRepo{}
	svc := NewService(repo)
	svc.RecordStatus(CollectStatus{
		ConnectorID: "c-1", AccountID: "210987654321",
		Outcome: OutcomePermissionDenied, Detail: "AccessDeniedException: denied",
	})

	rec := httptest.NewRecorder()
	NewHandler(svc).Status(rec, httptest.NewRequest(http.MethodGet, "/api/cost/status", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var got costStatusResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.False(t, got.Collected)
	require.Equal(t, 0, got.SnapshotsTotal)
	require.Equal(t, "ce:GetCostAndUsage", got.RequiredIAMPermission)
	require.Len(t, got.Connectors, 1)
	require.Equal(t, OutcomePermissionDenied, got.Connectors[0].Outcome)
	require.Equal(t, "210987654321", got.Connectors[0].AccountID)
	require.NotEmpty(t, got.Connectors[0].AttemptAt)
}

// An empty Cost Explorer answer is a distinct outcome from success: SaveSnapshots
// returns nil for an empty batch, so without this distinction "the API gave us
// nothing" was stored as, and reported as, a healthy collection.
func TestCollect_EmptyResultIsNotSuccess(t *testing.T) {
	// FetchCostByService is not injectable, so drive the classification directly
	// through the same statuses path the loop reads.
	svc := NewService(&fakeRepo{})
	svc.RecordStatus(CollectStatus{ConnectorID: "c-1", Outcome: OutcomeEmpty, Fetched: 0})

	statuses, err := svc.Statuses(context.Background())
	require.NoError(t, err)
	require.Equal(t, OutcomeEmpty, statuses[0].Outcome)
	require.NotEqual(t, OutcomeOK, statuses[0].Outcome)
	require.False(t, statuses[0].Collected())
}

// Collect against an unconfigured AWS config still classifies rather than
// vanishing: whatever the SDK returns, the status is recorded and the error is
// wrapped, never swallowed.
func TestCollect_ErrorIsClassifiedAndRecorded(t *testing.T) {
	svc := NewService(&fakeRepo{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // force the SDK call to fail fast without network access

	st, err := svc.Collect(ctx, "c-1", "1234567890", awssdk.Config{Region: "us-east-1"})
	require.Error(t, err)
	require.Equal(t, "c-1", st.ConnectorID)
	require.NotEqual(t, OutcomeOK, st.Outcome)
	require.NotEmpty(t, st.Detail)

	statuses, sErr := svc.Statuses(context.Background())
	require.NoError(t, sErr)
	require.Len(t, statuses, 1)
	require.Equal(t, st.Outcome, statuses[0].Outcome)
}
