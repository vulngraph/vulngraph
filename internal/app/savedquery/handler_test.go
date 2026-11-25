package savedquery

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

// historyRepo is fakeRepo whose List reports each query's newest recorded run
// as LastAttempt, as PGRepo's lateral join does.
type historyRepo struct {
	fakeRepo
	query SavedQuery
}

func (h *historyRepo) List(context.Context) ([]SavedQuery, error) {
	q := h.query
	if n := len(h.recorded); n > 0 {
		last := h.recorded[n-1].run
		last.RanAt = time.Date(2026, 10, 20, 0, 0, n, 0, time.UTC)
		q.LastAttempt = &last
	}
	return []SavedQuery{q}, nil
}

func listResponse(t *testing.T, svc *Service) queryResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	NewHandler(svc).List(rec, httptest.NewRequest(http.MethodGet, "/api/saved-queries", nil))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Queries []queryResponse `json:"queries"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Len(t, body.Queries, 1)
	return body.Queries[0]
}

// The response carries the newest run of any outcome beside the baseline: a
// scheduled query whose runs fail or truncate keeps its old baseline, and
// must not read as healthy; a manual-only query that ran is not "never run".
func TestList_ReportsLatestAttemptBesideTheBaseline(t *testing.T) {
	baselineAt := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	q := SavedQuery{ID: "q1", Name: "n", Cypher: "MATCH (n) RETURN n", Schedule: "0 * * * *",
		LastRunAt: &baselineAt, LastResultCount: 12, LastResultHash: "h"}
	repo := &historyRepo{query: q}
	runner := &fakeRunner{}
	svc := NewService(repo).WithRunner(runner).WithReadiness(ready)

	resp := listResponse(t, svc)
	require.Empty(t, resp.LastAttemptAt, "never run")
	require.Empty(t, resp.LastAttemptStatus)

	runner.err = errors.New("graph engine timeout")
	_, err := svc.Run(context.Background(), q, TriggerSchedule)
	require.Error(t, err)
	resp = listResponse(t, svc)
	require.Equal(t, RunStatusFailed, resp.LastAttemptStatus)
	require.Contains(t, resp.LastAttemptError, "graph engine timeout")
	require.Equal(t, TriggerSchedule, resp.LastAttemptTrigger)
	require.NotEmpty(t, resp.LastAttemptAt)
	require.Equal(t, "2026-10-01T00:00:00Z", resp.LastRunAt, "the baseline stays where the last good run left it")
	require.Equal(t, 12, resp.LastResultCount)

	runner.err, runner.res = nil, QueryResult{NodeIDs: []string{"a"}, Truncated: true}
	_, err = svc.Run(context.Background(), q, TriggerSchedule)
	require.ErrorIs(t, err, ErrResultTruncated)
	resp = listResponse(t, svc)
	require.Equal(t, RunStatusTruncated, resp.LastAttemptStatus)
	require.Equal(t, ErrResultTruncated.Error(), resp.LastAttemptError)

	runner.res = QueryResult{NodeIDs: []string{"a"}}
	_, err = svc.Run(context.Background(), q, TriggerManual)
	require.NoError(t, err)
	resp = listResponse(t, svc)
	require.Equal(t, RunStatusOK, resp.LastAttemptStatus)
	require.Empty(t, resp.LastAttemptError)
	require.Equal(t, TriggerManual, resp.LastAttemptTrigger)
}

func TestRunStatus(t *testing.T) {
	tests := []struct {
		err  string
		want string
	}{
		{"", RunStatusOK},
		{ErrResultTruncated.Error(), RunStatusTruncated},
		{ErrMultiHopMayBeIncomplete.Error(), RunStatusIncomplete},
		{"change alert not delivered, baseline kept: smtp down", RunStatusFailed},
		{"change alert reached no channel, baseline advanced: none", RunStatusFailed},
		{"cypher syntax error", RunStatusFailed},
		{appendRunError(ErrMultiHopMayBeIncomplete.Error(), "change alert not delivered, baseline kept: smtp down"), RunStatusFailed},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, Run{Error: tt.err}.Status(), tt.err)
	}
}
