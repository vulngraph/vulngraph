package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeTriggerer struct {
	called bool
	err    error
}

func (f *fakeTriggerer) EnqueueScan(context.Context) error {
	f.called = true
	return f.err
}

func newTestHandler() (*Handler, *fakeRepo, *fakeTriggerer) {
	repo := &fakeRepo{}
	trig := &fakeTriggerer{}
	// List/Get only touch the repo; engine/assets/findings are unused here.
	return NewHandler(NewService(repo, nil, nil, nil, nil), trig), repo, trig
}

func TestTriggerHandler_Enqueues204(t *testing.T) {
	h, _, trig := newTestHandler()

	req := httptest.NewRequest(http.MethodPost, "/api/scans", nil)
	rec := httptest.NewRecorder()
	h.Trigger(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.True(t, trig.called)
}

func TestListHandler_ReturnsRuns(t *testing.T) {
	h, repo, _ := newTestHandler()
	repo.run = Run{ID: "run-1", Status: StatusCompleted, TargetCount: 3, FindingCount: 1}

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got, 1)
	require.Equal(t, "completed", got[0]["status"])
}

func TestGetHandler_NotFound_404(t *testing.T) {
	h, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/scans/ghost", nil)
	req.SetPathValue("id", "ghost")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestGetHandler_Found(t *testing.T) {
	h, repo, _ := newTestHandler()
	repo.run = Run{ID: "run-1", Status: StatusRunning}

	req := httptest.NewRequest(http.MethodGet, "/api/scans/run-1", nil)
	req.SetPathValue("id", "run-1")
	rec := httptest.NewRecorder()
	h.Get(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

// The scan detail page colours each finding by the band the server assigned,
// so the response must carry it rather than leave the UI to re-derive it.
func TestGetFindingsHandler_CarriesScoreBand(t *testing.T) {
	repo := &fakeRepo{run: Run{ID: "run-1", Status: StatusCompleted}}
	findings := &fakeFindings{listed: []finding.Finding{
		{ID: "f1", Severity: finding.SeverityMedium, Score: 45, ScoreBand: "monitor", Title: "t", CheckID: "c"},
	}}
	h := NewHandler(NewService(repo, nil, nil, nil, findings), &fakeTriggerer{})

	req := httptest.NewRequest(http.MethodGet, "/api/scans/run-1/findings", nil)
	req.SetPathValue("id", "run-1")
	rec := httptest.NewRecorder()
	h.GetFindings(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var got struct {
		Findings []map[string]any `json:"findings"`
		Count    int              `json:"count"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, 1, got.Count)
	require.Equal(t, "monitor", got.Findings[0]["score_band"])
}
