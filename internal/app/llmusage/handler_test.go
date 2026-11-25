package llmusage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHandlerSummary(t *testing.T) {
	repo := &fakeRepo{lines: []Line{
		{Purpose: PurposeChat, Model: "m", Interactive: true, Calls: 3, InputTokens: 10, CostMicroUSD: 1_500_000},
		{Purpose: PurposeReason, Model: "m", Calls: 2, UnreportedCalls: 1, CostMicroUSD: 2_500_000},
	}}
	h := NewHandler(newSvc(repo, Budget{MonthlyMicroUSD: 50_000_000}))
	rec := httptest.NewRecorder()
	h.Summary(rec, httptest.NewRequest(http.MethodGet, "/api/llm/usage?month=2026-09", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var got SummaryResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, "2026-09", got.Month)
	require.InDelta(t, 50.0, got.MonthlyBudgetUSD, 1e-9)
	require.InDelta(t, 0.0, got.InteractiveBudgetUSD, 1e-9)
	require.InDelta(t, 4.0, got.SpentUSD, 1e-9)
	require.InDelta(t, 1.5, got.InteractiveSpentUSD, 1e-9)
	require.InDelta(t, 2.5, got.BackgroundSpentUSD, 1e-9)
	require.Len(t, got.Lines, 2)
	require.Equal(t, "chat", got.Lines[0].Purpose)
	require.EqualValues(t, 1, got.Lines[1].UnreportedCalls)
	require.NotNil(t, got.DefaultPriceUsedForModels)
}

func TestHandlerSummary_BadMonthIs400(t *testing.T) {
	h := NewHandler(newSvc(&fakeRepo{}, Budget{}))
	rec := httptest.NewRecorder()
	h.Summary(rec, httptest.NewRequest(http.MethodGet, "/api/llm/usage?month=13-2026", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
}
