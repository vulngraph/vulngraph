package alertctx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeContexter struct {
	res Result
	err error
	got []string
}

func (f *fakeContexter) Context(_ context.Context, ids []string) (Result, error) {
	f.got = ids
	return f.res, f.err
}

func post(h *Handler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.Context(rec, httptest.NewRequest(http.MethodPost, "/api/context/alert", strings.NewReader(body)))
	return rec
}

func TestHandler_OK_SnakeCaseAndNeverNull(t *testing.T) {
	fc := &fakeContexter{res: Result{
		Summary:     "1 of 1 identifiers resolved to 1 assets.",
		Identifiers: []Resolution{{Input: "i-1", Status: StatusResolved, Matches: []Match{{AssetID: "i-1", MatchType: MatchInstanceID, Confidence: ConfExact}}}},
		Assets:      []AssetContext{{Asset: AssetSummary{ID: "i-1", RiskScore: 7, RiskScoreSource: RiskSourceLadybug}}},
	}}
	rec := post(NewHandler(fc), `{"identifiers":["i-1"]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{"i-1"}, fc.got)

	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	assert.Equal(t, []any{}, out["omitted_assets"])
	a := out["assets"].([]any)[0].(map[string]any)
	assert.Contains(t, a, "blast_radius")
	assert.NotContains(t, a, "privileges", "absent for non-identities")
	// A section that was never measured serialises known=false, not as a clean zero.
	assert.Equal(t, false, a["exposure"].(map[string]any)["known"])
	assert.Equal(t, false, a["findings"].(map[string]any)["known"])
	assert.Equal(t, map[string]any{}, a["findings"].(map[string]any)["by_severity"])
	assert.Equal(t, []any{}, a["findings"].(map[string]any)["must_fix"])
	assert.Equal(t, float64(7), a["asset"].(map[string]any)["risk_score"])
	assert.Equal(t, "ladybug", a["asset"].(map[string]any)["risk_score_source"])
}

func TestHandler_PrivilegesAndUnavailableReason(t *testing.T) {
	fc := &fakeContexter{res: Result{Assets: []AssetContext{{
		Privileges: &Privileges{Availability: Availability{Reason: failFindings}},
		Exposure:   Exposure{Availability: Availability{Reason: failExposure}},
	}}}}
	rec := post(NewHandler(fc), `{"identifiers":["x"]}`)
	require.Equal(t, http.StatusOK, rec.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	a := out["assets"].([]any)[0].(map[string]any)
	assert.Equal(t, failFindings, a["privileges"].(map[string]any)["unavailable_reason"])
	assert.Equal(t, failExposure, a["exposure"].(map[string]any)["unavailable_reason"])
}

func TestHandler_Errors(t *testing.T) {
	tests := []struct {
		name string
		body string
		err  error
		want int
	}{
		{"bad json", `not json`, nil, http.StatusBadRequest},
		{"no identifiers", `{"identifiers":[]}`, ErrNoIdentifiers, http.StatusBadRequest},
		{"too many", `{"identifiers":["a"]}`, ErrTooManyIDs, http.StatusBadRequest},
		{"internal", `{"identifiers":["a"]}`, errors.New("boom secret"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := post(NewHandler(&fakeContexter{err: tt.err}), tt.body)
			assert.Equal(t, tt.want, rec.Code)
			assert.NotContains(t, rec.Body.String(), "secret")
		})
	}
}
