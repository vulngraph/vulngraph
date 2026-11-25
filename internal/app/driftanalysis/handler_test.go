package driftanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReader struct {
	listing Listing
	batch   Batch
	err     error
	gotList ListParams
}

func (f *fakeReader) List(_ context.Context, p ListParams) (Listing, error) {
	f.gotList = p
	return f.listing, f.err
}

func (f *fakeReader) Get(_ context.Context, _ string) (Batch, error) { return f.batch, f.err }

func analysedBatch() Batch {
	at := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	return Batch{
		ID: "b1", ConnectorID: "c1", WindowStart: at.Add(-time.Hour), WindowEnd: at,
		Status: StatusAnalysed, Truncated: true,
		Verdict: Verdict{
			Summary:           "new public bucket",
			Changes:           []ChangeItem{{Kind: KindNewExposure, AssetID: "a1", Note: "public"}},
			ExposureJudgement: ExposureIncreased,
			ScanRecommended:   true, ScanRecommendedKnown: true,
			Reason: "exposure grew", SuggestedProfileID: "p1", SuggestedTemplateTags: []string{"s3"},
			Confidence:         ConfidenceHigh,
			Evidence:           []EvidenceRef{{Source: EvidenceAsset, Ref: "a1", Fact: "public ip"}},
			AutoScanProfileIDs: []string{"p2"},
		},
	}
}

func serve(t *testing.T, h *Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/drift/analyses", h.List)
	mux.HandleFunc("GET /api/drift/analyses/{batch_id}", h.Get)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestHandler_List_Shape(t *testing.T) {
	h := NewHandler(&fakeReader{listing: Listing{Enabled: true, Analyses: []Batch{analysedBatch()}}})
	rec := serve(t, h, "/api/drift/analyses")
	require.Equal(t, http.StatusOK, rec.Code)

	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, true, got["enabled"])
	a := got["analyses"].([]any)[0].(map[string]any)
	assert.Equal(t, "b1", a["batch_id"])
	assert.Equal(t, "recommended", a["scan_recommendation"])
	assert.Equal(t, "llm", a["source"])
	assert.Equal(t, true, a["advisory"])
	assert.Equal(t, true, a["truncated"])
	assert.Equal(t, "p1", a["suggested_profile_id"])
	assert.Equal(t, []any{"p2"}, a["auto_scan_profile_ids"])
	assert.Equal(t, map[string]any{"kind": "new_exposure", "asset_id": "a1", "note": "public"}, a["changes"].([]any)[0])
	assert.Equal(t, map[string]any{"source": "asset", "ref": "a1", "fact": "public ip"}, a["evidence"].([]any)[0])
	assert.NotContains(t, a, "Verdict")
}

func TestHandler_List_DisabledIsNotAVerdict(t *testing.T) {
	h := NewHandler(&fakeReader{listing: Listing{Enabled: false}})
	rec := serve(t, h, "/api/drift/analyses")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"enabled":false,"analyses":[]}`, rec.Body.String())
}

func TestToResponse_UnknownIsNeverNoScanNeeded(t *testing.T) {
	for name, b := range map[string]Batch{
		"unknown batch": {ID: "b", Status: StatusUnknown, UnknownReason: ReasonBudget},
		"pending batch": {ID: "b", Status: StatusPending},
		"analysed but flag unknown": {ID: "b", Status: StatusAnalysed,
			Verdict: Verdict{ScanRecommended: false, ScanRecommendedKnown: false}},
	} {
		t.Run(name, func(t *testing.T) {
			r := ToResponse(b)
			assert.Equal(t, RecommendationUnknown, r.ScanRecommendation)
			assert.NotNil(t, r.Changes)
			assert.NotNil(t, r.Evidence)
			assert.NotNil(t, r.SuggestedTemplateTags)
			assert.NotNil(t, r.AutoScanProfileIDs)
		})
	}
	known := Batch{Status: StatusAnalysed, Verdict: Verdict{ScanRecommendedKnown: true}}
	assert.Equal(t, RecommendationNotNeeded, ToResponse(known).ScanRecommendation)
}

func TestHandler_List_Params(t *testing.T) {
	f := &fakeReader{}
	h := NewHandler(f)
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }

	require.Equal(t, http.StatusOK, serve(t, h, "/api/drift/analyses?since=24h&limit=10").Code)
	assert.Equal(t, now.Add(-24*time.Hour), f.gotList.Since)
	assert.Equal(t, 10, f.gotList.Limit)
}

func TestHandler_List_BadParams(t *testing.T) {
	for _, q := range []string{
		"since=7d", "since=-1h", "since=0s", "since=9999h", "since=",
		"limit=0", "limit=201", "limit=abc", "limit=-3",
	} {
		t.Run(q, func(t *testing.T) {
			f := &fakeReader{}
			rec := serve(t, NewHandler(f), "/api/drift/analyses?"+q)
			if q == "since=" {
				require.Equal(t, http.StatusOK, rec.Code, "an empty since means the default")
				return
			}
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.True(t, f.gotList == ListParams{}, "the service must not run on bad input")
		})
	}
}

func TestHandler_Get(t *testing.T) {
	rec := serve(t, NewHandler(&fakeReader{batch: analysedBatch()}), "/api/drift/analyses/b1")
	require.Equal(t, http.StatusOK, rec.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "b1", got["batch_id"])
	assert.Equal(t, true, got["advisory"])
}

func TestHandler_Get_NotFound(t *testing.T) {
	rec := serve(t, NewHandler(&fakeReader{err: ErrNotFound}), "/api/drift/analyses/nope")
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandler_ServiceErrorIs500(t *testing.T) {
	h := NewHandler(&fakeReader{err: errors.New("db down")})
	assert.Equal(t, http.StatusInternalServerError, serve(t, h, "/api/drift/analyses").Code)
	assert.Equal(t, http.StatusInternalServerError, serve(t, h, "/api/drift/analyses/b1").Code)
}
