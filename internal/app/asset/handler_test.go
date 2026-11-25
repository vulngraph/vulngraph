package asset

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestListRejectsFiltersWithSortRisk pins the fix for a silently-dropped filter.
//
// sort=risk short-circuits into listByRisk, which ranks the whole estate from the
// finding store — it never builds a Filter, so every inventory parameter sent
// with it was ignored. min_score was the dangerous one: `?sort=risk&min_score=90`
// answered 200 with the unfiltered top-100, which reads as "these are the assets
// scoring 90+". On a security tool a filter that silently does nothing is worse
// than an error, because the caller trusts the narrower claim.
func TestListRejectsFiltersWithSortRisk(t *testing.T) {
	// svc/risk are nil: the rejection must happen before either is touched.
	h := NewHandler(nil, nil)

	for _, q := range []string{
		"sort=risk&min_score=90",
		"sort=risk&provider=aws",
		"sort=risk&type=k8s_pod",
		"sort=risk&q=prod",
		"sort=risk&exposed=true",
		"sort=risk&cursor=abc",
	} {
		w := httptest.NewRecorder()
		h.List(w, httptest.NewRequest(http.MethodGet, "/api/assets?"+q, nil))
		require.Equal(t, http.StatusBadRequest, w.Code, "?%s must be rejected, not silently unfiltered", q)

		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Contains(t, w.Body.String(), "sort=risk",
			"?%s: the error must say which combination is unsupported", q)
	}
}

// A bare sort=risk, and the falsey forms of the boolean/numeric filters, are not
// filters at all — they must still reach the risk view. This is what the UI
// sends (frontend/src/routes/Assets.tsx builds either the risk filter or the
// inventory filters, never both), so the rejection above must not break it.
func TestListAcceptsBareSortRisk(t *testing.T) {
	h := NewHandler(nil, nil) // risk == nil: listByRisk answers an empty page
	for _, q := range []string{"sort=risk", "sort=risk&exposed=false", "sort=risk&min_score=0"} {
		w := httptest.NewRecorder()
		h.List(w, httptest.NewRequest(http.MethodGet, "/api/assets?"+q, nil))
		require.Equal(t, http.StatusOK, w.Code, "?%s is the risk view with no filters and must be served", q)
	}
}

func TestUnsupportedRiskParams(t *testing.T) {
	// Stable order, so the error message is deterministic.
	got := unsupportedRiskParams(url.Values{
		"sort":      []string{"risk"},
		"min_score": []string{"90"},
		"provider":  []string{"aws"},
	})
	require.Equal(t, []string{"provider", "min_score"}, got)

	require.Empty(t, unsupportedRiskParams(url.Values{"sort": []string{"risk"}}))
	require.Empty(t, unsupportedRiskParams(url.Values{
		"sort": []string{"risk"}, "exposed": []string{"false"}, "min_score": []string{"0"}, "q": []string{""},
	}))

	// Every filter the inventory path reads must be listed, or the next one added
	// there will be silently dropped here again.
	for _, p := range []string{"provider", "type", "region", "account_id", "q", "exposed", "min_score", "cursor"} {
		require.Contains(t, riskIgnoredParams, p)
	}
}
