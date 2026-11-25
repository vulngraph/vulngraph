package asset

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// Every asset response carries its classified environment, and an unknown one
// is spelled out rather than omitted.
func TestAssetResponse_Environment(t *testing.T) {
	for _, tc := range []struct {
		name   string
		a      Asset
		env    string
		source string
	}{
		{"tagged", Asset{ID: "a", Tags: map[string]string{"env": "production"}}, "prod", "tag:env"},
		{"gcp project", Asset{ID: "a", AccountID: "acme-staging"}, "staging", "account_id"},
		{"untagged", Asset{ID: "a"}, "unknown", ""},
		{"conflict", Asset{ID: "a", Tags: map[string]string{"env": "prod", "stage": "dev"}}, "unknown", "conflict:tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(toAssetResponse(tc.a, AssetRisk{}))
			require.NoError(t, err)
			var got map[string]any
			require.NoError(t, json.Unmarshal(b, &got))
			require.Equal(t, tc.env, got["environment"])
			require.Contains(t, got, "environment_source", "never omitted")
			require.Equal(t, tc.source, got["environment_source"])
		})
	}
}

// The single-asset read serves the resolved owner; a failed resolution omits it
// rather than reporting the asset as unowned.
func TestGet_Owner(t *testing.T) {
	fr := newFakeRepo()
	fr.assets["tagged"] = Asset{ID: "tagged", Tags: map[string]string{"team": "Payments"}}
	fr.assets["bare"] = Asset{ID: "bare"}

	get := func(h *Handler, id string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/assets/"+id, nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		h.Get(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		var got map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		return got
	}

	owner := get(NewHandler(NewService(fr), nil), "tagged")["owner"].(map[string]any)
	require.Equal(t, "payments", owner["team"])
	require.Equal(t, "tag", owner["source"])

	owner = get(NewHandler(NewService(fr), nil), "bare")["owner"].(map[string]any)
	require.Equal(t, "none", owner["source"])

	failing := NewService(edgeErrRepo{fakeRepo: fr, edgesErr: errors.New("ch down")})
	require.NotContains(t, get(NewHandler(failing, nil), "bare"), "owner")
}
