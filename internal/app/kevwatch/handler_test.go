package kevwatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestHandlerAdditions(t *testing.T) {
	repo := newMemRepo()
	detected := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	repo.events["CVE-2026-1"] = Addition{CVEID: "CVE-2026-1", Name: "x", DateAdded: today, OpenFindings: 3, DetectedAt: detected}
	repo.events["CVE-2026-2"] = Addition{CVEID: "CVE-2026-2", DetectedAt: detected}

	rec := httptest.NewRecorder()
	NewHandler(NewService(repo)).Additions(rec, httptest.NewRequest(http.MethodGet, "/api/kev/additions", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var got struct {
		Additions []map[string]any `json:"additions"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Len(t, got.Additions, 2)
	byID := map[string]map[string]any{}
	for _, a := range got.Additions {
		byID[a["cve_id"].(string)] = a
	}
	require.Equal(t, "2026-10-08T00:00:00Z", byID["CVE-2026-1"]["date_added"])
	require.EqualValues(t, 3, byID["CVE-2026-1"]["open_findings_at_detection"])
	require.Nil(t, byID["CVE-2026-2"]["date_added"], "an unknown dateAdded is null, not a zero date")
}

func TestHandlerAdditions_BadLimitIs400(t *testing.T) {
	for _, q := range []string{"limit=0", "limit=abc", "limit=201"} {
		rec := httptest.NewRecorder()
		NewHandler(NewService(newMemRepo())).Additions(rec, httptest.NewRequest(http.MethodGet, "/api/kev/additions?"+q, nil))
		require.Equal(t, http.StatusBadRequest, rec.Code, q)
	}
}
