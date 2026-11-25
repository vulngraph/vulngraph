package finding

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// decodePage unmarshals the findings list envelope into raw items.
func decodePage(t *testing.T, body []byte) (items []map[string]any, nextCursor string) {
	t.Helper()
	var page struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"next_cursor"`
	}
	require.NoError(t, json.Unmarshal(body, &page))
	return page.Items, page.NextCursor
}

func newTestHandler(stored []Finding) (*Handler, *fakeRepo) {
	repo := &fakeRepo{stored: stored}
	return NewHandler(NewService(repo), nil), repo
}

// fakeSuppressions reports fixed active/expired sets (and optionally an error, to
// prove a lookup failure never fails the findings list).
type fakeSuppressions struct {
	set     map[string]struct{}
	expired map[string]struct{}
	err     error
}

func (f fakeSuppressions) SuppressionStates(context.Context) (active, expired map[string]struct{}, err error) {
	return f.set, f.expired, f.err
}

func TestListHandler_ReturnsFindings(t *testing.T) {
	h, _ := newTestHandler([]Finding{
		{ID: "1", Source: "cspm", Type: "exposure", Severity: SeverityMedium, Title: "x", DetectedAt: time.Now()},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	got, _ := decodePage(t, rec.Body.Bytes())
	require.Len(t, got, 1)
	require.Equal(t, "medium", got[0]["severity"])
}

func TestListHandler_FlagsSuppressed(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{
		{ID: "1", Source: "cspm", Severity: SeverityHigh, Title: "a", DetectedAt: time.Now()},
		{ID: "2", Source: "cspm", Severity: SeverityHigh, Title: "b", DetectedAt: time.Now()},
	}}
	h := NewHandler(NewService(repo), fakeSuppressions{
		set:     map[string]struct{}{"2": {}},
		expired: map[string]struct{}{"1": {}},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	got, _ := decodePage(t, rec.Body.Bytes())
	require.Len(t, got, 2)
	byID := map[string]map[string]any{got[0]["id"].(string): got[0], got[1]["id"].(string): got[1]}
	require.Nil(t, byID["1"]["is_suppressed"], "a finding whose exception expired is not suppressed (omitempty)")
	require.Equal(t, true, byID["1"]["exception_expired"], "an expired exception is surfaced on the finding")
	require.Equal(t, true, byID["2"]["is_suppressed"])
	require.Nil(t, byID["2"]["exception_expired"])
	require.Equal(t, true, byID["1"]["suppression_known"])
	require.Equal(t, true, byID["2"]["suppression_known"])
}

func TestListHandler_SuppressionLookupFailure_StillReturnsFindings(t *testing.T) {
	repo := &fakeRepo{stored: []Finding{{ID: "1", Source: "cspm", Severity: SeverityHigh, Title: "a", DetectedAt: time.Now()}}}
	h := NewHandler(NewService(repo), fakeSuppressions{err: context.DeadlineExceeded})

	req := httptest.NewRequest(http.MethodGet, "/api/findings", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "a suppression-store hiccup must not fail the findings list")
	got, _ := decodePage(t, rec.Body.Bytes())
	require.Len(t, got, 1)
	require.Equal(t, false, got[0]["suppression_known"],
		"an unread suppression standing is unknown, not 'active'")
}

func TestListHandler_PassesFilters(t *testing.T) {
	h, repo := newTestHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/findings?source=cspm&severity=high&limit=10&cursor=abc", nil)
	h.List(httptest.NewRecorder(), req)

	require.Equal(t, "cspm", repo.filter.Source)
	require.Equal(t, SeverityHigh, repo.filter.Severity)
	require.Equal(t, 10, repo.filter.Limit)
	require.Equal(t, "abc", repo.filter.Cursor)
}

// A full page (len == DefaultLimit) carries a next_cursor to seek past it; a
// short page does not.
func TestListHandler_NextCursorOnFullPage(t *testing.T) {
	full := make([]Finding, DefaultLimit)
	for i := range full {
		full[i] = Finding{ID: strconv.Itoa(i), Source: "cspm", Severity: SeverityHigh, Score: uint8(i % 100), DetectedAt: time.Now()}
	}
	h, _ := newTestHandler(full)
	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	items, next := decodePage(t, rec.Body.Bytes())
	require.Len(t, items, DefaultLimit)
	require.NotEmpty(t, next, "a full page yields a cursor")

	h2, _ := newTestHandler(full[:3])
	rec2 := httptest.NewRecorder()
	h2.List(rec2, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	_, next2 := decodePage(t, rec2.Body.Bytes())
	require.Empty(t, next2, "a short page has no cursor")
}

func TestResolveHandler_ResolvesAndStashesReason(t *testing.T) {
	h, repo := newTestHandler([]Finding{
		{ID: "f1", Source: "aws_guardduty", Severity: SeverityHigh, Title: "x", DetectedAt: time.Now()},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/findings/f1/resolve",
		strings.NewReader(`{"reason":"verified via live check: instance terminated"}`))
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Resolve(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		ID         string    `json:"id"`
		ResolvedAt time.Time `json:"resolved_at"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Equal(t, "f1", resp.ID)
	require.False(t, resp.ResolvedAt.IsZero())

	require.Len(t, repo.stored, 2, "original row plus the resolved rewrite")
	resolved := repo.stored[len(repo.stored)-1]
	require.True(t, resolved.Resolved())
	require.Equal(t, "verified via live check: instance terminated", resolved.Metadata["resolved_reason"])
}

func TestResolveHandler_MissingReason_400(t *testing.T) {
	h, _ := newTestHandler([]Finding{{ID: "f1", DetectedAt: time.Now()}})

	req := httptest.NewRequest(http.MethodPost, "/api/findings/f1/resolve", strings.NewReader(`{}`))
	req.SetPathValue("id", "f1")
	rec := httptest.NewRecorder()
	h.Resolve(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestResolveHandler_UnknownID_404(t *testing.T) {
	h, _ := newTestHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/findings/ghost/resolve", strings.NewReader(`{"reason":"x"}`))
	req.SetPathValue("id", "ghost")
	rec := httptest.NewRecorder()
	h.Resolve(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestListHandler_BadLimit_400(t *testing.T) {
	h, _ := newTestHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/findings?limit=-5", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/findings?limit=abc", nil)
	rec = httptest.NewRecorder()
	h.List(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
}
