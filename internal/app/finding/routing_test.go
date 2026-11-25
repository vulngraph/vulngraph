package finding

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRoutingHaving(t *testing.T) {
	tests := []struct {
		name  string
		f     Filter
		want  string
		wargs []any
	}{
		{"no routing filter", Filter{}, "", nil},
		{"team", Filter{Owner: "payments"}, " HAVING argMax(owner_team, enriched_at) = ?", []any{"payments"}},
		{"unowned reads the source, not an empty team", Filter{Owner: OwnerUnowned},
			" HAVING argMax(owner_source, enriched_at) = 'none'", nil},
		{"environment", Filter{Environment: "prod"}, " HAVING argMax(environment, enriched_at) = ?", []any{"prod"}},
		{"both", Filter{Owner: "x", Environment: "dev"},
			" HAVING argMax(owner_team, enriched_at) = ? AND argMax(environment, enriched_at) = ?", []any{"x", "dev"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, args := routingHaving(tt.f)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wargs, args)
		})
	}
}

// The routing filters prune inside the finding_enrichment subquery and flip the
// join to INNER; they must never add columns to the outer per-id aggregation
// (CLAUDE.md: LIMIT bounds a result set, not an aggregation).
func TestListKeysQuery_RoutingFiltersPruneInsideEnrichment(t *testing.T) {
	q, args, err := listKeysQuery(Filter{Owner: "payments", Environment: "prod", Source: "cspm", CheckID: "c1"})
	require.NoError(t, err)

	require.Contains(t, q, "INNER JOIN (")
	require.NotContains(t, q, "LEFT JOIN (")
	feStart := strings.Index(q, "FROM finding_enrichment")
	feEnd := strings.Index(q, ") fe ON")
	require.Contains(t, q[feStart:feEnd], "HAVING argMax(owner_team, enriched_at) = ?")
	require.NotContains(t, q[feEnd:], "owner_team", "owner must not reach the outer aggregation")
	require.NotContains(t, q[feEnd:], "environment", "environment must not reach the outer aggregation")

	// Bind order follows text order: fe scope (check_id), fe HAVING, outer WHERE, LIMIT.
	require.Equal(t, []any{"c1", "payments", "prod", "cspm", "c1", DefaultLimit}, args)

	plain, _, err := listKeysQuery(Filter{})
	require.NoError(t, err)
	require.Contains(t, plain, "LEFT JOIN (", "no routing filter keeps never-enriched findings listable")
}

func TestListHandler_RoutingFilters(t *testing.T) {
	h, repo := newTestHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/findings?owner=@acme/Payments&environment=prod", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "payments", repo.filter.Owner, "owner is normalised like stored owners")
	require.Equal(t, "prod", repo.filter.Environment)

	rec = httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/findings?environment=production", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestListHandler_ServesRoutingContext(t *testing.T) {
	h, _ := newTestHandler([]Finding{
		{ID: "owned", Title: "a", DetectedAt: time.Now(), OwnerTeam: "payments", OwnerSource: "tag",
			OwnerConfidence: "high", Environment: "prod"},
		{ID: "pending", Title: "b", DetectedAt: time.Now()},
	})
	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/findings", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	items, _ := decodePage(t, rec.Body.Bytes())
	require.Len(t, items, 2)

	require.Equal(t, "payments", items[0]["owner_team"])
	require.Equal(t, "tag", items[0]["owner_source"])
	require.Equal(t, "prod", items[0]["environment"])

	// Unstamped is spelled out as "", never an absent key.
	require.Contains(t, items[1], "owner_source")
	require.Equal(t, "", items[1]["owner_source"])
	require.Contains(t, items[1], "environment")
}

func TestFindingUnowned(t *testing.T) {
	require.True(t, Finding{}.Unowned(), "unresolved routes as unowned so its alert still reaches someone")
	require.True(t, Finding{OwnerSource: "none"}.Unowned())
	require.False(t, Finding{OwnerSource: "tag", OwnerTeam: "x"}.Unowned())
}

func TestSummaryAdd_KeepsUnresolvedAndUnownedApart(t *testing.T) {
	s := newSummary()
	s.add(SeverityHigh, "page", "payments", "prod", 2)
	s.add(SeverityLow, "", OwnerUnowned, "unknown", 3)
	s.add(SeverityLow, "", "", "", 4)
	require.Equal(t, 9, s.Total)
	require.Equal(t, map[string]int{"payments": 2, OwnerUnowned: 3, "": 4}, s.ByOwner)
	require.Equal(t, map[string]int{"prod": 2, "unknown": 3, "": 4}, s.ByEnvironment)
	require.Equal(t, map[string]int{"page": 2}, s.ByBand)
}
