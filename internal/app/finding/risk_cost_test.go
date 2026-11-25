package finding

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// costRepo is a fakeRepo that can also answer the cost-bearing risk join.
type costRepo struct {
	*fakeRepo
	res       CostAtRisk
	gotMin    int
	gotLimit  int
	returnErr error
}

func (c *costRepo) CostAtRisk(_ context.Context, minScore, limit int) (CostAtRisk, error) {
	c.gotMin, c.gotLimit = minScore, limit
	return c.res, c.returnErr
}

// The regression: the Cost page's headline was the ROW COUNT of a LIMIT-100
// query, so an estate with thousands of at-risk resources read "100" forever.
// total must come from the count, independently of how many rows are returned.
func TestCostAtRisk_TotalIsNotThePageSize(t *testing.T) {
	repo := &costRepo{fakeRepo: &fakeRepo{}, res: CostAtRisk{
		MinScore:   60,
		Total:      8727,
		ByType:     map[string]int{"ec2_instance": 711, "cloud_function": 6056},
		ByProvider: map[string]int{"aws": 800, "gcp": 7927},
		Resources: []CostAtRiskResource{
			{ResourceID: "i-1", Name: "web-1", Type: "ec2_instance", Provider: "aws", MaxScore: 100, Count: 4},
			{ResourceID: "i-2", Name: "web-2", Type: "ec2_instance", Provider: "aws", MaxScore: 90, Count: 2},
		},
	}}
	h := NewHandler(NewService(repo), nil)

	rec := httptest.NewRecorder()
	h.CostAtRisk(rec, httptest.NewRequest(http.MethodGet, "/api/findings/cost-at-risk", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var got costAtRiskResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, 8727, got.Total, "total must be the server-side count")
	require.Equal(t, 2, got.Returned, "returned is the page size, distinct from total")
	require.Len(t, got.Items, 2)
	require.NotEqual(t, got.Total, got.Returned, "a page size must never stand in for the population")
	// The composition is published so the number is auditable.
	require.Equal(t, 6056, got.ByType["cloud_function"])
	require.Equal(t, 7927, got.ByProvider["gcp"])
	require.Contains(t, got.CostBearingTypes, "ec2_instance")
	// Defaults: score >= 60, bounded page.
	require.Equal(t, 60, repo.gotMin)
	require.Equal(t, costAtRiskDefaultLimit, repo.gotLimit)
}

func TestCostAtRisk_ParamValidation(t *testing.T) {
	repo := &costRepo{fakeRepo: &fakeRepo{}}
	h := NewHandler(NewService(repo), nil)

	for _, q := range []string{"?min_score=101", "?min_score=-1", "?min_score=abc", "?limit=1001", "?limit=-5"} {
		rec := httptest.NewRecorder()
		h.CostAtRisk(rec, httptest.NewRequest(http.MethodGet, "/api/findings/cost-at-risk"+q, nil))
		require.Equal(t, http.StatusBadRequest, rec.Code, q)
	}

	rec := httptest.NewRecorder()
	h.CostAtRisk(rec, httptest.NewRequest(http.MethodGet, "/api/findings/cost-at-risk?min_score=80&limit=5", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 80, repo.gotMin)
	require.Equal(t, 5, repo.gotLimit)
}

// A repo that cannot answer the join must ERROR, never return an empty result:
// "0 cost-bearing resources at risk" is the false all-clear this path removes.
func TestCostAtRisk_UnsupportedRepoErrors(t *testing.T) {
	svc := NewService(&fakeRepo{})
	_, err := svc.CostAtRisk(context.Background(), 60, 10)
	require.ErrorIs(t, err, ErrCostAtRiskUnsupported)

	rec := httptest.NewRecorder()
	NewHandler(svc, nil).CostAtRisk(rec, httptest.NewRequest(http.MethodGet, "/api/findings/cost-at-risk", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

// The category error that motivated this work: the panel headed "security risk
// and remediation cost compound here" was listing Go modules and service
// accounts. Those types must never be counted as cost-bearing.
func TestCostBearingAssetTypes_ExcludesNonBilledTypes(t *testing.T) {
	types := map[string]bool{}
	for _, t := range CostBearingAssetTypes() {
		types[t] = true
	}
	for _, banned := range []string{
		"package", "container_image", "iam_role", "iam_user", "gcp_service_account",
		"declared_cloud_identity", "declared_k8s_workload", "declared_ci_access",
		"security_group", "subnet", "vpc", "dns_record", "dns_zone",
		"k8s_pod", "container", "github_repo",
	} {
		require.False(t, types[banned], "%s carries no bill and must not be counted as cost-bearing", banned)
	}
	for _, want := range []string{"ec2_instance", "ebs_volume", "s3_bucket", "rds_instance", "load_balancer"} {
		require.True(t, types[want], "%s is billed and must be counted", want)
	}
	// Mutating the returned slice must not corrupt the package-level list.
	got := CostBearingAssetTypes()
	got[0] = "mutated"
	require.NotEqual(t, "mutated", CostBearingAssetTypes()[0])
}

// The two cost-at-risk queries share one FROM clause with TWO %s type-list
// occurrences (the finding_enrichment scoping subquery was added ahead of
// the assets WHERE) and positional binds. Type args come first
// (the enrichment scope), then min_score, then the type list again (the
// assets WHERE), then limit — get that order wrong and ClickHouse silently
// compares a score against a type string. This pins the shape.
func TestCostAtRiskQueries_PlaceholderOrder(t *testing.T) {
	placeholders, args := dbutil.CHIn(costBearingAssetTypes)
	require.Len(t, args, len(costBearingAssetTypes))
	require.Equal(t, len(costBearingAssetTypes), strings.Count(placeholders, "?"))

	comp := formatQuery(costAtRiskComposition, placeholders)
	page := formatQuery(costAtRiskPage, placeholders)

	// Composition: type list twice + min_score. Page: same + limit.
	require.Equal(t, 2*len(costBearingAssetTypes)+1, strings.Count(comp, "?"))
	require.Equal(t, 2*len(costBearingAssetTypes)+2, strings.Count(page, "?"))

	// ClickHouse binds positionally by TEXT order: the first type list (the
	// finding_enrichment scoping subquery) is textually first, then
	// min_score, then the second type list (the assets WHERE) — so
	// CostAtRisk must pass [types..., minScore, types...]. Getting this
	// wrong binds a type string to a score comparison and quietly returns
	// nothing, which on this page would read as "no billed resource is at
	// risk".
	firstTypes := strings.Index(comp, placeholders)
	haveMaxScore := strings.Index(comp, "max_score >= ?")
	secondTypes := strings.LastIndex(comp, placeholders)
	require.Less(t, firstTypes, haveMaxScore, "the enrichment scope's type list must precede max_score >= ?")
	require.Less(t, haveMaxScore, secondTypes, "max_score >= ? must precede the assets WHERE's type list")
	require.Less(t, strings.Index(page, placeholders), strings.Index(page, "max_score >= ?"))
	// And LIMIT is last in the page query.
	require.Greater(t, strings.LastIndex(page, "LIMIT ?"), strings.Index(page, "max_score >= ?"))

	// And the Go side binds them in that same order.
	compArgs := costAtRiskArgs(args, 60)
	require.Equal(t, costBearingAssetTypes[0], compArgs[0], "the first type list must bind first")
	require.Equal(t, 60, compArgs[len(costBearingAssetTypes)], "min_score binds after the first type list")
	require.Equal(t, costBearingAssetTypes[0], compArgs[len(costBearingAssetTypes)+1], "the second type list binds after min_score")
	require.Len(t, compArgs, 2*len(costBearingAssetTypes)+1)
	pageArgs := costAtRiskArgs(args, 60, 200)
	require.Equal(t, costBearingAssetTypes[0], pageArgs[0])
	require.Equal(t, 200, pageArgs[len(pageArgs)-1], "limit binds last")
	require.Len(t, pageArgs, 2*len(costBearingAssetTypes)+2)

	// The join is INNER: a finding whose resource has no asset row is not
	// evidence of a bill, and an outer join would resurrect the untyped rows.
	require.Contains(t, comp, "INNER JOIN")
	// No FINAL anywhere (CLAUDE.md house rule: RMT versions collapse via argMax).
	require.NotContains(t, comp, "FINAL")
	require.NotContains(t, page, "FINAL")
	// Resolved findings are excluded, so a fixed issue cannot inflate the count.
	require.Contains(t, comp, "argMax(resolved_at, synced_at) < toDateTime('2000-01-01 00:00:00')")

	// Both raw `assets` reads in costAtRiskFrom must apply the same
	// liveness/inventory gate every other UI-facing assets reader applies —
	// pinned by content, not just "some condition exists", so a future
	// refactor of costAtRiskFrom can't silently drop it. require.Contains, not Count:
	// the assets WHERE and the fe scoping subquery's nested assets read both
	// embed InventoryReadCond in full, so it appears twice in the query text.
	require.Contains(t, comp, asset.InventoryReadCond)
	require.Equal(t, 2, strings.Count(comp, asset.InventoryReadCond), "InventoryReadCond must gate both raw assets reads")
}

// formatQuery mirrors the fmt.Sprintf the repo does (now with the SAME
// placeholder string substituted at BOTH %s sites), kept local so the test
// exercises the real constants rather than a copy of them.
func formatQuery(q, placeholders string) string {
	return strings.ReplaceAll(q, "%s", placeholders)
}
