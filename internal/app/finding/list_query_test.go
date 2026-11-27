package finding

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestListKeysQueryStaysNarrow is the signal for the two-phase List.
//
// The defect it exists to prevent is not "the query is ugly", it is that
// List's filters are post-aggregation HAVINGs, so ClickHouse builds argMax state
// for EVERY id in `findings` before any predicate prunes. With the full
// 27-column set that state carries the long String columns and can reach
// multiple GiB per page at large scale, enough to exceed ClickHouse's per-query
// memory limit (code 241) and fail the enrich sweep. LIMIT bounds the result,
// not the aggregation — so the only thing that bounds the aggregation is the
// column list, and this test is what keeps it bounded.
//
// Adding a wide column back to selectFindingKeysArgMax — the single easiest way
// to reintroduce the bug, because it is exactly what "just also return the
// title" looks like in review — fails here.
func TestListKeysQueryStaysNarrow(t *testing.T) {
	// The enrich sweep's own phase-1 page: the filter most exposed to the
	// per-query memory limit.
	q, _, err := listKeysQuery(Filter{Unenriched: true, Severity: SeverityMedium})
	require.NoError(t, err)

	for _, col := range listWideColumns {
		require.NotContainsf(t, q, "argMax("+col,
			"listKeysQuery aggregates %q. Every column here is argMax state held for all "+
				"finding ids before the HAVING can prune, and the long String columns "+
				"multiply the page's memory several times over. Filter/sort columns only — "+
				"ByIDs hydrates the rest for the ≤200 ids that survive.", col)
	}
	require.NotContains(t, q, selectFindingsArgMax,
		"the wide read form must not be the page-selection query; that is the bug")

	// Only `id` is projected: the key columns exist to be filtered and sorted on.
	require.True(t, strings.HasPrefix(q, "SELECT id FROM ("),
		"phase one must project only id, got: %s", q)
}

// TestListKeysQueryCarriesEveryFilterAndSortColumn is the other half: narrowing
// the column set is only safe while every column a filter or sort references is
// still aggregated. Dropping one would not fail loudly in Go — it would emit SQL
// referencing an alias that no longer exists and fail at ClickHouse, at runtime,
// for whichever filter combination happened to use it.
//
// score/safety_class/must_fix_class/enriched_at now come
// from the fe join rather than argMax(col, synced_at) on findings directly —
// severity/detected_at/resolved_at (not enrich:"output" fields) still do.
func TestListKeysQueryCarriesEveryFilterAndSortColumn(t *testing.T) {
	// Every filter field set at once, so every conditional branch of
	// listKeysQuery contributes its predicate.
	all := Filter{
		Severity: SeverityHigh, MinScore: 10, SafeOnly: true, MustFixOnly: true,
		Unenriched: true, IncludeResolved: false,
	}
	q, _, err := listKeysQuery(all)
	require.NoError(t, err)

	for _, col := range []string{"severity", "detected_at", "resolved_at"} {
		require.Containsf(t, q, "argMax(f."+col+", f.synced_at) AS "+col,
			"%q is referenced post-aggregation but not aggregated — the emitted SQL "+
				"would reference a missing alias and fail at ClickHouse, not here", col)
	}
	for _, col := range []string{"score", "safety_class", "must_fix_class"} {
		require.Containsf(t, q, "fe."+col+" AS "+col,
			"%q must be selected from the finding_enrichment join AND explicitly re-aliased — "+
				"unlike selectFindingsArgMax/selectFindingByID, this query's outer wrapper "+
				"(listKeysQuery's \"SELECT id FROM (...) ORDER BY\") can't resolve a bare "+
				"qualified fe.%s reference by name; against ClickHouse this fails with "+
				"'Unknown expression identifier' without the explicit AS", col, col)
	}
	require.Contains(t, q, "fe.enr_at AS enriched_at")
}

// TestListKeysQuerySortsOutsideTheAggregation pins the ORDER BY/LIMIT placement.
// Inside the aggregation the sort runs over one argMax state per id in the whole
// table; outside it, over only the rows the HAVING kept.
func TestListKeysQuerySortsOutsideTheAggregation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		f     Filter
		order string
	}{
		{"default", Filter{}, ") ORDER BY detected_at DESC, id DESC LIMIT ?"},
		{"by score", Filter{SortByScore: true}, ") ORDER BY score DESC, id DESC LIMIT ?"},
		{"stale first", Filter{StaleFirst: true}, ") ORDER BY enriched_at ASC, id ASC LIMIT ?"},
		{"oldest first", Filter{OldestFirst: true}, ") ORDER BY detected_at ASC, id ASC LIMIT ?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, _, err := listKeysQuery(tc.f)
			require.NoError(t, err)
			require.Contains(t, q, tc.order,
				"the sort must follow the closing paren of the aggregation subquery")
			require.NotContains(t, q, "GROUP BY id ORDER BY",
				"sorting inside the aggregation is the shape this split exists to remove")
		})
	}
}

// TestListKeysQuerySplitsFiltersAcrossWhereAndHaving pins the split the narrow
// column set depends on: identity-stable columns prune BEFORE the GROUP BY (the
// primary key and bloom indexes can be used), mutable ones must be filtered
// after or they match a stale ReplacingMergeTree version.
func TestListKeysQuerySplitsFiltersAcrossWhereAndHaving(t *testing.T) {
	q, args, err := listKeysQuery(Filter{
		Source: "aws", ResourceID: "arn:x", CheckID: "aws-1", Severity: SeverityHigh, MinScore: 1,
	})
	require.NoError(t, err)

	groupByIdx := strings.Index(q, " GROUP BY "+findingKeysGroupBy)
	require.Greater(t, groupByIdx, -1, "GROUP BY must be the full findingKeysGroupBy suffix")
	where := q[:groupByIdx]
	having := q[groupByIdx:]

	for _, c := range []string{"f.source = ?", "f.resource_id = ?", "f.check_id = ?"} {
		require.Containsf(t, where, c, "%q is baked into the deterministic id, so it must prune pre-aggregation", c)
	}
	require.Contains(t, having, "severity = ?",
		"severity is rewritten on re-observation (a genuine change is never blocked by "+
			"pinFirstDetectedAt's narrow KEV-oscillation guard), so a pre-aggregation "+
			"filter would match whichever historical version satisfied it")
	require.NotContains(t, where, "severity = ?")

	// ResourceID and CheckID are also fe's own scope (resource_id/check_id,
	// never source, per selectFindingKeysArgMax's
	// comment) — fe's bare scope args bind FIRST (textually first, inside
	// the fe subquery), then the outer f.-qualified WHERE args, then HAVING,
	// then the limit.
	require.Equal(t, []any{
		"arn:x", "aws-1", // fe scope: resource_id, check_id
		"aws", "arn:x", "aws-1", // outer WHERE: source, resource_id, check_id
		string(SeverityHigh), uint8(1), // HAVING: severity, score
		DefaultLimit,
	}, args)
}

// TestListKeysQueryCVEInPrunesPreAggregation is the KEV worker's own filter:
// the fix for refresh_kev's ClickHouse timeout, which listAll's unfiltered
// per-source scan (every open finding of the source, fully re-aggregated on
// every one of many pagination pages, because the GROUP BY runs before
// ORDER BY/LIMIT) can hit on a large catalog.
// check_id is baked into the deterministic finding id (like source/
// resource_id above), so — like them — CVEIn must prune in the outer WHERE,
// before GROUP BY, not in HAVING.
func TestListKeysQueryCVEInPrunesPreAggregation(t *testing.T) {
	q, args, err := listKeysQuery(Filter{Source: "supply_chain", CVEIn: []string{"cve-2021-44228", "CVE-2024-0001"}})
	require.NoError(t, err)

	groupByIdx := strings.Index(q, " GROUP BY f.id")
	require.Greater(t, groupByIdx, -1)
	where := q[:groupByIdx]

	require.Contains(t, where,
		"(upper(f.check_id) IN (?, ?) OR upper(f.tags['cve']) IN (?, ?))",
		"must prune pre-aggregation using the primary-key-eligible check_id column, "+
			"matching kev.findingCVE's own two-lineage check_id/tags['cve'] match")

	// Args upper-cased to match kev.Catalog's own upper-casing (case-insensitive
	// lookup) — and doubled, once for the check_id IN, once for the tags IN.
	require.Equal(t, []any{
		"supply_chain",                    // outer WHERE: source
		"CVE-2021-44228", "CVE-2024-0001", // check_id IN
		"CVE-2021-44228", "CVE-2024-0001", // tags['cve'] IN
		DefaultLimit,
	}, args)
}

// A caller that passes lowercase or mixed-case CVE ids (kev.Catalog itself
// never does — NewCatalog upper-cases on construction — but nothing enforces
// that at this layer) must still match, since the SQL upper()s both sides.
func TestListKeysQueryCVEInIsCaseInsensitive(t *testing.T) {
	q, args, err := listKeysQuery(Filter{CVEIn: []string{"cve-2021-44228"}})
	require.NoError(t, err)
	require.Contains(t, q, "upper(f.check_id)")
	require.Contains(t, q, "upper(f.tags['cve'])")
	require.Contains(t, args, "CVE-2021-44228")
	require.NotContains(t, args, "cve-2021-44228",
		"the lowercase input must be upper-cased before becoming a bind arg, not passed through raw")
}

func TestListKeysQueryCVEInEmptyAddsNoPredicate(t *testing.T) {
	q, _, err := listKeysQuery(Filter{Source: "supply_chain"})
	require.NoError(t, err)
	require.NotContains(t, q, "tags['cve']", "an empty/nil CVEIn must not add a predicate at all")
}

// Every filter field must explicitly decide whether page selection needs
// enrichment. Otherwise a new score/routing filter could silently lose its join.
func TestListKeysQueryJoinsOnlyWhenNeeded(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cases := map[string]struct {
		value any
		join  bool
	}{
		"Source": {"source", false}, "Severity": {SeverityHigh, false},
		"ResourceID": {"resource", false}, "CheckID": {"check", false},
		"MinScore": {uint8(1), true}, "SortByScore": {true, true},
		"SafeOnly": {true, true}, "MustFixOnly": {true, true}, "Unenriched": {true, true},
		"Owner": {"team", true}, "Environment": {"prod", true}, "StaleFirst": {true, true},
		"OldestFirst": {true, false}, "IncludeResolved": {true, false},
		"DetectedAfter": {now, false}, "DetectedBefore": {now, false},
		"Limit": {10, false}, "Cursor": {EncodeCursor(Finding{ID: "id", DetectedAt: now}, false), false},
		"CVEIn": {[]string{"CVE-2024-0001"}, false},
	}
	require.Len(t, cases, reflect.TypeFor[Filter]().NumField(), "classify every filter's enrichment dependency")
	q, _, err := listKeysQuery(Filter{})
	require.NoError(t, err)
	require.NotContains(t, q, "finding_enrichment", "an ordinary page must not aggregate unrelated enrichments")
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var f Filter
			reflect.ValueOf(&f).Elem().FieldByName(name).Set(reflect.ValueOf(tc.value))
			q, _, err := listKeysQuery(f)
			require.NoError(t, err)
			require.Equal(t, tc.join, strings.Contains(q, "finding_enrichment"), "query: %s", q)
		})
	}
}
