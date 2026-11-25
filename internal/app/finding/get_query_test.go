package finding

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSelectFindingByID_JoinsFindingEnrichment pins the flip of
// finding.Get to finding_enrichment, by content rather than just "some join
// exists" — a future refactor of selectFindingByID that silently reverts to
// the legacy argMax(score, synced_at)-style columns would otherwise ship the
// exact lost-update regression the join exists to fix (findings.score=0 vs a
// real finding_enrichment value).
func TestSelectFindingByID_JoinsFindingEnrichment(t *testing.T) {
	require.Contains(t, selectFindingByID, "LEFT JOIN")
	require.Contains(t, selectFindingByID, "FROM finding_enrichment")

	// Every enrich:"output" field must be selected FROM the join (fe.*), not
	// from the legacy findings columns.
	for _, col := range []string{"score", "score_band", "known_exploited",
		"dependents", "unused", "safety_class", "fix_target",
		"must_fix_class", "must_fix_reason"} {
		require.Contains(t, selectFindingByID, "fe."+col,
			"%s must be selected via the finding_enrichment join, not the legacy findings column", col)
		require.NotContains(t, selectFindingByID, "argMax("+col+", synced_at)",
			"%s must not still read the legacy findings column", col)
	}

	// enr_at, never enriched_at: aliasing the fe subquery's version-column
	// aggregate as enriched_at would collide with the sibling
	// argMax(col, enriched_at) aggregates in the SAME select list that
	// bare-reference enriched_at as their own version argument — ClickHouse
	// resolves the bare reference to the alias instead of the raw column
	// (ILLEGAL_AGGREGATION), a known hazard (see also
	// finding.signalsByResource, belief.selectAdjudicationBacklog).
	require.Contains(t, selectFindingByID, "AS enr_at")
	require.NotContains(t, selectFindingByID, "AS enriched_at",
		"aliasing the fe version column as enriched_at would collide with the sibling argMax(col, enriched_at) aggregates")

	// id binds exactly twice: fe's own scope (`WHERE id = ?` inside the
	// subquery), then the outer `WHERE f.id = ?`. Binding it once (or in the
	// wrong order) either scans the whole finding_enrichment table or fails
	// to scope it at all — the same class of bug costAtRiskFrom guards
	// against. Get() passes args in that same text
	// order (id, id), so pin the order here too, not just the count —
	// today reversing it would still work by coincidence (both values are
	// identical), but that coincidence is exactly what a text-order
	// assertion, not just a count, is meant to stop relying on.
	require.Equal(t, 2, strings.Count(selectFindingByID, "id = ?"))
	feScope := strings.Index(selectFindingByID, "FROM finding_enrichment WHERE id = ?")
	outerWhere := strings.Index(selectFindingByID, "WHERE f.id = ?")
	require.Greater(t, feScope, -1, "fe subquery's own scoping WHERE must exist")
	require.Greater(t, outerWhere, -1, "the outer WHERE must exist")
	require.Less(t, feScope, outerWhere,
		"fe's scoping id must bind textually BEFORE the outer WHERE's id, matching Get()'s (id, id) argument order")
}

// TestSelectFindingsArgMax_JoinsFindingEnrichment pins the same fix for
// selectFindingsArgMax (backing ByIDs/ByResourceIDs) that
// TestSelectFindingByID_JoinsFindingEnrichment pins for selectFindingByID.
// selectFindingsArgMax is %s-templated (its fe subquery's WHERE differs by
// caller), so this checks the templated form directly, plus each caller's
// resolved query text.
func TestSelectFindingsArgMax_JoinsFindingEnrichment(t *testing.T) {
	require.Contains(t, selectFindingsArgMax, "LEFT JOIN")
	require.Contains(t, selectFindingsArgMax, "FROM finding_enrichment WHERE %s")

	for _, col := range []string{"score", "score_band", "known_exploited",
		"dependents", "unused", "safety_class", "fix_target",
		"must_fix_class", "must_fix_reason"} {
		require.Contains(t, selectFindingsArgMax, "fe."+col,
			"%s must be selected via the finding_enrichment join, not the legacy findings column", col)
		require.NotContains(t, selectFindingsArgMax, "argMax("+col+", synced_at)",
			"%s must not still read the legacy findings column", col)
	}

	require.Contains(t, selectFindingsArgMax, "AS enr_at")
	require.NotContains(t, selectFindingsArgMax, "AS enriched_at",
		"aliasing the fe version column as enriched_at would collide with the sibling argMax(col, enriched_at) aggregates")
}

// TestByIDsQuery_ScopesJoinAndBindsIDsTwice pins ByIDs' exact resolved query:
// fe's subquery scoped by the SAME id list as the outer WHERE (never
// unscoped — finding_enrichment is nearly as large as findings, and an
// unscoped join here would be a full-table aggregation on every call), with the id
// placeholder list appearing textually in fe's scope BEFORE the outer WHERE,
// matching ByIDs' [ids..., ids...] argument order.
func TestByIDsQuery_ScopesJoinAndBindsIDsTwice(t *testing.T) {
	placeholders := "?,?"
	feScope := "id IN (" + placeholders + ")"
	query := fmt.Sprintf(selectFindingsArgMax, feScope) +
		" WHERE f.id IN (" + placeholders + ") GROUP BY " + findingEnrichmentGroupBy

	require.Equal(t, 2, strings.Count(query, "id IN ("),
		"the id list must appear exactly twice: fe's own scope, then the outer WHERE")
	feIdx := strings.Index(query, "FROM finding_enrichment WHERE id IN (")
	outerIdx := strings.Index(query, "WHERE f.id IN (")
	require.Greater(t, feIdx, -1)
	require.Greater(t, outerIdx, -1)
	require.Less(t, feIdx, outerIdx,
		"fe's scoping id list must bind textually BEFORE the outer WHERE's, matching ByIDs' [ids..., ids...] argument order")
	require.Equal(t, 4, strings.Count(query, "?"), "2 placeholders x 2 occurrences (fe scope + outer WHERE)")
}

// TestByResourceIDsQuery_ScopesJoinViaNestedSubquery pins ByResourceIDs' fe
// scoping: since finding_enrichment carries no resource_id column, fe must be
// scoped by `id IN (SELECT id FROM findings WHERE resource_id IN (...))` —
// the same nested-subquery pattern costAtRiskFrom established — never left
// unscoped.
func TestByResourceIDsQuery_ScopesJoinViaNestedSubquery(t *testing.T) {
	placeholders := "?,?"
	feScope := "id IN (SELECT id FROM findings WHERE resource_id IN (" + placeholders + "))"
	query := fmt.Sprintf(selectFindingsArgMax, feScope) +
		" WHERE f.resource_id IN (" + placeholders + ") GROUP BY " + findingEnrichmentGroupBy +
		fmt.Sprintf(" LIMIT %d", byResourceIDsMaxRows+1)

	require.Contains(t, query, "FROM finding_enrichment WHERE id IN (SELECT id FROM findings WHERE resource_id IN (")
	require.Equal(t, 2, strings.Count(query, "resource_id IN ("),
		"the resource_id list must appear exactly twice: fe's nested subquery, then the outer WHERE")
	feIdx := strings.Index(query, "FROM finding_enrichment")
	outerIdx := strings.Index(query, "WHERE f.resource_id IN (")
	require.Less(t, feIdx, outerIdx,
		"fe's nested-subquery scope must bind textually BEFORE the outer WHERE's resource_id list")
}
