//go:build integration

package respond

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// Requires `docker compose up` and applied migrations (graph migrate).
func TestCHRepo_RecordAndList(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	target := "finding-" + time.Now().Format("150405.000000")
	ts := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE audit_events DELETE WHERE target_id = ?", target)
	})

	ev := AuditEvent{
		TS: ts, Actor: "agent", Action: "decision",
		TargetType: "finding", TargetID: target, Details: `{"outcome":"escalated"}`,
	}
	require.NoError(t, repo.Record(ctx, ev))

	events, err := repo.List(ctx, 100)
	require.NoError(t, err)

	var mine []AuditEvent
	for _, e := range events {
		if e.TargetID == target {
			mine = append(mine, e)
		}
	}
	require.Len(t, mine, 1)
	require.Equal(t, "agent", mine[0].Actor)
	require.Equal(t, "decision", mine[0].Action)
	require.Contains(t, mine[0].Details, "escalated")
	require.NotEmpty(t, mine[0].ID, "a correlation id is assigned")
}

// TestCHRepo_DecisionsSummary_HotspotsRespectLimitParameter is the regression
// test for selectEscalationHotspots' LIMIT going from a hardcoded literal (5)
// to a real query parameter (hotspotLimit) — a hardcoded literal can drift
// out of sync with the count claimed elsewhere; a shared parameter cannot.
// This proves the ClickHouse driver actually accepts LIMIT
// as a `?` placeholder (not all drivers do) and that the cap is enforced:
// more than hotspotLimit distinct findings qualify (each escalated >=3
// times), but the summary returns at most hotspotLimit of them.
func TestCHRepo_DecisionsSummary_HotspotsRespectLimitParameter(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	suffix := time.Now().Format("150405.000000")
	ts := time.Now().Truncate(time.Second)
	var targets []string
	for i := 0; i < hotspotLimit+1; i++ {
		targets = append(targets, "hotspot-"+suffix+"-"+string(rune('a'+i)))
	}
	t.Cleanup(func() {
		for _, target := range targets {
			_ = ch.Exec(ctx, "ALTER TABLE audit_events DELETE WHERE target_id = ?", target)
		}
	})

	for _, target := range targets {
		for i := 0; i < 3; i++ { // HAVING n >= 3
			require.NoError(t, repo.Record(ctx, AuditEvent{
				TS: ts, Actor: "agent", Action: "decision",
				TargetType: "finding", TargetID: target, Details: `{"outcome":"escalated"}`,
			}))
		}
	}

	s, err := repo.DecisionsSummary(ctx)
	require.NoError(t, err)
	require.LessOrEqual(t, len(s.Hotspots), hotspotLimit,
		"more than hotspotLimit findings qualified as hotspots, but the summary must cap at hotspotLimit")

	// hotspotLimit itself happens to equal the OLD hardcoded literal (5) today,
	// so the assertion above alone can't distinguish "parameterized correctly"
	// from "still hardcoded, coincidentally the same number". Call the query
	// with a DIFFERENT limit directly to prove the placeholder is genuinely
	// live, not decorative.
	var got int
	require.NoError(t, ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			got++
		}
		return nil
	}, selectEscalationHotspots, 2))
	require.Equal(t, 2, got, "the LIMIT parameter must actually constrain the result count, not just accept an arg and ignore it")
}

// Requires `docker compose up` and applied migrations (graph migrate).
//
// TestCHRepo_ListDecisions_FiltersAndPaginate is the regression test for the
// bug this filter shipped to fix: GET /api/decisions used to have no filter
// support at any layer, so the Decisions list filtered client-side over
// whatever ~100-row page happened to be loaded, silently truncating a
// filtered view. This exercises the real selectDecisions predicates against
// ClickHouse, including that a filtered page's keyset cursor continues
// within the filtered set (never leaking unfiltered rows back in on page 2).
func TestCHRepo_ListDecisions_FiltersAndPaginate(t *testing.T) {
	ctx := context.Background()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ch.Close() })
	repo := NewCHRepo(ch)

	prefix := "filter-test-" + time.Now().Format("150405.000000") + "-"
	base := time.Now().Truncate(time.Second)
	t.Cleanup(func() {
		_ = ch.Exec(ctx, "ALTER TABLE audit_events DELETE WHERE target_id LIKE ?", prefix+"%")
	})

	// Five decisions spanning distinct ts (newest first once inserted), mixing
	// outcome/action_class/safety so each filter has both matching and
	// non-matching rows to distinguish from "no filter applied".
	rows := []struct {
		id      string
		offset  time.Duration
		details string
	}{
		{"esc-remediate-1", 4 * time.Second, `{"outcome":"escalated","action_class":"remediate","safety_band":"caution"}`},
		{"esc-isolate-1", 3 * time.Second, `{"outcome":"escalated","action_class":"isolate","safety_band":"risky"}`},
		{"parked-remediate-1", 2 * time.Second, `{"outcome":"parked_for_approval","action_class":"remediate","safety_band":"safe"}`},
		{"parked-remediate-2", 1 * time.Second, `{"outcome":"parked_for_approval","action_class":"remediate","safety_band":"safe"}`},
		{"suppressed-remediate-1", 0, `{"outcome":"suppressed_by_verdict","action_class":"remediate","safety_band":"safe"}`},
	}
	for _, r := range rows {
		target := prefix + r.id
		require.NoError(t, repo.Record(ctx, AuditEvent{
			TS: base.Add(r.offset), Actor: "agent", Action: "decision",
			TargetType: "finding", TargetID: target, Details: r.details,
		}))
	}
	mineOnly := func(events []AuditEvent) []AuditEvent {
		var out []AuditEvent
		for _, e := range events {
			if strings.HasPrefix(e.TargetID, prefix) {
				out = append(out, e)
			}
		}
		return out
	}

	t.Run("by outcome", func(t *testing.T) {
		events, err := repo.ListDecisions(ctx, time.Time{}, "", 100, DecisionFilter{Outcome: "escalated"})
		require.NoError(t, err)
		mine := mineOnly(events)
		require.Len(t, mine, 2)
		for _, e := range mine {
			require.Contains(t, e.Details, `"outcome":"escalated"`)
		}
	})

	t.Run("by action_class", func(t *testing.T) {
		events, err := repo.ListDecisions(ctx, time.Time{}, "", 100, DecisionFilter{ActionClass: "isolate"})
		require.NoError(t, err)
		mine := mineOnly(events)
		require.Len(t, mine, 1)
		require.Equal(t, prefix+"esc-isolate-1", mine[0].TargetID)
	})

	t.Run("needs_action unions escalated and parked", func(t *testing.T) {
		events, err := repo.ListDecisions(ctx, time.Time{}, "", 100, DecisionFilter{Outcome: OutcomeNeedsAction})
		require.NoError(t, err)
		mine := mineOnly(events)
		require.Len(t, mine, 4)
	})

	t.Run("safe_to_fix excludes observe-free-but-suppressed and non-safe rows", func(t *testing.T) {
		events, err := repo.ListDecisions(ctx, time.Time{}, "", 100, DecisionFilter{Outcome: OutcomeSafeToFix})
		require.NoError(t, err)
		mine := mineOnly(events)
		// safety=safe AND action_class!=observe AND outcome!=suppressed_by_verdict:
		// only parked-remediate-1 and parked-remediate-2 qualify; suppressed-remediate-1
		// is safety=safe too but excluded by the outcome!=suppressed_by_verdict leg.
		require.Len(t, mine, 2)
	})

	t.Run("outcome and action_class AND together", func(t *testing.T) {
		events, err := repo.ListDecisions(ctx, time.Time{}, "", 100, DecisionFilter{Outcome: "escalated", ActionClass: "remediate"})
		require.NoError(t, err)
		mine := mineOnly(events)
		require.Len(t, mine, 1)
		require.Equal(t, prefix+"esc-remediate-1", mine[0].TargetID)
	})

	t.Run("pagination stays within the filtered set", func(t *testing.T) {
		// limit=2 forces an actual page boundary WITHIN this test's own fixture
		// rows (they are the newest four remediate rows in the table, all
		// inserted moments ago), so page 2 is proven to contain the specific
		// remaining rows rather than asserted vacuously over an empty page —
		// an earlier version of this test used limit=100, which returned the
		// whole filtered set on page 1 and left page 2 empty by construction
		// (nothing to assert), passing unchanged even if the cursor seek had
		// silently dropped the action_class predicate entirely.
		filter := DecisionFilter{ActionClass: "remediate"}
		page1, err := repo.ListDecisions(ctx, time.Time{}, "", 2, filter)
		require.NoError(t, err)
		mine1 := mineOnly(page1)
		require.Len(t, mine1, 2, "newest two remediate rows: esc-remediate-1, parked-remediate-1")
		require.Equal(t, prefix+"esc-remediate-1", mine1[0].TargetID)
		require.Equal(t, prefix+"parked-remediate-1", mine1[1].TargetID)

		last := mine1[len(mine1)-1]
		page2, err := repo.ListDecisions(ctx, last.TS, last.ID, 2, filter)
		require.NoError(t, err)
		mine2 := mineOnly(page2)
		require.Len(t, mine2, 2, "next two remediate rows: parked-remediate-2, suppressed-remediate-1")
		require.Equal(t, prefix+"parked-remediate-2", mine2[0].TargetID)
		require.Equal(t, prefix+"suppressed-remediate-1", mine2[1].TargetID)
		for _, e := range mine2 {
			require.NotEqual(t, mine1[0].ID, e.ID, "page 2 must not repeat a page-1 row")
			require.NotEqual(t, mine1[1].ID, e.ID, "page 2 must not repeat a page-1 row")
		}
	})
}
