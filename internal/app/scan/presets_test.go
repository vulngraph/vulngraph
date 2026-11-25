package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
)

// TestEveryTargetPresetIsBounded is the guard behind targetQuery's doc comment:
// a target query without `LIMIT MaxTargets` does not scan more assets, it fails
// every run — the resolver refuses a result the node budget truncated, so an
// unbounded preset is not "generous", it is broken: an unbounded all_exposed
// preset can match far more nodes than the 500-node budget.
//
// Asserting the literal `LIMIT <MaxTargets>` rather than just "contains LIMIT"
// is deliberate: a preset limited to some other number would still pass a
// weaker check while disagreeing with the cap a single run can actually scan.
//
// This guard covers the PRESETS only. It cannot see the workflow builder's own
// composer (frontend WorkflowBuilder.tsx), which is how most profiles are
// actually created — scan.ValidateTargetQuery is the server-side chokepoint
// that covers every path, and TestValidateTargetQuery is its guard.
func TestEveryTargetPresetIsBounded(t *testing.T) {
	wantLimit := fmt.Sprintf("LIMIT %d", MaxTargets)
	for _, p := range TargetPresets {
		if p.Query == "" {
			// The "custom" preset intentionally ships an empty query: it exists
			// to hand the user a blank editor. It resolves nothing until they
			// type something, so there is no bound to carry here.
			require.Equal(t, "custom", p.ID,
				"only the custom preset may ship an empty query — %s has one", p.ID)
			continue
		}
		require.Containsf(t, p.Query, wantLimit,
			"preset %q must be bounded by %q or it hits the node budget mid-traversal and "+
				"yields an arbitrary subset (which the resolver then refuses): %s", p.ID, wantLimit, p.Query)
		require.Containsf(t, p.Query, "ORDER BY a.score DESC",
			"preset %q must order before it limits, or its LIMIT selects an arbitrary page "+
				"rather than the highest-risk targets", p.ID)
		// LIMIT must come last: Cypher applies ORDER BY before LIMIT only when
		// the LIMIT trails it, and a limit placed before the ordering would
		// select an arbitrary page and then sort just that page.
		require.Truef(t, strings.HasSuffix(strings.TrimSpace(p.Query), wantLimit),
			"preset %q must END with %q so the ordering is applied before the bound: %s",
			p.ID, wantLimit, p.Query)
	}
}

// TestTargetPresetIDsAreUnique keeps the catalogue addressable: the frontend
// and the API both select a preset by ID, so a duplicate silently shadows one.
func TestTargetPresetIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range TargetPresets {
		require.Falsef(t, seen[p.ID], "duplicate target preset ID %q", p.ID)
		seen[p.ID] = true
	}
}

// TestAllExposedPresetShape pins the exact composed query for the all_exposed
// preset, so a refactor of targetQuery cannot quietly change what
// the platform's most-used scan scope actually selects.
func TestAllExposedPresetShape(t *testing.T) {
	var q string
	for _, p := range TargetPresets {
		if p.ID == "all_exposed" {
			q = p.Query
		}
	}
	require.Equal(t, fmt.Sprintf(
		"MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})\nRETURN a\nORDER BY a.score DESC\nLIMIT %d",
		MaxTargets), q)

	// And the label must not promise more than the query delivers — it read
	// "All internet-exposed assets" while returning a 500-node arbitrary subset.
	for _, p := range TargetPresets {
		if p.ID == "all_exposed" {
			require.NotContains(t, p.Label, "All",
				"the label must not claim to cover every exposed asset when the query is bounded to MaxTargets")
		}
	}
}

// TestValidateTargetQuery is the guard on the chokepoint. The presets are only
// one way a TargetQuery reaches the database: the workflow builder composes its
// own Cypher from the WHO-section chips and never reads TargetPresets, so
// bounding the presets alone left the primary profile-creation path able to
// save an unbounded query — which then failed every run, at run time, long
// after the person who could fix it had left the form.
func TestValidateTargetQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{"empty means the non-Cypher ListExternal path, always valid", "", false},
		{"whitespace only is still empty", "   \n\t ", false},
		{"a preset is valid by construction", TargetPresets[0].Query, false},
		{"bounded at the cap", "MATCH (a:Asset) RETURN a\nLIMIT 500", false},
		{"bounded below the cap", "MATCH (a:Asset) RETURN a\nLIMIT 10", false},
		{"lowercase limit", "MATCH (a:Asset) RETURN a\nlimit 25", false},
		{"trailing semicolon", "MATCH (a:Asset) RETURN a\nLIMIT 25;", false},
		{"no limit at all — the bug this exists for", "MATCH (a:Asset) RETURN a\nORDER BY a.score DESC", true},
		{"limit above the cap cannot be scanned in one run", "MATCH (a:Asset) RETURN a\nLIMIT 5000", true},
		// A LIMIT that is not trailing does not bound the result: Cypher puts
		// LIMIT last, so a mid-query occurrence belongs to a subclause and the
		// outer result is still unbounded.
		{"limit not in trailing position", "MATCH (a:Asset) RETURN a LIMIT 10 UNION MATCH (b:Asset) RETURN b", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTargetQuery(tc.query)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrUnboundedTargetQuery, "query: %s", tc.query)
				return
			}
			require.NoError(t, err, "query: %s", tc.query)
		})
	}
}

// TestDefaultPresetMatchesFrontendSentinel pins the byte-exact string the
// workflow builder uses as DEFAULT_QUERY. onSubmit sends target_query: "" while
// the form still equals that constant, which selects the non-Cypher
// ListExternal path; if this preset and that constant drift apart, choosing
// "all exposed" in the UI silently moves the profile onto the Cypher resolver
// — a different path with a different failure mode (it errors outright when no
// resolver is wired). Keep frontend/src/components/WorkflowBuilder.tsx's
// DEFAULT_QUERY identical to the string asserted here.
func TestDefaultPresetMatchesFrontendSentinel(t *testing.T) {
	var q string
	for _, p := range TargetPresets {
		if p.ID == "all_exposed" {
			q = p.Query
		}
	}
	require.Equal(t, "MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})\n"+
		"RETURN a\nORDER BY a.score DESC\nLIMIT 500", q,
		"this must stay byte-identical to DEFAULT_QUERY in frontend/src/components/WorkflowBuilder.tsx")
}

// TestHighRiskPresetUsesTheHighBand pins the high_risk preset to the enrich
// high-band threshold, so the preset's "high risk" means what a finding's
// "high" band means.
func TestHighRiskPresetUsesTheHighBand(t *testing.T) {
	for _, p := range TargetPresets {
		if p.ID != "high_risk" {
			continue
		}
		require.Contains(t, p.Query, fmt.Sprintf("WHERE a.score >= %d\n", enrich.ThresholdHigh))
		require.Contains(t, p.Label, fmt.Sprintf("%d", enrich.ThresholdHigh))
		return
	}
	t.Fatal("no high_risk preset")
}

// TestRoleHopPresetsIncludeHasRole: an EC2 instance reaches its instance
// profile role only through HasRole, so a preset that follows ExecutesAs alone
// leaves public instances out of its scans.
func TestRoleHopPresetsIncludeHasRole(t *testing.T) {
	for _, p := range TargetPresets {
		if strings.Contains(p.Query, ":ExecutesAs]") {
			t.Errorf("preset %q follows ExecutesAs without HasRole: %s", p.ID, p.Query)
		}
	}
	for _, p := range TargetPresets {
		if p.ID == "privesc_exposed" {
			require.Contains(t, p.Query, "-[:ExecutesAs|HasRole]->(r:IamRole)")
			return
		}
	}
	t.Fatal("no privesc_exposed preset")
}
