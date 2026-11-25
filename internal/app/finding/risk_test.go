package finding

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// TestRiskByResourceForIDsQuery_PlaceholderCountMatchesArgs pins the exact
// mistake this query is one typo away from: riskByResourceForIDs' %s
// placeholder appears TWICE in the text (the legacy findings filter and the
// finding_enrichment join's own id scope), so both the
// fmt.Sprintf call and the bound args must repeat the id list, not just one.
// ClickHouse binds ?s positionally; a mismatch here doesn't fail at the Go
// level (no compile error, no panic) — it either errors at query time or,
// worse, silently binds the wrong value to the wrong placeholder. This test
// builds the query and args exactly as RiskByResource does and catches the
// mismatch without needing a real ClickHouse.
func TestRiskByResourceForIDsQuery_PlaceholderCountMatchesArgs(t *testing.T) {
	ids := []string{"res-1", "res-2", "res-3"}
	placeholders, args := dbutil.CHIn(ids)

	// Mirrors RiskByResource's query-building exactly.
	query := fmt.Sprintf(riskByResourceForIDs, placeholders, placeholders)
	boundArgs := append(append([]any{}, args...), args...)

	require.Equal(t, strings.Count(query, "?"), len(boundArgs),
		"every ? placeholder in the query text must have exactly one bound arg")
	require.Equal(t, len(ids)*2, len(boundArgs),
		"the id list is bound twice — once per %%s occurrence in riskByResourceForIDs")
}
