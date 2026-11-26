package coverage

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

func offlineDoc(t *testing.T) string {
	t.Helper()
	r, err := NewService(checks.Default(), nil, "../../..").Build(context.Background())
	require.NoError(t, err)
	return Render(r)
}

func liveDoc(t *testing.T) string {
	t.Helper()
	reg := checks.Default()
	r, err := NewService(reg, fakeLive{facts: bucketFacts(reg, 100)}, "../../..").Build(context.Background())
	require.NoError(t, err)
	return Render(r)
}

// The offline document must say, per section, that it could not measure —
// never print a zero. Conflating "unknown" with "none" is how a coverage
// document lies.
func TestRenderOfflineMarksEveryLiveSectionUnmeasured(t *testing.T) {
	doc := offlineDoc(t)
	assert.Contains(t, doc, "Mode: **offline**")
	for _, section := range []string{
		"## Coverage by finding category",
		"## The lineage chain",
		"## Metadata collected but never asserted on",
		"## What 100% means",
	} {
		require.Contains(t, doc, section)
		rest := doc[strings.Index(doc, section):]
		assert.Contains(t, rest[:min(len(rest), 900)], needsLive, "section %q must state that it needs a live connection", section)
	}
}

func TestRenderOfflineStillCarriesTheDerivableHalf(t *testing.T) {
	doc := offlineDoc(t)
	assert.Contains(t, doc, "## The four axes")
	assert.Contains(t, doc, "## Scope")
	assert.Contains(t, doc, "aws-s3-public-bucket", "the checks registry is derivable without a cluster")
	assert.Contains(t, doc, graphschema.EdgeTypes[0].Type, "the edge registry is derivable without a cluster")
	assert.Contains(t, doc, "supply_chain", "declared sources come from the AST, not from ClickHouse")
}

func TestRenderRecordsItsOwnMethodAndTimestamp(t *testing.T) {
	doc := offlineDoc(t)
	assert.Contains(t, doc, "## Method")
	assert.Contains(t, doc, AssetFreshness)
	assert.Contains(t, doc, graphschema.EdgeFreshnessCond)
	assert.Contains(t, doc, "resolved_at = toDateTime(0)")
	assert.Contains(t, doc, "argMax(col, synced_at)")
	assert.Contains(t, doc, "Generated 20")
	assert.Contains(t, doc, "DO NOT EDIT")
}

func TestRenderLiveIncludesCategoriesAxisTotalsAndTargets(t *testing.T) {
	doc := liveDoc(t)
	assert.Contains(t, doc, "Mode: **live**")
	assert.Contains(t, doc, "| cspm | exposure |")
	assert.Contains(t, doc, "Open findings by failing axis")
	assert.Contains(t, doc, "Condition that closes it")
	assert.NotContains(t, doc, needsLive)
}

// The generated document describes the current report only; it carries no
// revision history.
func TestRenderCarriesNoRevisionNotes(t *testing.T) {
	doc := liveDoc(t)
	assert.NotContains(t, doc, "Correction to an earlier")
}

// The producer join is what makes the evidence axis answer for the right check,
// so a section built on it must say when it did not run.
func TestRenderWarnsWhenTheProducerJoinFailed(t *testing.T) {
	reg := checks.Default()
	facts := bucketFacts(reg, 100)
	facts.Failed = []string{stepProducers}
	facts.QueryErrors = []string{"open findings by category and check: timeout"}
	r, err := NewService(reg, fakeLive{facts: facts}, "../../..").Build(context.Background())
	require.NoError(t, err)

	doc := Render(r)
	assert.Equal(t, 2, strings.Count(doc, "**Incomplete.**"),
		"the category table and the targets table both rest on the producer join")
	assert.Contains(t, doc, "`open findings by category and check`")
}

func TestRenderNamesEveryProviderInScope(t *testing.T) {
	doc := offlineDoc(t)
	for _, s := range ProviderScopes {
		assert.Contains(t, doc, "| "+s.Provider+" | ")
	}
	assert.Contains(t, doc, "reported and not weighted", "azure's status must be visible, not implied")
}

// Registry Doc and DropReason strings carry multi-sentence histories
// with pipes and quotes in them. Unescaped, one of them silently destroys the
// table it lands in.
func TestFirstLineKeepsMarkdownTablesIntact(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", "—"},
		{"pipe becomes a slash", "a | b", "a / b"},
		{"newline collapses", "a\nb", "a b"},
		{"first sentence only", "short one. a much longer follow-up sentence.", "short one."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, firstLine(tc.in))
		})
	}
	long := strings.Repeat("x", 400)
	assert.LessOrEqual(t, len(firstLine(long)), 160)
}

func TestRenderedEdgeTableRowsHaveAStableColumnCount(t *testing.T) {
	doc := liveDoc(t)
	start := strings.Index(doc, "## The graph axis")
	require.Positive(t, start)
	section := doc[start:]
	section = section[:strings.Index(section, "## What 100%")]
	var rows int
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		rows++
		assert.Equal(t, 11, strings.Count(line, "|"), "row %q has the wrong column count", line)
	}
	assert.Equal(t, len(graphschema.EdgeTypes), rows, "every registered edge type must appear")
}

// A section whose measurement failed must say so. Rendering its zeros as counts
// is the "unknown reads as none" failure that this whole document exists to
// prevent, and it is the exact way a partial run would lie about coverage.
func TestRenderWarnsInEverySectionBuiltOnAFailedMeasurement(t *testing.T) {
	reg := checks.Default()
	facts := bucketFacts(reg, 100)
	facts.Failed = []string{stepEdges}
	facts.QueryErrors = []string{"fresh edges: ILLEGAL_AGGREGATION"}
	r, err := NewService(reg, fakeLive{facts: facts}, "../../..").Build(context.Background())
	require.NoError(t, err)

	doc := Render(r)
	assert.Equal(t, 3, strings.Count(doc, "**Incomplete.**"),
		"the three sections built on edge data — categories, lineage and the edge pipeline — must each carry the caveat")
	assert.Contains(t, doc, "`fresh edges`")
	assert.Contains(t, doc, "floors, not counts")

	lineage := doc[strings.Index(doc, "## The lineage chain"):]
	assert.Contains(t, lineage[:600], "**Incomplete.**")
}

func TestRenderHasNoIncompleteCaveatWhenEveryMeasurementSucceeded(t *testing.T) {
	assert.NotContains(t, liveDoc(t), "**Incomplete.**")
	assert.NotContains(t, offlineDoc(t), "**Incomplete.**",
		"offline is not a partial measurement — it says so once, at the top and per section")
}
