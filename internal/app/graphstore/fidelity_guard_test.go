package graphstore

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFidelityGateAbandonsBeforeAnySideEffect guards the two things about the gate
// that a behavioural test cannot reach.
//
// FIRST: position. A behavioural test proves the gate refuses today's side effects.
// It cannot prove that a side effect added TOMORROW lands below the gate rather than
// above it — and above is exactly where a new pre-flight step naturally goes, since
// the gate sits at the top of the function next to filterLadybugAssets. Anything that
// publishes, stamps or latches must be downstream of the decision to abandon, or the
// candidate has already changed the world before it was judged.
//
// SECOND: that the refusal is a return and not a warning. This is the defect being
// guarded, in its own original words: asset.AllEdgesForSync met a ClickHouse
// out-of-memory error on the bulk edge query, set BulkPassFailed, logged
// `Warn().Msg("… bulk pass failed — graph has critical edges only")`, and CONTINUED.
// That single "continue" published a graph missing a large share of its edges and
// served it for a full correlate interval with every gauge green. The correlate
// sweep had to be changed from warn to fail for the same reason. A gate that logs is
// not a gate.
func TestFidelityGateAbandonsBeforeAnySideEffect(t *testing.T) {
	body := serviceSource(t)

	require.Equal(t, 1, strings.Count(body, "checkFidelity("),
		"exactly one call site: the gate must be the single decision point, not a check "+
			"repeated per path where one copy can drift or be skipped")

	sync := funcBody(t, body, "func (s *Service) SyncFromSources(")
	gate := strings.Index(sync, "checkFidelity(")
	require.Positive(t, gate, "SyncFromSources must call checkFidelity")

	// Everything a candidate build does that outlives it. Each one was a real
	// early-return hazard while wiring this: latching a digest, stamping the freshness
	// gauge, or writing the PVC snapshot for a graph nobody is serving all leave a
	// refused build's fingerprints on the next sweep's decisions.
	sideEffects := map[string]string{
		"computeLoadDigest(":         "the digest gate can route a degraded load set onto the cheap signal path, which publishes without ever building",
		"openAndInit(":               "allocating the replacement database is the first cost, and the first thing a refusal should avoid paying",
		"s.db = newDB":               "the swap itself",
		"s.lastBuiltAt.Store(":       "stamping freshness for a graph that was never published makes GraphLadybugRebuildStalled blind to a gate that is refusing every sweep",
		"s.lastDigest.Store(":        "latching a baseline for a load set that never loaded makes the NEXT sweep skip the rebuild that would repair it",
		"s.nodeCount.Store(":         "the readiness and node-budget gauges",
		"s.synced.Store(":            "readiness",
		"WriteSnapshot(":             "a snapshot of a refused build becomes the baseline a restart trusts",
		"s.prewarmSignalCache(":      "the signal cache enrich reads next",
		"s.recordSyncPath(":          "the sync-path metric would count a refusal as a completed build",
		"s.fidelity.publishedShape(": "recording a shape as published is the definition of publishing it",
	}
	for marker, why := range sideEffects {
		at := strings.Index(sync, marker)
		if at < 0 {
			continue // the call moved out of this function; nothing to order against
		}
		assert.Greaterf(t, at, gate,
			"%q occurs BEFORE the fidelity gate in SyncFromSources — %s. Move it below "+
				"checkFidelity, or if it genuinely must run first, say why here.", marker, why)
	}

	// The refusal branch must end the function with an error.
	refusal := strings.Index(sync, "case verdict.Refuse:")
	require.Positive(t, refusal, "the gate's refusal branch must be findable")
	next := strings.Index(sync[refusal+1:], "\n\tcase ")
	require.Positive(t, next, "the refusal branch must be followed by another case")
	branch := sync[refusal : refusal+1+next]
	assert.Contains(t, branch, "return",
		"the refusal branch does not return: this is the exact defect being guarded — "+
			"AllEdgesForSync logged a warning and continued, and that continue published a "+
			"graph missing a large share of its edges")
	assert.Contains(t, branch, "ErrRebuildRefused",
		"a refusal must surface ErrRebuildRefused so the correlate job fails visibly; the "+
			"worker's container logs are retained only briefly, so a log line is not a record")
}

// serviceFiles returns the Service's non-test service*.go files, sorted. The
// source guards follow an invariant across the Service, not one file name, so
// moving a method between these files cannot silently blind them.
func serviceFiles(t *testing.T) []string {
	t.Helper()
	names, err := filepath.Glob("service*.go")
	require.NoError(t, err)
	var out []string
	for _, n := range names {
		if !strings.HasSuffix(n, "_test.go") {
			out = append(out, n)
		}
	}
	require.NotEmpty(t, out)
	sort.Strings(out)
	return out
}

// serviceSource is the concatenated source of serviceFiles.
func serviceSource(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for _, n := range serviceFiles(t) {
		src, err := os.ReadFile(n)
		require.NoError(t, err)
		b.Write(src)
		b.WriteByte('\n')
	}
	return b.String()
}

// funcBody returns the source of the function starting at decl, up to the next
// top-level declaration. Crude on purpose: the alternative is an AST walk that would
// need the whole package to parse, and this guard must still work while a mutation
// has the package in a deliberately broken state.
func funcBody(t *testing.T, src, decl string) string {
	t.Helper()
	start := strings.Index(src, decl)
	require.Positivef(t, start, "cannot find %q in the service*.go sources", decl)
	rest := src[start+len(decl):]
	if end := strings.Index(rest, "\n}\n"); end > 0 {
		return rest[:end]
	}
	return rest
}
