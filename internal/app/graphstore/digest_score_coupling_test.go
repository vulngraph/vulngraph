package graphstore

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDigestLatchIsGatedOnScoresApplied keeps the digest gate and the BFS score
// write coupled.
//
// The digest is what lets a sweep skip the rebuild, and the Scores half is computed
// from the assets ClickHouse returned — NOT from what the graph actually holds. So
// if the BFS score write fails and the digest is latched anyway, the next sweep
// compares an unchanged corpus against a matching digest, takes the cheap path, and
// never repairs the un-boosted graph. Withholding only the lastScores stash does not
// help: refreshScores is not called at all.
//
// This needs a source-level guard rather than a behavioural test because the two
// latch sites are in different functions (SyncFromSources and LoadFromSnapshot), the
// failure is invisible (no error, just stale scores that never heal), and the natural
// way to add a third load path is to copy one of them. A behavioural test would also
// have to inject a Ladybug write failure through a full sync, which there is no seam for.
//
// Same reasoning as TestNoGraphNodesWriter and graphschema's
// TestGraphEdgesReadersApplyFreshness: guard the invariant where it can drift.
func TestDigestLatchIsGatedOnScoresApplied(t *testing.T) {
	// Two different names carry the same proof depending on the path:
	//   scoresApplied — the full rebuild and the snapshot load, where propagateRisk
	//                   reports whether its UNWIND SET reached the graph.
	//   refreshed     — the cheap path, where a refreshScores error clears the flag
	//                   and drops through to a full rebuild, so a latch under it
	//                   already implies the scores landed.
	//   *prev         — rebaseSignalsDigest, which moves only the Signals half of a
	//                   digest that was itself latched under one of the above.
	// A latch under none of them is unproven. Store(nil) latches nothing and is
	// not counted.
	const latch = "s.lastDigest.Store("
	proofs := []string{"scoresApplied", "refreshed", "*prev"}

	found := 0
	for _, name := range serviceFiles(t) {
		b, err := os.ReadFile(name)
		require.NoError(t, err)
		found += checkLatchSites(t, name, strings.Split(string(b), "\n"), latch, proofs)
	}
	require.Equal(t, 4, found,
		"expected exactly 4 lastDigest.Store sites (SyncFromSources full path, the cheap "+
			"refresh path, LoadFromSnapshot, rebaseSignalsDigest); found %d. A new one must carry the same proof — "+
			"update this guard deliberately.", found)
}

// checkLatchSites asserts every latch in one file is gated and returns how many
// it found.
func checkLatchSites(t *testing.T, name string, lines []string, latch string, proofs []string) int {
	t.Helper()
	found := 0
	for i, line := range lines {
		if !strings.Contains(line, latch) || strings.Contains(line, latch+"nil)") {
			continue
		}
		found++
		// The gate is the enclosing condition, so look back over the surrounding
		// block rather than at the single line. 12 lines covers every current site
		// including its explanatory comment.
		lo := i - 12
		if lo < 0 {
			lo = 0
		}
		window := strings.Join(lines[lo:i], "\n")
		gated := false
		for _, p := range proofs {
			if strings.Contains(window, p) {
				gated = true
				break
			}
		}
		assert.True(t, gated,
			"%s:%d latches the load digest without any evidence the BFS scores reached "+
				"the graph (looked for %v). A digest latched over a graph whose scores failed to "+
				"write makes the next sweep skip the refresh that would repair it, permanently — "+
				"the Scores half is computed from what ClickHouse returned, not from what the "+
				"graph holds. Gate this site like the others, or if this path genuinely cannot "+
				"have unapplied scores, say why here.", name, i+1, proofs)
	}
	return found
}
