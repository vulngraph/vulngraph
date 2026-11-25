package graphstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNoGraphNodesWriter keeps the post-BFS risk score in Ladybug only.
//
// Ladybug serves the propagated score; nothing reads a ClickHouse copy of it. A
// node-score write-back (a graph.nodes table re-upserted on every rebuild) would
// put a large write on the critical path of the rebuild against zero reads.
//
// It is worth a source-level guard rather than trusting review because the failure
// mode is invisible: an INSERT-only path with no reader breaks nothing when it
// drifts, and its rows go stale without anyone noticing, because nobody reads
// them. Same reasoning as graphschema's TestGraphEdgesReadersApplyFreshness.
func TestNoGraphNodesWriter(t *testing.T) {
	err := filepath.WalkDir("../../..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Hidden dirs (.git, nested worktrees) hold copies of the tree.
			if path != "../../.." && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "no_graph_nodes_writer_test.go") {
			return nil // this file
		}
		// The mutation catalogue names the exact bytes that reintroduce this bug,
		// so it necessarily contains the forbidden string. Skipping it is required
		// for this guard to be green on the unmutated tree — which is the
		// precondition the guardmutation harness checks before trusting it.
		if strings.Contains(filepath.ToSlash(path), "internal/guardmutation/") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(b)
		for _, forbidden := range []string{"INSERT INTO graph.nodes", "INSERT INTO nodes"} {
			assert.NotContains(t, src, forbidden,
				"%s writes graph.nodes, a node-score copy nothing reads: Ladybug serves the post-BFS score. "+
					"If a real reader is needed, wire it to Ladybug rather than adding an unread write path.", path)
		}
		return nil
	})
	assert.NoError(t, err)
}
