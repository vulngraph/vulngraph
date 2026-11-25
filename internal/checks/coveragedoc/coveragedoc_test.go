package coveragedoc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCoverageDocIsCurrent fails when docs/cspm-coverage.md no longer matches
// the matrices, snapshots and framework mappings — the document is the
// published answer to "how much of each benchmark and framework does graph
// evaluate", so it must never lag the data it renders.
func TestCoverageDocIsCurrent(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	want, err := Render(root)
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(root, Path))
	require.NoError(t, err)
	require.Equal(t, want, string(got), "docs/cspm-coverage.md is stale — run: go run ./cmd/cspm-coverage")
}
