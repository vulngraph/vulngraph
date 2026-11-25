package graphschema

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshnessExempt are files allowed to read graph_edges WITHOUT the freshness
// filter, each with a reason. Everything else querying graph_edges must apply
// EdgeFreshnessCond — a reader that skips it resurrects edges that no longer
// exist (they are never deleted, only left un-restamped until TTL).
var freshnessExempt = map[string]string{
	"app/asset/drift.go":                "drift timeline is deliberately historical — it reports on old edges",
	"app/asset/repo_package_runners.go": "package departure evidence reads the LAPSED edges into a package and each runner's newest stamp on purpose — which runners used to ship it and whether their producer read them again since; a freshness filter would hide exactly the evidence. Nothing it returns is traversed or served as a live relationship.",
	"app/asset/purge.go":                "PurgeEdgesForAssets deletes every graph_edges row referencing a purged account's assets, fresh or stale — applying EdgeFreshnessCond here would UNDERCOUNT (missing already-stale rows that still physically exist) and, worse, leave them undeleted: purging must remove all of them, not just the fresh ones.",
}

// TestGraphEdgesReadersApplyFreshness walks internal/ and asserts every
// non-test file that queries graph_edges references EdgeFreshnessCond (or is
// explicitly exempted above with a reason).
func TestGraphEdgesReadersApplyFreshness(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel == "graphschema/graphschema.go" {
			return nil // the definition itself
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(b)
		if !strings.Contains(src, "FROM graph_edges") {
			return nil
		}
		if reason, ok := freshnessExempt[rel]; ok {
			t.Logf("exempt: %s (%s)", rel, reason)
			return nil
		}
		assert.Contains(t, src, "EdgeFreshnessCond",
			"%s queries graph_edges without the freshness filter — stale (disappeared) edges "+
				"stay readable until TTL; apply graphschema.EdgeFreshnessCond or add an exemption with a reason", rel)
		return nil
	})
	require.NoError(t, err)
}
