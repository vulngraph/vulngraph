package compliance

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
)

func customFile(t *testing.T, ref string) string {
	t.Helper()
	dir := t.TempDir()
	body := fmt.Sprintf("framework: acme\nname: \"Acme\"\nversion: \"1\"\nsources:\n  - \"Acme security\"\n"+
		"requirements:\n  - {id: \"A.1\", title: \"Rotate keys\", controls: [%q]}\n", ref)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "acme.yaml"), []byte(body), 0o600))
	return dir
}

func firstControlRef(t *testing.T) string {
	t.Helper()
	bs, err := benchmarks.Load()
	require.NoError(t, err)
	return bs[0].ID + "/" + bs[0].Controls[0].ID
}

// TestLoadCatalogAddsCustomFrameworksAfterTheBuiltIn: a framework from
// FRAMEWORKS_DIR is listed beside NIST with its file as the source.
func TestLoadCatalogAddsCustomFrameworksAfterTheBuiltIn(t *testing.T) {
	c, err := LoadCatalog(customFile(t, firstControlRef(t)))
	require.NoError(t, err)
	var got []string
	for _, fw := range c.frameworks {
		got = append(got, fw.ID+"="+fw.Source)
	}
	require.Equal(t, []string{"nist-800-53-r5=" + frameworks.SourceBuiltIn, "acme=custom: acme.yaml"}, got)
}

// TestLoadCatalogRefusesABadCustomFramework: serve must not start with a
// framework missing from the page; the error names the file.
func TestLoadCatalogRefusesABadCustomFramework(t *testing.T) {
	_, err := LoadCatalog(customFile(t, "no-such-benchmark/9.9"))
	require.ErrorContains(t, err, "acme.yaml")
	require.ErrorContains(t, err, "no benchmark matrix row")
	_, err = LoadCatalog(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
}
