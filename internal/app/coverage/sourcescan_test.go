package coverage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeGo(t *testing.T, dir, name, src string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644))
}

func TestDeclaredSourcesFindsEveryProducerShape(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "literal.go", `package p
func f() any { return finding.Finding{Source: "aws_guardduty"} }
`)
	writeGo(t, dir, "constant.go", `package p
const source = "cspm"
func g() any { return finding.Finding{Source: source} }
`)
	// The nuclei shape: a local defaulted to a literal, never a const.
	writeGo(t, dir, "local.go", `package p
func h(scanner string) any {
	source := scanner
	if source == "" {
		source = "nuclei"
	}
	return finding.Finding{Source: source}
}
`)
	writeGo(t, filepath.Join(dir, "scan"), "import.go", `package scan
var validImportSources = map[string]bool{"openvas": true, "qualys": true}
`)

	got, err := DeclaredSources(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"aws_guardduty", "cspm", "nuclei", "openvas", "qualys"}, got)
}

// A Source field on anything that is not a finding must not inflate the set:
// beliefs, filters and webhook payloads all have one, and counting them would
// invent sources that can never appear in the findings table.
func TestDeclaredSourcesIgnoresNonFindingSourceFields(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "other.go", `package p
func f() {
	_ = belief.Evidence{Source: "enrich_score"}
	_ = finding.Filter{Source: "nuclei"}
	_ = webhook.Payload{Source: "graph"}
}
`)
	got, err := DeclaredSources(dir)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestDeclaredSourcesIgnoresTestFilesAndSkippedTrees(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "fixture_test.go", `package p
func f() any { return finding.Finding{Source: "only_in_a_fixture"} }
`)
	writeGo(t, filepath.Join(dir, "node_modules"), "x.go", `package p
func f() any { return finding.Finding{Source: "vendored"} }
`)
	got, err := DeclaredSources(dir)
	require.NoError(t, err)
	assert.Empty(t, got, "a source that only exists in a fixture is not one the platform can produce")
}

// An unparseable file must fail loudly. Swallowing it would silently shrink the
// declared set, which reads as "this source does not exist" — the exact lie
// this scan exists to prevent.
func TestDeclaredSourcesFailsOnUnparseableGo(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "broken.go", "package p\nfunc f( {\n")
	_, err := DeclaredSources(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken.go")
}

// The real tree is the case that matters: these have been discussed as
// "sources we have" for months. Whether they have produced anything is the live
// half; that the code declares them must be derivable here.
func TestDeclaredSourcesOnThisTreeFindsActiveProducers(t *testing.T) {
	got, err := DeclaredSources("../../..")
	require.NoError(t, err)
	for _, want := range []string{"cspm", "supply_chain", "vm_vuln", "base_image"} {
		assert.Contains(t, got, want)
	}
}
