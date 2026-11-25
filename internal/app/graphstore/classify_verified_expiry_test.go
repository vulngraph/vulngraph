package graphstore

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestClassifyRelEndpointsTrustsOnlyVerifiedExpiry is a structural guard against
// the exact regression the verified-expiry change closed: classifyRelEndpoints
// deciding relRowEndpointExpired from the edge row's own DECLARED src_type/
// dst_type (via ephemeralEndpointType) instead of the caller's ClickHouse-backed
// verifiedExpired map.
//
// A fixture-based table test (TestDropClassificationSeparatesExpiredEphemeralFromDangling)
// already proves the CURRENT behaviour is correct for the cases it constructs,
// but it cannot prove classifyRelEndpoints does not ALSO consult
// ephemeralEndpointType internally and reach the same verdict on those same
// fixtures for the wrong reason — a declared-type check and a verified-map check
// agree on every case where the declaration happens to be true, and disagree
// only on the case that matters: a stale/wrong producer type, or a load-set
// regression that silently drops a live ephemeral asset. This test reads the
// function's own source rather than its output, so it cannot be fooled by a
// coincidentally-correct fixture the way the table test can.
func TestClassifyRelEndpointsTrustsOnlyVerifiedExpiry(t *testing.T) {
	src, err := os.ReadFile("copy_load_relcsv.go")
	require.NoError(t, err)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "copy_load_relcsv.go", src, 0)
	require.NoError(t, err)

	body := funcBodySource(t, file, fset, string(src), "classifyRelEndpoints")

	require.Contains(t, body, "verifiedExpired",
		"classifyRelEndpoints must decide relRowEndpointExpired from the caller's "+
			"verified map, not from the edge row's own declared type")
	require.NotContains(t, body, "ephemeralEndpointType",
		"classifyRelEndpoints must NOT consult ephemeralEndpointType (the DECLARED-type "+
			"set) directly — that set is candidate selection for the bulk verification "+
			"query in bulkSyncCopy, never a basis for classification. Reintroducing this "+
			"reference is exactly the gap the fix closed: a wrong or stale "+
			"producer type, or a load-set regression dropping a live ephemeral asset, "+
			"could force \"expired\" again with nothing verifying it.")
}

// funcBodySource returns the source text of the named top-level function's body.
func funcBodySource(t *testing.T, file *ast.File, fset *token.FileSet, src, name string) string {
	t.Helper()
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Body.Pos()).Offset
		end := fset.Position(fn.Body.End()).Offset
		return src[start:end]
	}
	t.Fatalf("%s not found", name)
	return ""
}
