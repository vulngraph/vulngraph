package correlate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestScanAssetsBoundsAggregationMemory is the signal for the LoadView memory
// bound, and it has to read the source because the thing it protects is a call
// site, not a value. loadViewSpillBytes could keep its correct value forever
// while nothing applies it — which is exactly how a fix ships inert.
//
// What it guards: loadView is a GROUP BY id over a large asset table whose argMax state
// carries `metadata` (a JSON String). At scale it can peak at several GiB and
// ClickHouse can kill it with code 241, "Memory limit
// (total) exceeded" — not because that alone exceeds the server cap, but
// because it overlaps the findings pages and a cache floor. Spilling the
// aggregation to disk makes a once-per-sweep bulk
// read a few seconds slower instead of dead, and a dead LoadView costs a whole
// correlate sweep.
//
// Deleting the WithQuerySettings call — the natural "simplify this" edit, since
// the query works fine in every test and in staging — restores the multi-GiB peak
// silently. Nothing else in the tree would notice.
func TestScanAssetsBoundsAggregationMemory(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "repo.go", nil, parser.ParseComments)
	require.NoError(t, err)

	var body *ast.FuncDecl
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == "scanAssets" && fn.Recv != nil {
			body = fn
			break
		}
	}
	require.NotNil(t, body, "scanAssets not found in repo.go — this guard is reading the wrong thing")

	var (
		appliesSettings bool
		namesTheSetting bool
		usesTheConst    bool
	)
	ast.Inspect(body, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithQuerySettings" {
			appliesSettings = true
		}
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING &&
			lit.Value == `"max_bytes_before_external_group_by"` {
			namesTheSetting = true
		}
		if id, ok := n.(*ast.Ident); ok && id.Name == "loadViewSpillBytes" {
			usesTheConst = true
		}
		return true
	})

	require.True(t, appliesSettings,
		"scanAssets no longer calls WithQuerySettings. Every correlation read (LoadView, "+
			"LoadViewForTypes) goes through here; without it the full-view "+
			"aggregation is unbounded again and can exceed the memory limit under concurrent load.")
	require.True(t, namesTheSetting,
		"scanAssets applies query settings but not max_bytes_before_external_group_by — "+
			"a Go context deadline cannot bound ClickHouse's aggregation memory, only this can")
	require.True(t, usesTheConst,
		"the spill threshold must stay the loadViewSpillBytes const, where its arithmetic "+
			"and the disk it spills to are documented — not an inline literal")
}
