package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCostCollectLoopHasNoSilentExit guards against a return/continue on a
// connector-list or per-connector config error with no log line and no
// metric — which renders in the UI as a clean "No cost anomalies", making a
// permission denial indistinguishable from an actual absence of anomalies.
//
// A syntax tree is used rather than a regex for the reason audit_wiring_test.go
// documents: a guard whose verdict depends on line breaks is not guarding the
// thing it names. The check is structural — inside the runCostCollect closure,
// every branch that abandons work must be preceded, in the same block, by a
// metric observation.
func TestCostCollectLoopHasNoSilentExit(t *testing.T) {
	body := costCollectBody(t)

	// Every metric outcome the loop can report, and the log calls beside them.
	metricCalls := countSelectorCalls(body, "ObserveCostCollect")
	successCalls := countSelectorCalls(body, "ObserveCostCollectSuccess")
	require.GreaterOrEqual(t, metricCalls, 4,
		"each failure mode (connector list, config, collect outcome, nothing-to-do) must increment graph_cost_collect_total")
	require.GreaterOrEqual(t, successCalls, 1,
		"a stored collection must stamp graph_cost_last_success_timestamp_seconds")

	// Structural: no `return` or `continue` in the closure may sit in a block
	// that does not also observe a metric. This is the exact shape of the bug.
	for _, blk := range abandoningBlocks(body) {
		require.Truef(t, blockObserves(blk),
			"a return/continue at %d abandons cost collection without incrementing graph_cost_collect_total — "+
				"an integration can then stay dark while its UI reports health", blk.Pos())
	}
}

// TestCostCollectLoopLogsEveryOutcome pins the log half. A metric says how often;
// only a log line says which connector and which AWS error, and the operator fix
// (grant ce:GetCostAndUsage) is not derivable from a counter.
func TestCostCollectLoopLogsEveryOutcome(t *testing.T) {
	body := costCollectBody(t)
	logCalls := countSelectorCalls(body, "Msg")
	require.GreaterOrEqual(t, logCalls, 5,
		"every outcome of the cost collect loop must produce a log line, including the ones that used to return silently")
	// The permission-denied branch must name the missing permission, so the log
	// line alone is actionable.
	require.True(t, mentionsIdent(body, "RequiredIAMPermission"),
		"the denial branch must carry costdata.RequiredIAMPermission so the fix does not need a code read")
	require.True(t, mentionsIdent(body, "IsPermissionDenied"),
		"a permission denial must be classified, not lumped in with generic errors")
}

// TestCostCollectLoopDecryptsConfigBeforeUse guards against reading
// region/account_id straight off connectorSvc.List's result: List returns
// connectors with Config == nil by design (see connector.Service.List's own
// doc comment), so any field read off it directly is always empty. The fix is
// connector.Service.Get, which decrypts — the same pattern ConnectorByAccountID
// already uses elsewhere in this package. Structural, not string-matched:
// proves the loop calls .Get on the connector service before it references
// any field off a config map.
func TestCostCollectLoopDecryptsConfigBeforeUse(t *testing.T) {
	body := costCollectBody(t)
	require.GreaterOrEqual(t, countSelectorCalls(body, "Get"), 1,
		"the cost-collect loop must call connectorSvc.Get (decrypted config) for each connector — "+
			"List's result has Config == nil by design, so reading a field off it directly is always empty")
}

// costCollectBody returns the body of the runCostCollect closure in
// serve_costcollect.go.
func costCollectBody(t *testing.T) *ast.BlockStmt {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "serve_costcollect.go", nil, 0)
	require.NoError(t, err)

	var body *ast.BlockStmt
	ast.Inspect(f, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		id, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || id.Name != "runCostCollect" {
			return true
		}
		lit, ok := assign.Rhs[0].(*ast.FuncLit)
		if !ok {
			return true
		}
		body = lit.Body
		return false
	})
	require.NotNil(t, body, "runCostCollect closure not found in serve_costcollect.go — did the cost loop move again?")
	return body
}

func countSelectorCalls(n ast.Node, name string) int {
	var count int
	ast.Inspect(n, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			count++
		}
		return true
	})
	return count
}

func mentionsIdent(n ast.Node, name string) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if sel, ok := node.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// abandoningBlocks returns every block containing a return or continue that is
// not the loop's own trailing flow — i.e. the early exits.
func abandoningBlocks(body *ast.BlockStmt) []*ast.BlockStmt {
	var out []*ast.BlockStmt
	ast.Inspect(body, func(n ast.Node) bool {
		blk, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for _, stmt := range blk.List {
			switch s := stmt.(type) {
			case *ast.ReturnStmt:
				out = append(out, blk)
			case *ast.BranchStmt:
				if s.Tok == token.CONTINUE {
					out = append(out, blk)
				}
			}
		}
		return true
	})
	return out
}

// blockObserves reports whether a block increments the cost metric (directly, or
// via the type-skip guard that is not an abandonment of work but a filter).
func blockObserves(blk *ast.BlockStmt) bool {
	if countSelectorCalls(blk, "ObserveCostCollect") > 0 {
		return true
	}
	// `if c.Type != "aws" { continue }` skips a non-AWS connector: nothing was
	// attempted, so there is no outcome to report. Recognised by the block
	// containing ONLY the branch statement.
	return len(blk.List) == 1
}
