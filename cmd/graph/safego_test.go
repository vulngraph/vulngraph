package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafego_RecoversPanicAndKeepsProcessAlive(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	safego(context.Background(), "boom", func() {
		defer wg.Done()
		panic("kaboom")
	})
	wg.Wait() // the test binary surviving to here IS the assertion
}

func TestSafego_RunsFn(t *testing.T) {
	done := make(chan struct{})
	safego(context.Background(), "ok", func() { close(done) })
	<-done
}

// TestNoUnrecoveredGoroutines guards against a panic in any background
// goroutine killing the whole single-binary pod instead of just the
// subsystem. Every `go` statement in cmd/graph must either call safego
// (which is a plain call, not a `go` statement, so it never trips this) or
// open its body with a deferred recover. Derived from the source on every
// run rather than a hand-maintained list.
func TestNoUnrecoveredGoroutines(t *testing.T) {
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	var checked int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)

		ast.Inspect(file, func(n ast.Node) bool {
			g, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			checked++
			pos := fset.Position(g.Pos())
			lit, ok := g.Call.Fun.(*ast.FuncLit)
			require.Truef(t, ok,
				"%s: `go %s(...)` spawns a goroutine with no recover — wrap it in safego(ctx, name, func(){...})",
				pos, exprString(g.Call.Fun))
			require.Truef(t, opensWithRecover(lit),
				"%s: goroutine body does not start with a deferred recover — wrap it in safego(ctx, name, func(){...})",
				pos)
			return true
		})
	}
	require.NotZero(t, checked, "no `go` statements parsed from cmd/graph — did the package layout change?")
}

// opensWithRecover reports whether the first statement of body is a deferred
// closure that calls recover().
func opensWithRecover(lit *ast.FuncLit) bool {
	if lit.Body == nil || len(lit.Body.List) == 0 {
		return false
	}
	d, ok := lit.Body.List[0].(*ast.DeferStmt)
	if !ok {
		return false
	}
	var found bool
	ast.Inspect(d, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "recover" {
			found = true
		}
		return !found
	})
	return found
}

func exprString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprString(v.X) + "." + v.Sel.Name
	default:
		return "func"
	}
}
