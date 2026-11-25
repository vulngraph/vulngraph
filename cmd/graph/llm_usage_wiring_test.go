package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLLMConsumersAreMetered fails when the raw provider client is handed to
// any consumer instead of llmUsage.Client(llmClient, <purpose>). A raw client
// would spend without a ledger row and without a budget check — the one way
// the monthly cap could be bypassed silently (ADR 085 §7).
func TestLLMConsumersAreMetered(t *testing.T) {
	for _, file := range []string{"serve.go", "worker.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		require.NoError(t, err)
		metered := 0
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			isMeter := false
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "llmUsage" && sel.Sel.Name == "Client" {
					isMeter = true
					metered++
				}
			}
			for _, arg := range call.Args {
				if id, ok := arg.(*ast.Ident); ok && id.Name == "llmClient" && !isMeter {
					t.Errorf("%s: llmClient passed raw to a call at %s — wrap it in llmUsage.Client(llmClient, <purpose>)",
						file, fset.Position(call.Pos()))
				}
			}
			return true
		})
		require.Positive(t, metered, "%s: no metered client at all — did the wiring move?", file)
	}
}
