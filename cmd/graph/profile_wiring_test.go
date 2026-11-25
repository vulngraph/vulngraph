package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// scan.ProfileService's last constructor argument is its ProfileJobEnqueuer, and
// TriggerProfileScan calls it unconditionally. A nil there is not a disabled
// feature, it is a panic — and a panic AFTER CreateRunForProfile has already
// inserted a `running` scan_runs row, so River recovers it into a job error and
// leaves a run nothing will ever finish.
//
// Only a pod that TRIGGERS runs needs one: serve (the profiles handler) and worker
// (the per-minute cron tick, Deps.ProfileSchedules). The scanner pod only executes
// runs, so nil is correct there and this test says so by name rather than by
// silence.
//
// The real fix belongs in internal/app/scan — NewProfileService should reject a nil
// enqueuer, or TriggerProfileScan should return a sentinel instead of panicking.
// This is the cmd/graph half: it guarantees the two triggering pods pass one.
func TestProfileServiceEnqueuerIsWired(t *testing.T) {
	triggersRuns := map[string]bool{
		"serve.go":   true,  // the profiles HTTP handler triggers on demand
		"worker.go":  true,  // ProfileScheduleWorker triggers on the cron tick
		"scanner.go": false, // executes runs only; never triggers one
	}

	for file, needsEnqueuer := range triggersRuns {
		t.Run(file, func(t *testing.T) {
			arg := profileServiceEnqueuerArg(t, file)
			if needsEnqueuer {
				require.NotEqualf(t, "nil", arg,
					"%s triggers profile runs, so scan.NewProfileService must get a real "+
						"ProfileJobEnqueuer: TriggerProfileScan calls it after the scan_runs row "+
						"is already inserted, so a nil leaves a run stuck `running` forever", file)
				return
			}
			require.Equalf(t, "nil", arg,
				"%s does not trigger profile runs; passing an enqueuer there would be a second, "+
					"unowned producer", file)
		})
	}
}

// profileServiceEnqueuerArg returns the source text of the 5th argument to the
// scan.NewProfileService call in file — "nil" or an expression.
func profileServiceEnqueuerArg(t *testing.T, file string) string {
	t.Helper()
	src, err := os.ReadFile(file)
	require.NoError(t, err)
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, src, 0)
	require.NoError(t, err)

	var arg string
	ast.Inspect(parsed, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "NewProfileService" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "scan" {
			return true
		}
		require.Lenf(t, call.Args, 5,
			"scan.NewProfileService signature changed — this guard reads argument 5 (the enqueuer)")
		start := fset.Position(call.Args[4].Pos()).Offset
		end := fset.Position(call.Args[4].End()).Offset
		arg = string(src[start:end])
		return false
	})
	require.NotEmptyf(t, arg, "no scan.NewProfileService call found in %s — did the wiring move?", file)
	return arg
}
