package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/obs"
)

// TestExecutorIsWiredWithAudit and its suppress counterpart guard against a
// service whose doc comment promises "every write is audited" while its
// actual construction site never calls .WithAudit(...). The audit sink is an
// option rather than a constructor argument so non-HTTP construction sites
// keep compiling, which means a wiring that forgets it fails silently and
// looks identical to one that does not.
//
// The check walks the syntax tree rather than regexing the source text, so it
// cannot be fooled by a constructor call gofmt splits across lines: for every
// call to <pkg>.NewService anywhere in the file, is that call the receiver of
// a .WithAudit(...) selector, at any nesting depth?
func TestExecutorIsWiredWithAudit(t *testing.T) {
	assertAllConstructionsAudited(t, "serve.go", "executor", "NewService")
}

func TestSuppressIsWiredWithAudit(t *testing.T) {
	for _, file := range []string{"serve.go", "worker.go"} {
		assertAllConstructionsAudited(t, file, "suppress", "NewService")
	}
}

// Every admin-action service serve builds writes audit_events rows: sign-in,
// users, API keys, connectors, alert channels, the approval policy, manual
// finding resolves, saved queries and scan profiles. The `graph user`
// commands are audited the same way.
func TestAdminServicesAreWiredWithAudit(t *testing.T) {
	for _, pkg := range []string{"auth", "apikey", "connector", "notify", "policy", "finding", "savedquery"} {
		assertAllConstructionsAudited(t, "serve.go", pkg, "NewService")
	}
	assertAllConstructionsAudited(t, "serve.go", "scan", "NewProfileService")
	assertAllConstructionsAudited(t, "user.go", "auth", "NewService")
}

// A scan a person starts from the API writes a scan.start or
// scan.profile_start row. Only serve takes those requests; the worker and
// scanner pods build the scan services without audit because no person
// starts anything there.
func TestScanStartsAreWiredWithAudit(t *testing.T) {
	assertAllConstructionsAudited(t, "serve.go", "scan", "NewService")
	assertAllConstructionsAudited(t, "serve.go", "scan", "NewProfileService")
}

// assertAllConstructionsAudited fails when any <pkg>.<ctor>(...) call in file is
// not wrapped in .WithAudit(...).
func assertAllConstructionsAudited(t *testing.T, file, pkg, ctor string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	require.NoError(t, err)

	// Every call expression that is the receiver of a `.WithAudit(...)` call.
	audited := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "WithAudit" {
			return true
		}
		// sel.X is whatever WithAudit was called on — the constructor call, or
		// another option in a chain. Mark the whole receiver subtree: an option
		// chained before WithAudit must not hide the constructor from us.
		ast.Inspect(sel.X, func(inner ast.Node) bool {
			audited[inner] = true
			return true
		})
		return true
	})

	var found int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != ctor {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != pkg {
			return true
		}
		found++
		require.Truef(t, audited[call],
			"%s.%s at %s is constructed without .WithAudit(...) — every human-triggered write must reach audit_events",
			pkg, ctor, fset.Position(call.Pos()))
		return true
	})
	require.NotZerof(t, found, "no %s.%s construction found in %s — did the wiring move?", pkg, ctor, file)
}

// TestObsSourcesAreAllWired guards against a field added to obs.Sources that
// never gets populated in registerMetricsSources' obs.Sources{...} literal,
// which would leave its metric permanently dark with nothing to notice.
// internal/obs/metrics_test.go and alerts_test.go both build their own
// in-package Sources{} literals, which proves the emission machinery works
// but can never catch cmd/graph forgetting to populate a field — this test
// reads the actual literal cmd/graph constructs instead.
func TestObsSourcesAreAllWired(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "worker_metrics.go", nil, 0)
	require.NoError(t, err)

	wired := map[string]bool{}
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RegisterSources" || len(call.Args) != 1 {
			return true
		}
		lit, ok := call.Args[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		found = true
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			id, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			// A field set to the literal nil identifier compiles cleanly (every
			// obs.Sources field is a func type, which is nilable) but never emits —
			// the exact same dark-metric failure mode this guard exists to catch,
			// just spelled `Field: nil,` instead of an absent key. Checking key
			// presence alone would call that "wired". This only catches the literal bare identifier
			// `nil` — a variable that HOLDS nil (e.g. `Field: maybeNilFunc,`) is not
			// statically decidable here and is out of scope for an AST guard.
			if value, ok := kv.Value.(*ast.Ident); ok && value.Name == "nil" {
				continue
			}
			wired[id.Name] = true
		}
		return true
	})
	require.True(t, found, "no metrics.RegisterSources(obs.Sources{...}) call found in worker_metrics.go — did the wiring move?")

	sourcesType := reflect.TypeOf(obs.Sources{})
	var missing []string
	for i := range sourcesType.NumField() {
		name := sourcesType.Field(i).Name
		if !wired[name] {
			missing = append(missing, name)
		}
	}
	require.Emptyf(t, missing,
		"obs.Sources field(s) %v declared but never set in registerMetricsSources' obs.Sources{...} literal in "+
			"worker_metrics.go — that metric will never emit, and any alert reading it can never fire (this is "+
			"exactly the bug GraphSourceActivityMetricAbsent existed to catch for SourceActivity)", missing)
}
