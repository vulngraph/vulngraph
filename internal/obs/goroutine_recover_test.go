package obs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// knownUnrecoveredGoroutines is the ratchet: the files that still spawn a
// goroutine with no deferred recover. It is keyed by FILE, not line, so it
// survives unrelated edits to those files, and it only ever shrinks — a new
// unrecovered goroutine anywhere in the repo fails this test.
//
// Fixing one of these is a change to another domain's error handling (both need
// a decision about what the surviving parent should do when a worker dies
// mid-fan-out), so they are recorded rather than silently tolerated. Delete the
// entry when you wrap the goroutine. The list is empty and must stay that way.
var knownUnrecoveredGoroutines = map[string]bool{}

// skippedDirs are trees this guard does not own or cannot parse as first-party Go.
var skippedDirs = map[string]bool{
	".git": true, "third_party": true, "vendor": true, "node_modules": true, "frontend": true,
}

// TestNoUnrecoveredGoroutines_RepoWide is the repo-wide half of the goroutine
// guard. cmd/graph/safego_test.go has the same invariant but reads only its own
// directory, so it is structurally blind to every goroutine in internal/ —
// which is where most of them live.
//
// The invariant is the same and the reason is the platform's shape: this is a
// single Go binary, so an unrecovered panic in any background goroutine kills the
// whole pod — a restart loop, not a degraded subsystem. cmd/graph satisfies it via
// its safego helper; library packages cannot use that (it is package main), so
// they open the goroutine body with a deferred recover instead. Both forms are
// accepted here.
//
// This test lives in obs because obs is the cross-cutting process-health package
// and the guard is a process-health invariant; it walks from the repo root, so it
// is not scoped to this directory the way the cmd/graph one is.
func TestNoUnrecoveredGoroutines_RepoWide(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()

	var (
		offenders []string
		checked   int
	)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] || (path != root && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		helpers := recoverHelpers(file)

		ast.Inspect(file, func(n ast.Node) bool {
			g, ok := n.(*ast.GoStmt)
			if !ok {
				return true
			}
			checked++
			if knownUnrecoveredGoroutines[rel] {
				return true
			}
			lit, ok := g.Call.Fun.(*ast.FuncLit)
			if !ok || !goroutineGuarded(lit, helpers) {
				offenders = append(offenders, fset.Position(g.Pos()).String())
			}
			return true
		})
		return nil
	})
	require.NoError(t, err)
	require.NotZero(t, checked, "no `go` statements parsed — did the repo layout change?")

	sort.Strings(offenders)
	require.Emptyf(t, offenders,
		"goroutine(s) spawned with no deferred recover:\n  %s\n\nThis is a single-binary process: an "+
			"unrecovered panic in a background goroutine kills the whole pod. Open the body with a "+
			"deferred recover that logs the panic (cmd/graph may use safego instead).",
		strings.Join(offenders, "\n  "))
}

// goroutineGuarded reports whether lit's body starts with a run of defer
// statements, one of which calls recover(). A recover placed after any other
// statement is not a guard — a panic in the statements before it is unrecovered —
// so only a leading run of defers counts. That admits the common
// `defer wg.Done(); defer func(){ recover() }()` pairing, which cmd/graph's
// stricter first-statement-only check would reject.
//
// helpers names same-file functions whose own body recovers, so
// `defer recoverSignal("x")` counts as a guard — internal/jobs/enrich.go spawns
// three goroutines that share one such closure, and reading only the defer's own
// syntax reported all three as unguarded.
func goroutineGuarded(lit *ast.FuncLit, helpers map[string]bool) bool {
	if lit.Body == nil {
		return false
	}
	for _, st := range lit.Body.List {
		d, ok := st.(*ast.DeferStmt)
		if !ok {
			return false // reached real work without having registered a recover
		}
		if callsRecover(d) {
			return true
		}
		if id, ok := d.Call.Fun.(*ast.Ident); ok && helpers[id.Name] {
			return true
		}
	}
	return false
}

// callsRecover reports whether n contains a reference to the builtin recover.
func callsRecover(n ast.Node) bool {
	var found bool
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "recover" {
			found = true
		}
		return !found
	})
	return found
}

// recoverHelpers returns the names declared in file that recover when called:
// top-level funcs and func-literals bound to a name (`x := func(){…}`, `var x =
// func(){…}`). Only names from the SAME file count — this guard is syntactic, it
// does not type-check, and a cross-file match on a bare name would be a guess.
func recoverHelpers(file *ast.File) map[string]bool {
	helpers := map[string]bool{}
	record := func(name string, body ast.Node) {
		if name != "" && name != "_" && body != nil && callsRecover(body) {
			helpers[name] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Body != nil {
				record(d.Name.Name, d.Body)
			}
		case *ast.AssignStmt:
			for i, lhs := range d.Lhs {
				if i >= len(d.Rhs) {
					break
				}
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				if fn, ok := d.Rhs[i].(*ast.FuncLit); ok {
					record(id.Name, fn.Body)
				}
			}
		case *ast.ValueSpec:
			for i, name := range d.Names {
				if i >= len(d.Values) {
					break
				}
				if fn, ok := d.Values[i].(*ast.FuncLit); ok {
					record(name.Name, fn.Body)
				}
			}
		}
		return true
	})
	return helpers
}

// TestGoroutineGuardedForms pins what the guard accepts and rejects. Without it
// the ratchet above can only say "no offenders", which an over-permissive rule
// also says.
func TestGoroutineGuardedForms(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		guarded bool
	}{
		{
			name:    "inline recover in leading defers",
			src:     "package p\nfunc f() { go func() { defer wg.Done(); defer func() { recover() }(); work() }() }",
			guarded: true,
		},
		{
			name:    "shared recover helper declared in the same file",
			src:     "package p\nfunc f() { rec := func() { recover() }; go func() { defer wg.Done(); defer rec(); work() }() }",
			guarded: true,
		},
		{
			name:    "top-level recover helper",
			src:     "package p\nfunc rec() { recover() }\nfunc f() { go func() { defer rec(); work() }() }",
			guarded: true,
		},
		{
			name:    "recover registered after a non-defer statement",
			src:     "package p\nfunc f() { go func() { defer wg.Done(); sem <- struct{}{}; defer func() { recover() }(); work() }() }",
			guarded: false,
		},
		{
			name:    "helper that does not recover",
			src:     "package p\nfunc rel() { <-sem }\nfunc f() { go func() { defer rel(); work() }() }",
			guarded: false,
		},
		{
			name:    "no defers at all",
			src:     "package p\nfunc f() { go func() { work() }() }",
			guarded: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "x.go", tc.src, 0)
			require.NoError(t, err)
			helpers := recoverHelpers(file)

			var got, seen bool
			ast.Inspect(file, func(n ast.Node) bool {
				g, ok := n.(*ast.GoStmt)
				if !ok {
					return true
				}
				lit, ok := g.Call.Fun.(*ast.FuncLit)
				require.True(t, ok)
				got, seen = goroutineGuarded(lit, helpers), true
				return false
			})
			require.True(t, seen, "no go statement in fixture")
			require.Equal(t, tc.guarded, got)
		})
	}
}
