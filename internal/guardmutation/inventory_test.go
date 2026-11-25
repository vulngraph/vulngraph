package guardmutation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// structuralMarkers are the calls that make a test a source-reading structural
// guard: it derives its expectation from the repository itself rather than from
// a fixture the test wrote. Everything in the mechanically-discoverable half of
// the inventory is found through one of these.
var structuralMarkers = map[string]bool{
	"parser.ParseFile": true,
	"filepath.WalkDir": true,
	"filepath.Walk":    true,
	"os.ReadDir":       true,
	"packages.Load":    true,
	"os.ReadFile":      true,
	"moduleRoot":       true,
}

// skippedDirs are trees this inventory does not own.
var skippedDirs = map[string]bool{
	".git": true, "third_party": true, "vendor": true, "node_modules": true, "frontend": true, "build": true,
}

// TestEveryDiscoveredGuardIsMutatedOrExempt keeps a new guard from being added
// without this harness noticing it.
//
// It walks the module for test functions that read the repository's own source
// (see structuralMarkers), adds the hand-listed registry-iterating guards, and
// requires every one of them to be either in the mutation catalogue or in
// `exempt` with a stated reason. It runs untagged on purpose: the mutation
// driver edits the working tree and must stay opt-in, but the decision it
// enforces must not.
func TestEveryDiscoveredGuardIsMutatedOrExempt(t *testing.T) {
	covered := map[string]bool{}
	for _, m := range mutations {
		covered[m.Guard] = true
	}

	discovered := discoverGuards(t)
	discovered = append(discovered, extraGuards...)

	var missing []string
	for _, g := range discovered {
		if covered[g] {
			continue
		}
		if _, ok := exempt[g]; ok {
			continue
		}
		missing = append(missing, g)
	}
	sort.Strings(missing)
	require.Emptyf(t, missing,
		"structural guard(s) with no mutation and no exemption:\n  %s\n\n"+
			"A guard's existence is no evidence it guards anything — two in this repo passed with their own bug "+
			"fully reintroduced. Add a row to `mutations` that reintroduces the bug the guard exists to prevent, "+
			"or an entry in `exempt` saying why a text substitution cannot express it.",
		strings.Join(missing, "\n  "))
}

// TestCatalogueHasNoStaleEntries keeps the catalogue from rotting the other
// way: a mutation naming a guard that no longer exists exempts nothing and
// hides the next real gap, and an exemption for a deleted test is dead weight.
func TestCatalogueHasNoStaleEntries(t *testing.T) {
	all := map[string]bool{}
	for _, name := range allTestFuncNames(t) {
		all[name] = true
	}
	require.NotEmpty(t, all, "no test functions parsed — the walk is broken")

	for _, m := range mutations {
		require.Truef(t, all[m.Guard], "mutation names guard %q, which no test declares", m.Guard)
		require.NotEmptyf(t, m.Why, "mutation for %q states no reason", m.Guard)
		require.NotEqualf(t, m.Old, m.New, "mutation for %q is a no-op", m.Guard)
	}
	for name, reason := range exempt {
		require.Truef(t, all[name], "exempt names %q, which no test declares", name)
		require.NotEmptyf(t, reason, "exemption for %q states no reason", name)
	}
	for _, name := range extraGuards {
		require.Truef(t, all[name], "extraGuards names %q, which no test declares", name)
	}
}

// TestEveryMutationTargetsRealText proves each mutation still describes the
// tree it was written against — WITHOUT modifying anything. A rotted Old string
// would otherwise surface only as a mutation the harness could not apply, which
// is one hop away from a mutation quietly skipped.
func TestEveryMutationTargetsRealText(t *testing.T) {
	root := moduleRoot(t)
	for _, m := range mutations {
		t.Run(m.Guard, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(root, m.File))
			require.NoErrorf(t, err, "mutation for %s targets a file that does not exist", m.Guard)
			require.Equalf(t, 1, strings.Count(string(src), m.Old),
				"mutation for %s must match %s exactly once (found %d) — the source moved; update the row",
				m.Guard, m.File, strings.Count(string(src), m.Old))
			require.Equalf(t, strings.HasSuffix(m.File, "_test.go"), m.MutatesTest,
				"mutation for %s: MutatesTest must state whether it edits a test file", m.Guard)
		})
	}
}

// discoverGuards returns the names of test functions that read this
// repository's own source. Helpers are resolved transitively across every test
// file of the same package directory, because the guards in this tree
// consistently push the AST walk into a helper (parsePackage,
// scanAssetsColumns, adjacent), often one declared in a sibling file.
func discoverGuards(t *testing.T) []string {
	t.Helper()

	pkgs := map[string]map[string]*ast.FuncDecl{} // dir + package name → func name → decl
	forEachTestFileIn(t, func(path string, file *ast.File) {
		key := filepath.Dir(path) + "\x00" + file.Name.Name
		if pkgs[key] == nil {
			pkgs[key] = map[string]*ast.FuncDecl{}
		}
		for _, d := range file.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
				pkgs[key][fn.Name.Name] = fn
			}
		}
	})
	var out []string
	for _, bodies := range pkgs {
		for name, fn := range bodies {
			if strings.HasPrefix(name, "Test") && readsRepoSource(fn, bodies, map[string]bool{}) {
				out = append(out, name)
			}
		}
	}
	require.NotEmpty(t, out, "discovered no source-reading guards — the walk is broken")
	return out
}

// readsRepoSource reports whether fn, or any same-package test helper it
// reaches, invokes a structural marker.
func readsRepoSource(fn *ast.FuncDecl, samePkg map[string]*ast.FuncDecl, visited map[string]bool) bool {
	visited[fn.Name.Name] = true
	if callsMarker(fn) {
		return true
	}
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if helper, ok := samePkg[id.Name]; ok && !visited[id.Name] && readsRepoSource(helper, samePkg, visited) {
			found = true
		}
		return !found
	})
	return found
}

func callsMarker(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if name := calleeName(call.Fun); name != "" && structuralMarkers[name] {
			found = true
		}
		return !found
	})
	return found
}

func calleeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if pkg, ok := v.X.(*ast.Ident); ok {
			return pkg.Name + "." + v.Sel.Name
		}
		return v.Sel.Name
	case *ast.IndexExpr: // generic helper call
		return calleeName(v.X)
	}
	return ""
}

// allTestFuncNames returns every `func TestXxx` declared in the module.
func allTestFuncNames(t *testing.T) []string {
	t.Helper()
	var out []string
	forEachTestFile(t, func(file *ast.File) {
		for _, d := range file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				out = append(out, fn.Name.Name)
			}
		}
	})
	return out
}

// forEachTestFile parses every _test.go in the module, including build-tagged
// ones — a guard behind `integration` is still a guard.
func forEachTestFile(t *testing.T, visit func(file *ast.File)) {
	t.Helper()
	forEachTestFileIn(t, func(_ string, file *ast.File) { visit(file) })
}

// forEachTestFileIn is forEachTestFile with each file's path.
func forEachTestFileIn(t *testing.T, visit func(path string, file *ast.File)) {
	t.Helper()
	root := moduleRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Dot-dirs too (as the go tool does): nested checkouts (e.g. git
			// worktrees under dot-directories) would otherwise be scanned as module code.
			if skippedDirs[d.Name()] || (path != root && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		visit(path, file)
		return nil
	})
	require.NoError(t, err)
}

// moduleRoot walks up from the working directory to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqualf(t, dir, parent, "go.mod not found above %s", dir)
		dir = parent
	}
}
