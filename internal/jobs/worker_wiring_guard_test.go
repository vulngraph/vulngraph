package jobs

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

// This guards a defect that should have been unrepresentable from the start:
// SyncWorker declared a `drift driftScanner` field, the field compiled,
// and registerRealWorkers' composite literal for &SyncWorker{...} simply never
// mentioned it — a struct-literal omission zero-values the field, which is
// indistinguishable from "deliberately disabled" to every existing test,
// because none of them read the field's absence as a fact worth checking.
//
// enqueueSites (below, TestEveryJobKindHasAProducer) catches a job kind with
// no producer ANYWHERE in the module — a coarser, complementary check. This
// one is narrower and catches the specific unwired-field shape: a worker
// struct whose OWN dependency field never got wired into the literal that
// actually constructs it, which enqueueSites cannot see (the literal, and everything it
// omits, is a fact about ONE type, not about whether some producer string
// exists anywhere in the module).
//
// Two halves, mirroring internal/policy/evidence_guard_test.go's design:
//  1. DECLARATION — every river.WorkerDefaults-embedding struct's non-embedded
//     fields are enumerated from source.
//  2. CONSUMPTION — the fullest `&WorkerName{...}` composite literal found
//     anywhere in this package's non-test source sets every one of them, or
//     the gap is named in workerFieldAllowlist with a reason.
func TestWorkerStructFieldsAreWiredAtConstruction(t *testing.T) {
	dir, err := os.Getwd()
	require.NoError(t, err)

	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		files[path] = f
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, files, "found no non-test source files in %s — the walk is broken", dir)

	structs := workerStructFields(files)
	require.NotEmpty(t, structs, "found no river.WorkerDefaults-embedding structs — the AST walk is broken")

	coverage := bestFieldCoverage(files, structs)

	for name, fields := range structs {
		if len(fields) == 0 {
			// Nothing to wire (e.g. rescueOnlyWorker[T] — WorkerDefaults only,
			// and a generic type's composite literal has an *ast.IndexExpr Type
			// this scan does not match anyway). This guard exists to catch an
			// unwired FIELD; a struct with none has nothing this check can say.
			continue
		}
		t.Run(name, func(t *testing.T) {
			best, found := coverage[name]
			require.Truef(t, found,
				"%s embeds river.WorkerDefaults but no &%s{...} composite literal was found anywhere in "+
					"this package's non-test source — nothing constructs it, so it can never run.", name, name)
			for _, field := range fields {
				if best[field] {
					continue
				}
				reason, allowed := workerFieldAllowlist[name+"."+field]
				require.Truef(t, allowed,
					"%s.%s is never set by any &%s{...} literal in this package. If this is deliberate "+
						"(the field is genuinely optional and nil-safe on every construction path), add "+
						"%q to workerFieldAllowlist with the reason. Otherwise this is the unwired-field defect: a "+
						"field that compiles and reads as wired while nothing ever assigns it.",
					name, field, name, name+"."+field)
				_ = reason
			}
		})
	}
}

// workerFieldAllowlist names fields a worker struct declares but that no
// single construction site sets — because the field is genuinely optional
// everywhere the worker is built, not because wiring it was missed. Add an
// entry only with a reason that would survive a skeptical reading — this
// list is the declaration that a gap here is deliberate, so a false entry
// defeats the guard as thoroughly as removing it would.
var workerFieldAllowlist = map[string]string{
	// Injectable clock fields, each with its own w.<field> != nil fallback to
	// time.Now() at the one call site that reads them (see clock()/nowFn in
	// each file) — overridden only by tests that need to avoid sleeping/pin a
	// cutoff. The real registration literal in client.go deliberately leaves
	// them unset to get that default.
	"ProfileScheduleWorker.now":     "nil-safe injectable clock, defaults to time.Now() — see Work's nowFn fallback",
	"SavedQueryWorker.now":          "nil-safe injectable clock, defaults to time.Now() — see Work's nowFn fallback",
	"ReenrichWorker.clock":          "nil-safe injectable clock, defaults to time.Now() — see clock()'s nil check",
	"KEVWorker.now":                 "nil-safe injectable clock, defaults to time.Now() — see clock()'s nil check",
	"DiskScanPlanWorker.now":        "nil-safe injectable clock, defaults to time.Now() — see clock()",
	"DiskScanSweepWorker.now":       "nil-safe injectable clock, defaults to time.Now() — see clock()",
	"DiskScanVolumeWorker.now":      "nil-safe injectable clock, defaults to time.Now() — see clock()",
	"DiskScanVolumeWorker.scanDisk": "nil-safe injectable disk reader, defaults to engine.ScanDisk; only tests replace it",
}

// workerStructFields returns, for every struct in files that embeds
// river.WorkerDefaults[...], its non-embedded field names.
func workerStructFields(files map[string]*ast.File) map[string][]string {
	out := map[string][]string{}
	for _, f := range files {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || !embedsWorkerDefaults(st) {
					continue
				}
				var fields []string
				for _, fld := range st.Fields.List {
					if len(fld.Names) == 0 {
						continue // the embedded river.WorkerDefaults field itself
					}
					for _, n := range fld.Names {
						fields = append(fields, n.Name)
					}
				}
				sort.Strings(fields)
				out[ts.Name.Name] = fields
			}
		}
	}
	return out
}

// embedsWorkerDefaults reports whether st has an embedded river.WorkerDefaults[...] field.
func embedsWorkerDefaults(st *ast.StructType) bool {
	for _, fld := range st.Fields.List {
		if len(fld.Names) != 0 {
			continue // not embedded
		}
		idx, ok := fld.Type.(*ast.IndexExpr)
		if !ok {
			continue
		}
		sel, ok := idx.X.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if ok && pkgIdent.Name == "river" && sel.Sel.Name == "WorkerDefaults" {
			return true
		}
	}
	return false
}

// bestFieldCoverage scans files for every `&StructName{...}` composite literal
// (StructName a key of structs) and returns, per struct, the largest set of
// keyed field names any single occurrence assigns. A literal with any
// non-keyed (positional) element is skipped — this package's worker structs
// are never built positionally, and a positional literal's coverage can't be
// read from its Elts without also matching field order to the declaration.
func bestFieldCoverage(files map[string]*ast.File, structs map[string][]string) map[string]map[string]bool {
	best := map[string]map[string]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			ident, ok := cl.Type.(*ast.Ident)
			if !ok {
				return true
			}
			if _, known := structs[ident.Name]; !known {
				return true
			}
			keys := map[string]bool{}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					return true // positional — skip this occurrence entirely
				}
				if k, ok := kv.Key.(*ast.Ident); ok {
					keys[k.Name] = true
				}
			}
			if len(keys) > len(best[ident.Name]) {
				best[ident.Name] = keys
			}
			return true
		})
	}
	return best
}
