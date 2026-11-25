package collect

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// completenessField is the field a false claim would be written to.
const completenessField = "CompletedEnumerations"

// writerFile/writerFunc are the ONLY place allowed to write it.
const (
	writerFile = "internal/collect/collect.go"
	writerFunc = "MarkComplete"
)

// TestCompletedEnumerationsHaveASingleWriter enforces that
// Result.CompletedEnumerations — the input sync deletion reconciliation
// deletes real inventory on — is only ever set through MarkComplete, where a
// claim is validated (non-empty scope, at least one non-empty type,
// non-negative count) before it becomes coverage. A hand-rolled
// `res.CompletedEnumerations = append(...)` elsewhere compiles and looks
// ordinary but bypasses that validation, so the write path is checked
// structurally rather than left to review. Reads are unrestricted; only
// writes are, and test files (which build a Result by hand on purpose) are
// excluded from the scan.
func TestCompletedEnumerationsHaveASingleWriter(t *testing.T) {
	root := completenessModuleRoot(t)
	var offenders []string

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "frontend", "third_party", "build":
				return filepath.SkipDir
			}
			// Other dot-dirs too, as the go tool does — nested checkouts (e.g.
			// git worktrees under dot-directories) hold whole copies of the module.
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
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
		for _, fn := range writesTo(file, completenessField) {
			if filepath.ToSlash(rel) == writerFile && fn == writerFunc {
				continue
			}
			offenders = append(offenders, filepath.ToSlash(rel)+": "+fn)
		}
		return nil
	})
	require.NoError(t, err)

	require.Emptyf(t, offenders,
		"%s is written outside %s.%s:\n  %s\n\n"+
			"Route the write through MarkComplete. It is the only place a completeness claim is validated, "+
			"and an unvalidated claim is the single input a future enforce mode would delete inventory on.",
		completenessField, writerFile, writerFunc, strings.Join(offenders, "\n  "))
}

// writesTo returns the names of the functions in file that ASSIGN to a field
// named field (directly, or by taking its address). Plain reads are ignored.
func writesTo(file *ast.File, field string) []string {
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range v.Lhs {
					if selectsField(lhs, field) {
						out = append(out, fn.Name.Name)
					}
				}
			case *ast.UnaryExpr:
				if v.Op == token.AND && selectsField(v.X, field) {
					out = append(out, fn.Name.Name)
				}
			}
			return true
		})
	}
	return out
}

func selectsField(e ast.Expr, field string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == field
}

// completenessModuleRoot walks up to the directory holding go.mod.
func completenessModuleRoot(t *testing.T) string {
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
