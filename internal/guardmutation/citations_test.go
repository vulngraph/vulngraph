package guardmutation

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// citedTestName matches a test-shaped name in a comment. A trailing "*" cites
// every function with that prefix.
var citedTestName = regexp.MustCompile(`\bTest[A-Z0-9]\w*\*?`)

// placeholderTestNames are cited as the shape of a name, not as a function.
var placeholderTestNames = map[string]bool{"TestX": true, "TestXxx": true}

// TestEveryCitedTestExists keeps comments honest about what enforces them. A
// comment naming the test that pins an invariant is how a reader decides the
// invariant is guarded; if that test was never written, or was renamed,
// nothing guards it and the comment says otherwise. Every Test-shaped name in a Go comment must be a
// function or method declared somewhere in the module (production methods
// named Test... count; build-tagged files count).
func TestEveryCitedTestExists(t *testing.T) {
	declared := map[string]bool{}
	type citation struct{ pos, name string }
	var cites []citation

	root := moduleRoot(t)
	fset := token.NewFileSet()
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if perr != nil {
			return perr
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && strings.HasPrefix(fn.Name.Name, "Test") {
				declared[fn.Name.Name] = true
			}
		}
		rel, _ := filepath.Rel(root, path)
		for _, group := range file.Comments {
			for _, c := range group.List {
				for _, name := range citedTestName.FindAllString(c.Text, -1) {
					pos := fmt.Sprintf("%s:%d", rel, fset.Position(c.Pos()).Line)
					cites = append(cites, citation{pos: pos, name: name})
				}
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, declared, "no test functions parsed — the walk is broken")
	require.NotEmpty(t, cites, "no citations found — the comment scan is broken")

	resolves := func(name string) bool {
		if prefix, wild := strings.CutSuffix(name, "*"); wild {
			for d := range declared {
				if strings.HasPrefix(d, prefix) {
					return true
				}
			}
			return false
		}
		return declared[name] || placeholderTestNames[name]
	}
	var dangling []string
	for _, c := range cites {
		if !resolves(c.name) {
			dangling = append(dangling, c.pos+" cites "+c.name)
		}
	}
	sort.Strings(dangling)
	require.Emptyf(t, dangling,
		"comment(s) cite a test no file declares:\n  %s\n\nWrite the test so it guards what the comment says, "+
			"or remove the citation.", strings.Join(dangling, "\n  "))
}
