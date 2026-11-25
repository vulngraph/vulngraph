package safenet_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// clientGuardSkippedDirs are trees this guard does not own or cannot parse as first-party Go.
var clientGuardSkippedDirs = map[string]bool{
	".git": true, "third_party": true, "vendor": true, "node_modules": true, "frontend": true,
}

// TestNoHTTPClientConstructedOutsideSafenet keeps every outbound client behind
// the safenet factories. A hand-built http.Client has no SSRF dial guard and,
// unless someone remembers, no timeout. golangci-lint cannot express this ban:
// forbidigo matches identifiers and selectors, so it would flag every
// `*http.Client` parameter along with the constructions. This walks the module
// and flags each `http.Client{...}` literal and `new(http.Client)` in non-test
// Go outside pkg/safenet.
func TestNoHTTPClientConstructedOutsideSafenet(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()

	var (
		offenders []string
		parsed    int
	)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if clientGuardSkippedDirs[d.Name()] || (path != root && strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if strings.HasPrefix(filepath.ToSlash(rel), "pkg/safenet/") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		parsed++
		for _, pos := range httpClientConstructions(file) {
			offenders = append(offenders, fset.Position(pos).String())
		}
		return nil
	})
	require.NoError(t, err)
	require.NotZero(t, parsed, "no Go files parsed — did the repo layout change?")

	sort.Strings(offenders)
	require.Emptyf(t, offenders,
		"http.Client constructed outside pkg/safenet:\n  %s\n\nUse safenet.New(timeout) for user- or "+
			"connector-supplied URLs, safenet.NewInternal(timeout) for trusted internal ones, or "+
			"safenet.NewWithTransport when the transport chain already carries the SSRF guard.",
		strings.Join(offenders, "\n  "))
}

func TestHTTPClientConstructions(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"pointer literal", `import "net/http"; var c = &http.Client{}`, 1},
		{"value literal", `import "net/http"; var c = http.Client{Timeout: 1}`, 1},
		{"new", `import "net/http"; var c = new(http.Client)`, 1},
		{"aliased import", `import h "net/http"; var c = &h.Client{}`, 1},
		{"dot import", `import . "net/http"; var c = &Client{}`, 1},
		{"parameter type only", `import "net/http"; func f(c *http.Client) {}`, 0},
		{"zero-value declaration", `import "net/http"; var c *http.Client`, 0},
		{"other package Client", `import "example.com/http"; var c = &http.Client{}`, 0},
		{"no net/http import", `type Client struct{}; var c = &Client{}`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x; "+tc.src, parser.SkipObjectResolution)
			require.NoError(t, err)
			require.Len(t, httpClientConstructions(file), tc.want)
		})
	}
}

// httpClientConstructions returns the position of each http.Client literal or
// new(http.Client) in file, resolving the name net/http is imported under.
func httpClientConstructions(file *ast.File) []token.Pos {
	httpName := ""
	for _, imp := range file.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != "net/http" {
			continue
		}
		httpName = "http"
		if imp.Name != nil {
			httpName = imp.Name.Name
		}
	}
	if httpName == "" || httpName == "_" {
		return nil
	}
	isClient := func(e ast.Expr) bool {
		if httpName == "." {
			id, ok := e.(*ast.Ident)
			return ok && id.Name == "Client"
		}
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Client" {
			return false
		}
		x, ok := sel.X.(*ast.Ident)
		return ok && x.Name == httpName
	}

	var out []token.Pos
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CompositeLit:
			if v.Type != nil && isClient(v.Type) {
				out = append(out, v.Pos())
			}
		case *ast.CallExpr:
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "new" && len(v.Args) == 1 && isClient(v.Args[0]) {
				out = append(out, v.Pos())
			}
		}
		return true
	})
	return out
}
