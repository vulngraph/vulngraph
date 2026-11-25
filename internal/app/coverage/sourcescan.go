package coverage

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// skipDirs are trees with no Go finding producers in them.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "frontend": true,
	"third_party": true, "vendor": true, "web": true, "docs": true,
}

// DeclaredSources derives, from the AST of the tree rooted at dir, every
// finding source string the code is capable of producing.
//
// A hand-kept list of "sources we have" is exactly the artefact this package
// exists to abolish: it is how `burp`, `nessus`, `openvas` and `qualys` stayed
// in a mental model as "covered" while never having emitted a single row. Two rules produce the set, and both are mechanical:
//
//   - a `finding.Finding` composite literal whose Source field is a string
//     literal, or an identifier the same file assigns a string literal to
//     (constant, variable or local alike) — the direct producers;
//   - a package-level `map[string]bool` variable whose name ends in `Sources` —
//     how the external-scanner import allowlist is expressed, where the Source
//     value reaching the finding is a request field rather than a literal.
//
// Test files are excluded: a source that only exists in a fixture is not a
// source the platform can produce.
func DeclaredSources(dir string) ([]string, error) {
	found := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Hidden dirs (.git, nested worktrees) hold copies of the tree, not sources
		// this binary declares.
		if d.IsDir() {
			if skipDirs[d.Name()] || (path != dir && strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if scanErr := scanFileSources(path, found); scanErr != nil {
			return fmt.Errorf("DeclaredSources: %w", scanErr)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("DeclaredSources: walk %s: %w", dir, err)
	}
	out := make([]string, 0, len(found))
	for s := range found {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

func scanFileSources(path string, found map[string]bool) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		// An unparseable file is a build failure elsewhere; it must not silently
		// shrink the declared set, so it is reported.
		return fmt.Errorf("parse %s: %w", path, err)
	}
	idents := stringIdents(file)
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CompositeLit:
			if isFindingLit(v.Type) {
				collectSourceField(v, idents, found)
			}
		case *ast.GenDecl:
			collectSourceAllowlists(v, found)
		}
		return true
	})
	return nil
}

// stringIdents indexes every identifier in a file that is ever assigned a
// string literal — package constants, variable declarations and local
// assignments alike — so `Source: source` resolves as reliably as
// `Source: "cspm"`.
//
// Locals matter: the nuclei source is `source := r.Scanner; if source == "" {
// source = "nuclei" }`, so a const-only resolver reports the platform's
// longest-running scanner as undeclared. An identifier assigned several
// literals contributes all of them. The scan therefore over-approximates
// rather than under-approximates, which is the safe direction: a source named
// here that cannot really be produced shows up as "declared, never fired" and
// is visible; a source omitted here is invisible, which is the failure this
// package exists to end.
func stringIdents(file *ast.File) map[string][]string {
	out := map[string][]string{}
	add := func(name string, e ast.Expr) {
		if s, ok := stringLit(e); ok {
			out[name] = appendUnique(out[name], s)
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.ValueSpec:
			for i, name := range v.Names {
				if i < len(v.Values) {
					add(name.Name, v.Values[i])
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range v.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(v.Rhs) {
					continue
				}
				add(id.Name, v.Rhs[i])
			}
		}
		return true
	})
	return out
}

// isFindingLit reports whether a composite literal is a finding.Finding — the
// only struct whose Source field reaches the findings table. Filters, beliefs
// and webhook payloads also carry a Source field and must not be counted.
func isFindingLit(t ast.Expr) bool {
	switch v := t.(type) {
	case *ast.SelectorExpr:
		pkg, ok := v.X.(*ast.Ident)
		return ok && pkg.Name == "finding" && v.Sel.Name == "Finding"
	case *ast.Ident:
		return v.Name == "Finding"
	}
	return false
}

func collectSourceField(lit *ast.CompositeLit, idents map[string][]string, found map[string]bool) {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Source" {
			continue
		}
		if s, ok := stringLit(kv.Value); ok {
			found[s] = true
			continue
		}
		if id, ok := kv.Value.(*ast.Ident); ok {
			for _, s := range idents[id.Name] {
				found[s] = true
			}
		}
	}
}

// collectSourceAllowlists picks up `var xxxSources = map[string]bool{...}` — the
// external-scanner import allowlist shape, where the Source that lands on the
// finding is a validated request field and so is never a literal at the
// construction site.
func collectSourceAllowlists(gd *ast.GenDecl, found map[string]bool) {
	if gd.Tok != token.VAR {
		return
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range vs.Names {
			if !strings.HasSuffix(name.Name, "Sources") || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.CompositeLit)
			if !ok || !isStringBoolMap(lit.Type) {
				continue
			}
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if s, ok := stringLit(kv.Key); ok {
					found[s] = true
				}
			}
		}
	}
}

func isStringBoolMap(t ast.Expr) bool {
	m, ok := t.(*ast.MapType)
	if !ok {
		return false
	}
	k, kok := m.Key.(*ast.Ident)
	v, vok := m.Value.(*ast.Ident)
	return kok && vok && k.Name == "string" && v.Name == "bool"
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, s != ""
}
