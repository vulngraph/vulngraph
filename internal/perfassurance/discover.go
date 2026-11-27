// Package perfassurance reconciles the performance inventory with shipped code.
package perfassurance

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Entry identifies a registered operation or production service module.
type Entry struct {
	ID     string `json:"id"`
	Source string `json:"source"`
}

// Discover includes optional registrations. Module entries keep direct-call
// service families visible even when there is no central service registry.
func Discover(root string) ([]Entry, error) {
	entries := map[string]Entry{}
	add := func(kind, name, source string) { entries[kind+":"+name] = Entry{kind + ":" + name, source} }
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "vendor" || (strings.HasPrefix(d.Name(), ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "openapi/openapi.yaml" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range regexp.MustCompile(`(?m)^  (/api/[^:]+):`).FindAllStringSubmatch(string(data), -1) {
				add("openapi", m[1], rel)
			}
		}
		if strings.HasPrefix(rel, "migrations/") && (strings.HasSuffix(rel, ".sql") || (strings.HasSuffix(rel, ".go") && len(filepath.Base(rel)) > 0 && filepath.Base(rel)[0] >= '0' && filepath.Base(rel)[0] <= '9')) && !strings.HasSuffix(rel, "_test.go") {
			add("migration", rel, rel)
		}
		if strings.HasPrefix(rel, "frontend/src/routes/") && strings.HasSuffix(rel, ".tsx") && !strings.Contains(rel, ".test.") {
			add("browser", strings.TrimSuffix(filepath.Base(rel), ".tsx"), rel)
		}
		if rel == "frontend/src/router.tsx" {
			add("module", rel, rel)
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			pattern := regexp.MustCompile(`(?:\b(route|investigateChild|findingsViewRedirect)\(\s*|\b(path)\s*:\s*)"([^"]+)"`)
			for _, m := range pattern.FindAllStringSubmatch(string(data), -1) {
				kind := m[1]
				if kind == "" {
					kind = m[2]
				}
				add("browser-route", kind+":"+m[3], rel)
			}
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		// These are exact file memberships, not wildcard workload assignments.
		for _, prefix := range []string{"internal/collect/", "internal/scanner/", "internal/intel/", "internal/checks/", "internal/app/", "internal/jobs/", "internal/migrate/", "internal/db/", "cmd/graph/"} {
			if strings.HasPrefix(rel, prefix) {
				add("module", rel, rel)
				break
			}
		}
		if !strings.HasPrefix(rel, "internal/httpsrv/") && !strings.HasPrefix(rel, "internal/app/mcp/") && !strings.HasPrefix(rel, "internal/jobs/") && !strings.HasPrefix(rel, "internal/collect/") && !strings.HasPrefix(rel, "internal/app/enrich/") && !strings.HasPrefix(rel, "internal/app/correlate/") && rel != "cmd/graph/collect_registry.go" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
		constants := map[string]string{}
		ast.Inspect(f, func(n ast.Node) bool {
			v, ok := n.(*ast.ValueSpec)
			if ok {
				for i, name := range v.Names {
					if i < len(v.Values) {
						constants[name.Name] = literal(v.Values[i])
					}
				}
			}
			return true
		})
		value := func(e ast.Expr) string {
			if id, ok := e.(*ast.Ident); ok {
				if v := constants[id.Name]; v != "" {
					return v
				}
				return siblingConstant(filepath.Dir(path), id.Name)
			}
			return literal(e)
		}
		var discoveryErr error
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.CallExpr:
				s, ok := v.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}

				if strings.HasPrefix(rel, "internal/app/mcp/") && s.Sel.Name == "register" {
					if len(v.Args) != 1 {
						discoveryErr = fmt.Errorf("unsupported MCP registration in %s", rel)
					} else if _, ok := v.Args[0].(*ast.CompositeLit); !ok {
						discoveryErr = fmt.Errorf("dynamic MCP registration in %s requires discovery support", rel)
					}
				}
				if strings.HasPrefix(rel, "internal/httpsrv/") && (s.Sel.Name == "HandleFunc" || s.Sel.Name == "Handle") && len(v.Args) > 0 {
					route := value(v.Args[0])
					if route == "" {
						discoveryErr = fmt.Errorf("dynamic HTTP route in %s requires discovery support", rel)
					} else {
						add("http", route, rel)
					}
				}
				if rel == "cmd/graph/collect_registry.go" && s.Sel.Name == "Register" && len(v.Args) > 0 {
					if kind, ok := v.Args[0].(*ast.SelectorExpr); ok {
						add("collector", kind.Sel.Name, rel)
					} else {
						discoveryErr = fmt.Errorf("dynamic collector in %s", rel)
					}
				}
				if strings.HasPrefix(rel, "internal/jobs/") && s.Sel.Name == "AddWorker" && len(v.Args) > 1 {
					name := workerName(v.Args[1])
					if name == "" {
						discoveryErr = fmt.Errorf("unsupported worker registration in %s", rel)
					} else {
						add("worker", name, rel)
					}
				}
			case *ast.CompositeLit:
				if strings.HasPrefix(rel, "internal/app/mcp/") {
					if typ, ok := v.Type.(*ast.Ident); ok && typ.Name == "tool" {
						for _, elt := range v.Elts {
							if kv, ok := elt.(*ast.KeyValueExpr); ok {
								if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Name" {
									name := value(kv.Value)
									if name == "" {
										discoveryErr = fmt.Errorf("unresolved MCP tool in %s", rel)
									} else {
										add("mcp", name, rel)
									}
								}
							}
						}
					}
				}
				if rel == "internal/jobs/periodic.go" {
					if typ, ok := v.Type.(*ast.Ident); ok && strings.HasSuffix(typ.Name, "Args") {
						add("schedule", typ.Name, rel)
					}
				}
			case *ast.FuncDecl:
				if strings.HasPrefix(rel, "internal/collect/") && (v.Name.Name == "Collect" || strings.HasPrefix(v.Name.Name, "collect")) {
					add("collection", filepath.ToSlash(filepath.Dir(rel))+":"+v.Name.Name, rel)
				}
				if v.Name.Name == "Name" && v.Recv != nil && v.Body != nil && (strings.HasPrefix(rel, "internal/app/enrich/") || strings.HasPrefix(rel, "internal/app/correlate/")) {
					kind := "enrichment"
					if strings.HasPrefix(rel, "internal/app/correlate/") {
						kind = "correlation"
					}
					ast.Inspect(v.Body, func(n ast.Node) bool {
						if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
							if name := value(ret.Results[0]); name != "" {
								add(kind, name, rel)
							} else {
								discoveryErr = fmt.Errorf("unresolved %s name in %s", kind, rel)
							}
						}
						return true
					})
				}
				if strings.HasPrefix(rel, "internal/jobs/") && v.Name.Name == "Kind" && v.Body != nil {
					ast.Inspect(v.Body, func(n ast.Node) bool {
						if ret, ok := n.(*ast.ReturnStmt); ok && len(ret.Results) == 1 {
							if kind := value(ret.Results[0]); kind != "" {
								add("job", kind, rel)
							} else {
								discoveryErr = fmt.Errorf("dynamic job kind in %s", rel)
							}
						}
						return true
					})
				}
			}
			return true
		})
		return discoveryErr
	})
	if err != nil {
		return nil, fmt.Errorf("discover workloads: %w", err)
	}
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func literal(e ast.Expr) string {
	if v, ok := e.(*ast.BasicLit); ok && v.Kind == token.STRING {
		s, _ := strconv.Unquote(v.Value)
		return s
	}
	return ""
}
func workerName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.UnaryExpr:
		return workerName(v.X)
	case *ast.CompositeLit:
		if id, ok := v.Type.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.CallExpr:
		if id, ok := v.Fun.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func siblingConstant(dir, name string) string {
	files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			continue
		}
		var found string
		ast.Inspect(f, func(n ast.Node) bool {
			if v, ok := n.(*ast.ValueSpec); ok {
				for i, id := range v.Names {
					if id.Name == name && i < len(v.Values) {
						found = literal(v.Values[i])
					}
				}
			}
			return true
		})
		if found != "" {
			return found
		}
	}
	return ""
}
