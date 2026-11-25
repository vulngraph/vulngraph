// Package keyscan derives, from source, the asset metadata keys each CSPM
// check's Violates predicate actually reads.
//
// A check's required keys are the contract the sync-time lifecycle reconcile
// depends on to tell "the collector observed this resource and the problem is
// gone" from "the collector could not read the setting at all" — a
// hand-written list would drift silently the moment someone edits a
// predicate. Deriving from the AST makes the list a consequence of the code
// rather than a promise about it.
package keyscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	goscanner "go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Result is one check literal's derived contract.
type Result struct {
	// Keys are the asset metadata keys the predicate reads, sorted and deduped.
	// Empty means the predicate reads no metadata at all (it decides on
	// structural asset fields like PublicIP or Type) — a legitimate, provable
	// state, not a gap.
	Keys []string
	// Dynamic is true when the predicate could not be analysed statically (an
	// unresolvable indirection). A dynamic check must never be gated on derived
	// keys: an incomplete key set would suppress a real resolution.
	Dynamic bool
	// Probes are candidate values for an ABSENT key, used to decide whether the
	// predicate's "no violation" answer actually depended on the missing data.
	// The set is every string literal the predicate closure mentions, plus the
	// empty string and numeric sentinels when the closure parses integers — a
	// deliberate superset. A probe that cannot make the predicate fire costs
	// nothing; a missing probe would let a real dependency pass as evaluable, so
	// the set errs wide.
	Probes []string
	// Unresolved lists the imported values (asset.PublicAccessConfirmed) the
	// predicate compares a value against with ==, != or a switch case. The scan
	// harvests only this package's literals, so such a value is never a probe:
	// the check must declare it in TableProbes, or an absent key reads as
	// "evaluated, clean". Not rendered; TestUnresolvedComparandsHaveTableProbes
	// reads it from a fresh scan.
	Unresolved []string
	// Logic is a digest of the check literal and every package-level func,
	// const and var it reaches, printed without comments or blank lines, plus
	// the whole source of each logicPackages package it references. The
	// registry fingerprint includes it, so a deploy that edits a check's
	// predicate, severity grading or wording forces one full-asset re-check per
	// connector instead of leaving the edit dark on every unchanged asset.
	Logic string
	// TimeDependent is true when the check reads the wall clock (time.Now,
	// time.Since, time.Until) anywhere it reaches. Its answer on an unchanged
	// asset can change from one day to the next, so the sync worker re-evaluates
	// it on every asset daily rather than only on changed ones.
	TimeDependent bool
}

// logicPackages are the in-repo leaf packages whose functions decide check
// verdicts (the CIDR union behind every world-open rule, distro lifecycle
// tables, the system-namespace list), by import path, with their directory
// relative to the checks package. Their source is digested into the Logic of
// every check that references them, so a behaviour change there re-checks
// unchanged assets as an edit in package checks does. asset and finding are
// absent: checks use their types and constants, and digesting them would
// re-check every asset on any domain edit.
var logicPackages = map[string]string{
	"github.com/vulngraph/vulngraph/internal/cidrset": "../cidrset",
	"github.com/vulngraph/vulngraph/internal/distro":  "../distro",
	"github.com/vulngraph/vulngraph/internal/k8sns":   "../k8sns",
}

// Scan parses every non-test .go file in dir (the checks package) and returns
// one Result per check ID.
func Scan(dir string) (map[string]Result, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("Scan: read %s: %w", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("Scan: parse %s: %w", name, err)
		}
		if f.Name.Name != "checks" {
			continue
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("Scan: no package checks source found in %s", dir)
	}

	s := &scanner{fset: fset, funcs: map[string]*ast.FuncDecl{}, values: map[string]ast.Node{}, imports: map[string]bool{}, pkgLogic: map[string]string{}}
	for _, f := range files {
		for _, imp := range f.Imports {
			name := importName(imp)
			s.imports[name] = true
			path, _ := strconv.Unquote(imp.Path.Value)
			rel, ok := logicPackages[path]
			if !ok || s.pkgLogic[name] != "" {
				continue
			}
			digest, err := packageDigest(filepath.Join(dir, rel))
			if err != nil {
				return nil, fmt.Errorf("Scan: %s: %w", path, err)
			}
			s.pkgLogic[name] = digest
		}
		for _, d := range f.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil {
					s.funcs[decl.Name.Name] = decl
				}
			case *ast.GenDecl:
				s.addValues(decl)
			}
		}
	}

	out := map[string]Result{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || !isCheckType(cl.Type) {
				return true
			}
			id, violates := checkFields(cl)
			if id == "" {
				return true
			}
			logic, clock := s.logicOf(cl)
			if violates == nil {
				out[id] = Result{Dynamic: true, Logic: logic, TimeDependent: clock}
				return true
			}
			keys, dynamic := s.keysOf(violates, map[string]bool{})
			sort.Strings(keys)
			probes, unresolved := s.probesOf(violates, map[string]bool{})
			sort.Strings(probes)
			sort.Strings(unresolved)
			out[id] = Result{Keys: dedupe(keys), Dynamic: dynamic, Probes: dedupe(probes), Unresolved: dedupe(unresolved), Logic: logic, TimeDependent: clock}
			return false // a Check literal never nests another
		})
	}
	return out, nil
}

func isCheckType(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "Check"
}

// checkFields pulls the literal ID and the Violates expression out of a Check
// composite literal. A non-literal ID yields "" (the caller skips it).
func checkFields(cl *ast.CompositeLit) (string, ast.Expr) {
	var id string
	var violates ast.Expr
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		k, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch k.Name {
		case "ID":
			if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil {
					id = v
				}
			}
		case "Violates":
			violates = kv.Value
		}
	}
	return id, violates
}

type scanner struct {
	fset     *token.FileSet
	funcs    map[string]*ast.FuncDecl
	values   map[string]ast.Node // package-level const/var name → its ValueSpec
	imports  map[string]bool     // every package name an import binds in this package
	pkgLogic map[string]string   // import name of a logicPackages package → its source digest
}

// packageDigest digests every non-test .go file in dir as normalized tokens,
// in file-name order, so comments and layout are not logic there either.
func packageDigest(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("packageDigest: %w", err)
	}
	h := sha256.New()
	files := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", fmt.Errorf("packageDigest: %w", err)
		}
		h.Write([]byte(name + "\x00" + normalizedTokens(src) + "\x00"))
		files++
	}
	if files == 0 {
		return "", fmt.Errorf("packageDigest: no Go source in %s", dir)
	}
	return hex.EncodeToString(h.Sum(nil)[:8]), nil
}

// importName is the identifier an import binds: its alias, else the last path
// element (every import in this package is named for its last element).
func importName(imp *ast.ImportSpec) string {
	if imp.Name != nil {
		return imp.Name.Name
	}
	p, err := strconv.Unquote(imp.Path.Value)
	if err != nil {
		return ""
	}
	return p[strings.LastIndex(p, "/")+1:]
}

// addValues indexes a package-level const/var declaration by each name it
// declares, so logicOf can follow a check's reference to a threshold or table.
func (s *scanner) addValues(decl *ast.GenDecl) {
	if decl.Tok != token.CONST && decl.Tok != token.VAR {
		return
	}
	for _, spec := range decl.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for _, n := range vs.Names {
			s.values[n.Name] = vs
		}
	}
}

// clockFuncs are the time package functions that read the wall clock.
var clockFuncs = map[string]bool{"Now": true, "Since": true, "Until": true}

// logicOf digests a Check literal together with every package-level func,
// const and var it transitively references, and reports whether any of them
// reads the wall clock. Over-inclusion (a local variable that shares a
// package-level name) only costs an extra re-check; under-inclusion would leave
// an edit dark, so the walk follows every identifier.
func (s *scanner) logicOf(cl *ast.CompositeLit) (string, bool) {
	var parts []string
	clock := false
	seen := map[string]bool{}
	queue := []ast.Node{cl}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		parts = append(parts, s.normalized(n))
		ast.Inspect(n, func(x ast.Node) bool {
			switch v := x.(type) {
			case *ast.SelectorExpr:
				pkg, ok := v.X.(*ast.Ident)
				if !ok {
					return true
				}
				if pkg.Name == "time" && clockFuncs[v.Sel.Name] {
					clock = true
				}
				if digest := s.pkgLogic[pkg.Name]; digest != "" && !seen["package "+pkg.Name] {
					seen["package "+pkg.Name] = true
					parts = append(parts, "package "+pkg.Name+" "+digest)
				}
			case *ast.Ident:
				if seen[v.Name] {
					return true
				}
				if fd, ok := s.funcs[v.Name]; ok {
					seen[v.Name] = true
					queue = append(queue, fd)
				} else if vs, ok := s.values[v.Name]; ok {
					seen[v.Name] = true
					queue = append(queue, vs)
				}
			}
			return true
		})
	}
	// The literal comes first; the rest is order-independent.
	sort.Strings(parts[1:])
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8]), clock
}

// normalized renders a node as its token stream — no comments, no layout, no
// automatically inserted semicolons — so documenting or reformatting a check
// never reads as a logic change.
func (s *scanner) normalized(n ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, s.fset, n); err != nil {
		return fmt.Sprintf("unprintable:%T", n)
	}
	return normalizedTokens(buf.Bytes())
}

// normalizedTokens renders Go source as its token stream, comments and
// automatically inserted semicolons dropped.
func normalizedTokens(src []byte) string {
	fs := token.NewFileSet()
	var sc goscanner.Scanner
	sc.Init(fs.AddFile("", fs.Base(), len(src)), src, nil, 0)
	var toks []string
	for {
		_, tok, lit := sc.Scan()
		if tok == token.EOF {
			break
		}
		if tok == token.SEMICOLON && lit == "\n" {
			continue
		}
		if lit == "" {
			lit = tok.String()
		}
		toks = append(toks, lit)
	}
	return strings.Join(toks, " ")
}

// keysOf walks an expression (a func literal, or an identifier naming a
// package-level func) and returns every metadata key it reads.
func (s *scanner) keysOf(e ast.Expr, seen map[string]bool) ([]string, bool) {
	switch v := e.(type) {
	case *ast.FuncLit:
		return s.keysIn(v.Body, nil, seen)
	case *ast.Ident:
		fd, ok := s.funcs[v.Name]
		if !ok {
			return nil, true // not a package-level func — unanalysable
		}
		if seen[v.Name] {
			return nil, false
		}
		seen[v.Name] = true
		return s.keysIn(fd.Body, nil, seen)
	default:
		return nil, true
	}
}

// keysIn walks a function body. bound maps a parameter name to the string
// literals the caller passed for it, so a helper that indexes Metadata with its
// own parameter (observedNone(a, "encryption")) still resolves to a real key.
func (s *scanner) keysIn(body *ast.BlockStmt, bound map[string][]string, seen map[string]bool) ([]string, bool) {
	if body == nil {
		return nil, true
	}
	var keys []string
	dynamic := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IndexExpr:
			if !isMetadataSelector(node.X) {
				return true
			}
			switch idx := node.Index.(type) {
			case *ast.BasicLit:
				if idx.Kind == token.STRING {
					if v, err := strconv.Unquote(idx.Value); err == nil {
						keys = append(keys, v)
					}
					return true
				}
				dynamic = true
			case *ast.Ident:
				if vals, ok := bound[idx.Name]; ok {
					keys = append(keys, vals...)
					return true
				}
				dynamic = true
			default:
				dynamic = true
			}
		case *ast.CallExpr:
			id, ok := node.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			fd, ok := s.funcs[id.Name]
			if !ok {
				return true // builtin or imported: cannot read this asset's metadata
			}
			sub, subDyn := s.callKeys(fd, id.Name, node.Args, seen)
			keys = append(keys, sub...)
			dynamic = dynamic || subDyn
		}
		return true
	})
	return keys, dynamic
}

// callKeys resolves a call to a package-level func, binding string-literal
// arguments to their parameter names before descending.
func (s *scanner) callKeys(fd *ast.FuncDecl, name string, args []ast.Expr, seen map[string]bool) ([]string, bool) {
	if seen[name] {
		return nil, false
	}
	seen[name] = true
	defer delete(seen, name)

	bound := map[string][]string{}
	for i, pname := range paramNames(fd) {
		if i >= len(args) {
			break
		}
		lit, ok := args[i].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		if v, err := strconv.Unquote(lit.Value); err == nil {
			bound[pname] = append(bound[pname], v)
		}
	}
	return s.keysIn(fd.Body, bound, seen)
}

// paramNames flattens a func's parameter names in declaration order ("_" and
// unnamed params included as placeholders so positions stay aligned).
func paramNames(fd *ast.FuncDecl) []string {
	var out []string
	if fd.Type.Params == nil {
		return out
	}
	for _, f := range fd.Type.Params.List {
		if len(f.Names) == 0 {
			out = append(out, "")
			continue
		}
		for _, n := range f.Names {
			out = append(out, n.Name)
		}
	}
	return out
}

// isMetadataSelector reports whether e is an X.Metadata selector.
func isMetadataSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "Metadata"
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Render emits the generated Go source for a scan result. Kept here beside the
// scanner so the shape of what is written can never drift from what is derived.
func Render(scanned map[string]Result) []byte {
	ids := make([]string, 0, len(scanned))
	for id := range scanned {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var b strings.Builder
	b.WriteString("// Code generated by cmd/checkkeys-gen. DO NOT EDIT.\n\n")
	b.WriteString("package checks\n\n")
	b.WriteString(`// derivedRequiredKeys maps a check ID to the asset metadata keys its Violates
// predicate reads, derived from the AST of this package (internal/checks/keyscan).
// A nil entry means the predicate reads no metadata at all — it decides on
// structural asset fields — which is a proved fact, not a missing declaration.
//
// Registry.Register stamps these onto Check.RequiredKeys, so the runtime value
// and the source it came from cannot disagree.
`)
	b.WriteString("var derivedRequiredKeys = map[string][]string{\n")
	for _, id := range ids {
		r := scanned[id]
		if r.Dynamic {
			// A predicate the scanner could not resolve gets no keys: gating on a
			// partial set would suppress legitimate resolutions.
			fmt.Fprintf(&b, "\t%q: nil, // predicate not statically analysable\n", id)
			continue
		}
		if len(r.Keys) == 0 {
			fmt.Fprintf(&b, "\t%q: nil,\n", id)
			continue
		}
		fmt.Fprintf(&b, "\t%q: {", id)
		for i, k := range r.Keys {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", k)
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n\n")
	b.WriteString(`// derivedProbeValues maps a check ID to the values tried for an ABSENT required
// key when deciding whether the predicate's silence depended on it. Derived with
// the keys, from the same AST — see Check.Evaluable for why a syntactic
// "reads the key" test is not enough (ns_psa_enforce is read by three k8s pod
// checks purely to SUPPRESS them, and requiring it would freeze effectively
// every pod's findings open forever).
`)
	b.WriteString("var derivedProbeValues = map[string][]string{\n")
	for _, id := range ids {
		r := scanned[id]
		if len(r.Keys) == 0 || r.Dynamic {
			continue
		}
		fmt.Fprintf(&b, "\t%q: {", id)
		for i, p := range r.Probes {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", p)
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n\n")
	b.WriteString(`// dynamicPredicateChecks are check IDs whose predicate the scanner could not
// analyse statically. They are exempt from the evaluability gate by necessity —
// an incomplete key set would be worse than none. Empty is the healthy state.
`)
	b.WriteString("var dynamicPredicateChecks = map[string]bool{\n")
	for _, id := range ids {
		if scanned[id].Dynamic {
			fmt.Fprintf(&b, "\t%q: true,\n", id)
		}
	}
	b.WriteString("}\n\n")
	b.WriteString(`// derivedLogicDigests maps a check ID to a digest of its literal and every
// package-level func, const and var it reaches. Registry.Fingerprint includes
// it, so editing a check's logic forces one full-asset re-check per connector.
`)
	b.WriteString("var derivedLogicDigests = map[string]string{\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "\t%q: %q,\n", id, scanned[id].Logic)
	}
	b.WriteString("}\n\n")
	b.WriteString(`// derivedTimeDependent are the check IDs that read the wall clock. Their answer
// on an unchanged asset changes with the date, so the sync worker re-evaluates
// them over every applicable asset once a day.
`)
	b.WriteString("var derivedTimeDependent = map[string]bool{\n")
	for _, id := range ids {
		if scanned[id].TimeDependent {
			fmt.Fprintf(&b, "\t%q: true,\n", id)
		}
	}
	b.WriteString("}\n")
	return []byte(b.String())
}

// numericProbes are the values tried for an absent key when the predicate parses
// integers. They straddle every threshold this catalogue uses: negative (the
// "never authenticated" sentinel), zero, one, and a value past any age or count
// bound. Combined with the literal thresholds harvested from the source, they
// cover both sides of every comparison a predicate makes.
var numericProbes = []string{"-1", "0", "1", "999999"}

// probesOf collects the candidate values for an absent key: every string literal
// the predicate closure mentions, always the empty string (the observed-none
// convention), and the numeric probes when the closure parses integers. The
// second result is every imported value the closure compares against, which
// the literal harvest cannot see (Result.Unresolved).
func (s *scanner) probesOf(e ast.Expr, seen map[string]bool) ([]string, []string) {
	probes := []string{""}
	var body *ast.BlockStmt
	switch v := e.(type) {
	case *ast.FuncLit:
		body = v.Body
	case *ast.Ident:
		fd, ok := s.funcs[v.Name]
		if !ok {
			return probes, nil
		}
		body = fd.Body
	default:
		return probes, nil
	}
	lits, unresolved := s.literalsIn(body, seen)
	return append(probes, lits...), unresolved
}

// literalsIn walks a body (descending into package-level funcs it calls) and
// returns every string literal, every integer literal rendered as a string, and
// the numeric probes if any integer parsing appears; and, separately, every
// imported value used as a comparand (importedComparands).
func (s *scanner) literalsIn(body *ast.BlockStmt, seen map[string]bool) ([]string, []string) {
	if body == nil {
		return nil, nil
	}
	var out, unresolved []string
	numeric := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BasicLit:
			switch node.Kind {
			case token.STRING:
				if v, err := strconv.Unquote(node.Value); err == nil {
					out = append(out, v)
				}
			case token.INT:
				out = append(out, node.Value)
			}
		case *ast.BinaryExpr:
			if node.Op == token.EQL || node.Op == token.NEQ {
				unresolved = append(unresolved, s.importedComparands(node.X, node.Y)...)
				unresolved = append(unresolved, s.importedComparands(node.Y, node.X)...)
			}
		case *ast.SwitchStmt:
			if node.Tag != nil {
				for _, st := range node.Body.List {
					if cc, ok := st.(*ast.CaseClause); ok {
						for _, v := range cc.List {
							unresolved = append(unresolved, s.importedComparands(v, node.Tag)...)
						}
					}
				}
			}
		case *ast.SelectorExpr:
			// strconv.Atoi / strconv.ParseInt: the key is read as a number, so the
			// literal thresholds alone do not straddle every comparison.
			if pkg, ok := node.X.(*ast.Ident); ok && pkg.Name == "strconv" {
				numeric = true
			}
		case *ast.CallExpr:
			id, ok := node.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			fd, ok := s.funcs[id.Name]
			if !ok || seen[id.Name] {
				return true
			}
			seen[id.Name] = true
			lits, unres := s.literalsIn(fd.Body, seen)
			out = append(out, lits...)
			unresolved = append(unresolved, unres...)
		}
		return true
	})
	if numeric {
		out = append(out, numericProbes...)
	}
	return out, unresolved
}

// importedComparands returns v rendered as pkg.Name when it is a value from an
// imported package compared against other, a value the predicate computed (an
// index, a call, a local). A comparison against a structural field (a.Provider
// == asset.ProviderAWS) reads no metadata, so it is not reported.
func (s *scanner) importedComparands(v, other ast.Expr) []string {
	sel, ok := v.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || !s.imports[pkg.Name] {
		return nil
	}
	if o, ok := other.(*ast.SelectorExpr); ok {
		if x, ok := o.X.(*ast.Ident); !ok || !s.imports[x.Name] {
			return nil
		}
	}
	return []string{pkg.Name + "." + sel.Sel.Name}
}
