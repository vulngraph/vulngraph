package guardknownness

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This is the structural half of the
// "degraded input" convention that internal/policy/evidence_guard_test.go
// enforces for policy.Input specifically, generalized to the other structs the
// convention actually appears on. It is deliberately an explicit table, not a
// name-derived scan: this codebase's own <Field>Known pairs are NOT uniformly
// named (enrich.mustFixInputs pairs "reachable" with "reachKnown", not
// "reachableKnown" — a real irregularity found while writing this guard), so
// deriving companions from a suffix convention would either miss that pair or
// require guessing at names a future field might not follow either. Each row
// here is a claim that this pairing exists and matters; adding a field to
// pairFields is how a new instance of the convention gets covered.
//
// Two halves, mirroring the policy guard's own design:
//  1. DECLARATION — every (field, companion) pair actually exists as declared
//     bool fields in the named struct.
//  2. CONSUMPTION — the half that actually bites (it is what would have caught
//     the unmeasured-blast-radius bug: govern's former auto-execute gate compared BlastRadius against a cap
//     without also requiring BlastRadiusKnown). Every order-comparison
//     (<, <=, >, >=) against the field, inside an if-condition in the
//     DECLARING PACKAGE's own non-test source, must sit in an enclosing
//     function that mentions the companion (see
//     TestKnownnessGatesCheckTheirCompanion for why not the same condition).
//     A bool field (reachable) is never order-compared, so its row takes part
//     only in the declaration half.
//
// Scope, same as the policy guard's own stated scope: this catches a gate
// re-derived without its known-ness check IN THE PACKAGE THAT OWNS THE FIELD.
// A consumer in another package that reads QueueItem.BlastRadius without the
// Known field is a different, harder-to-close gap (the field crossing a
// package boundary loses its paired-ness at the type level) — out of scope
// here by design, not oversight.
type pairTarget struct {
	pkgDir    string // relative to this package's directory
	declFile  string // file the struct is declared in, for a clearer failure message
	structTyp string
	field     string
	companion string
}

var pairFields = []pairTarget{
	{pkgDir: "../app/govern", declFile: "domain.go", structTyp: "QueueItem", field: "BlastRadius", companion: "BlastRadiusKnown"},
	{pkgDir: "../app/reasoncache", declFile: "domain.go", structTyp: "Entry", field: "BlastRadius", companion: "BlastRadiusKnown"},
	{pkgDir: "../app/enrich", declFile: "mustfix.go", structTyp: "mustFixInputs", field: "blast", companion: "blastKnown"},
	{pkgDir: "../app/enrich", declFile: "mustfix.go", structTyp: "mustFixInputs", field: "reachable", companion: "reachKnown"},
}

// TestKnownnessFieldsArePaired is half 1 — DECLARATION.
func TestKnownnessFieldsArePaired(t *testing.T) {
	for _, target := range pairFields {
		t.Run(target.structTyp+"."+target.field, func(t *testing.T) {
			fields := structFields(t, filepath.Join(target.pkgDir, target.declFile), target.structTyp)
			require.NotEmpty(t, fields, "found no fields for %s in %s — the parse or struct name is wrong",
				target.structTyp, target.declFile)

			_, ok := fields[target.field]
			require.Truef(t, ok, "%s has no field %q", target.structTyp, target.field)

			ct, ok := fields[target.companion]
			require.Truef(t, ok, "%s.%s has no companion %s — every field paired in pairFields must actually exist",
				target.structTyp, target.field, target.companion)
			require.Equalf(t, "bool", ct, "%s.%s must be a bool — it answers \"did we measure %s\", nothing more",
				target.structTyp, target.companion, target.field)
		})
	}
}

// TestKnownnessGatesCheckTheirCompanion is half 2 — CONSUMPTION, the half that
// actually bites. It would have caught the unmeasured-blast-radius bug directly: govern/service.go's
// `it.BlastRadius <= pol.BlastRadiusCap` gate, before its fix, compared
// BlastRadius against a cap with no mention of BlastRadiusKnown anywhere in
// applyPolicyRules at all.
//
// Scoped to the enclosing FUNCTION, not the if-condition itself: clusterQueue's
// legitimate max-tracking (`if e.BlastRadius > it.BlastRadius { it.BlastRadius
// = e.BlastRadius }`, immediately followed by a SEPARATE
// `it.BlastRadiusKnown = it.BlastRadiusKnown && e.BlastRadiusKnown` statement)
// compares the field without its companion in the SAME condition on purpose —
// the known-ness is folded in as its own AND-reduction, not re-checked at
// every place the raw number is compared. Requiring the companion anywhere in
// the same function is the honest boundary: narrow enough to still catch
// that bug's shape (that function never mentioned BlastRadiusKnown at all), loose
// enough not to flag this codebase's own already-verified-correct pattern.
func TestKnownnessGatesCheckTheirCompanion(t *testing.T) {
	for _, target := range pairFields {
		t.Run(target.structTyp+"."+target.field, func(t *testing.T) {
			violations := findUncheckedGates(t, target.pkgDir, target.field, target.companion)
			require.Emptyf(t, violations,
				"%s: order-comparison against %q with no %q anywhere in the enclosing function:\n  %s\n\n"+
					"A comparison against an unmeasured value's zero can be MORE permissive than a real "+
					"measurement (blast_radius==0 satisfies <=N more easily than any real walk) — see "+
					"CLAUDE.md's \"Degraded input\" rule.",
				target.structTyp, target.field, target.companion, strings.Join(violations, "\n  "))
		})
	}
}

// structFields parses relPath (relative to this package's directory) and
// returns the scalar field types of the named struct, keyed by field name.
func structFields(t *testing.T, relPath, structName string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, relPath, nil, 0)
	require.NoErrorf(t, err, "parsing %s", relPath)

	out := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != structName {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, fld := range st.Fields.List {
			id, ok := fld.Type.(*ast.Ident)
			if !ok {
				continue // this guard only reasons about plain scalar fields
			}
			for _, nm := range fld.Names {
				out[nm.Name] = id.Name
			}
		}
		return false
	})
	return out
}

var orderCompRe = regexp.MustCompile(`<=|>=|<|>`)

// findUncheckedGates scans every non-test .go file in pkgDir for if-statements
// whose condition order-compares against field (a word-boundary match, so
// BlastRadius never matches BlastRadiusCap) where the ENCLOSING FUNCTION's
// source contains no mention of companion at all.
func findUncheckedGates(t *testing.T, pkgDir, field, companion string) []string {
	t.Helper()
	fieldRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(field) + `\b`)

	var violations []string
	entries, err := os.ReadDir(pkgDir)
	require.NoError(t, err)
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		src, err := os.ReadFile(path)
		require.NoError(t, err)
		file, err := parser.ParseFile(fset, path, src, 0)
		require.NoErrorf(t, err, "parsing %s", path)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if identUsed(fn.Body, companion) {
				continue // the function accounts for known-ness somewhere — good enough
			}

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				start, end := fset.Position(ifs.Cond.Pos()).Offset, fset.Position(ifs.Cond.End()).Offset
				if start < 0 || end > len(src) || start >= end {
					return true
				}
				condSrc := string(src[start:end])
				if orderCompRe.MatchString(condSrc) && fieldRe.MatchString(condSrc) {
					line := fset.Position(ifs.Cond.Pos()).Line
					violations = append(violations, path+":"+strconv.Itoa(line)+": "+condSrc+
						" (function "+fn.Name.Name+" never mentions "+companion+")")
				}
				return true
			})
		}
	}
	sort.Strings(violations)
	return violations
}

// identUsed reports whether any identifier named want appears anywhere in n
// (a qualified reference like it.BlastRadiusKnown is an *ast.Ident nested
// under a SelectorExpr, so a plain Ident walk covers both the qualified and
// unqualified case). AST-based rather than a text search over the function's
// source bytes on purpose: a doc comment mentioning the companion field by
// name — exactly the kind of comment this guard's own violation messages
// produce — sits in those same bytes but was never parsed into the AST
// (parser.ParseFile here uses mode 0, no ast.ParseComments), so a text search
// would silently pass a function whose CODE dropped the check and whose
// COMMENT still describes it.
func identUsed(n ast.Node, want string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == want {
			found = true
		}
		return !found
	})
	return found
}
