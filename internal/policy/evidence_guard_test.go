package policy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// This guard protects the only gate that can let a proposed action proceed
// without a human. Since ADR 087 that gate grants autonomy to exactly one thing,
// the read-only observe class, and the guard holds it there.
//
// A general lint — "a function that observes an error must return one" — was
// tried and rejected: an AST cannot see that a zero value means "unknown", so
// it needed a long list of prose exemptions. What IS exactly checkable is the
// chokepoint: policy.Input is the sole input to the gate, and Decide is the
// sole place autonomy is granted.
//
// Scope: this guard protects the gate's input contract and the AllowAuto
// grants in Decide only. It does not catch the same defect shape in dashboard
// aggregates, collectors, or Cypher readers — those are out of scope by design.

// evidenceKnownSuffix is the companion-field convention: an evidence field Foo
// is paired with FooKnown.
const evidenceKnownSuffix = "Known"

// observeCondition is the one case condition under which Decide may grant
// AllowAuto. It is compared with the whole printed case expression, so `!=`,
// a negation or an extra `&&`/`||` term can never pass for it.
const observeCondition = "in.ActionClass == classObserve"

// actionFields are the fields of Input that describe the action being PROPOSED
// rather than evidence the gate weighs about it. They need no known-ness: they
// are what the caller is asking permission for, and a caller that cannot name
// its own action has nothing to gate. Everything else in Input is evidence and
// must be paired.
//
// Adding a field here is how you say "this is not evidence" — and it is a claim
// that will be read, so make it true.
var actionFields = map[string]string{
	"ActionClass":    "the proposed action itself, supplied by the planner — not a measurement of the estate",
	"ConfidenceBand": "already four-valued WITH its own unknown: `insufficient` is the not-measured case, and Decide escalates on it",
}

// TestAutoExecuteGateRequiresKnownEvidence is the guard. Two halves:
//
//  1. DECLARATION — every evidence field of Input has a `<Field>Known bool`
//     companion. The gate weighs none today; this half makes the next one
//     arrive paired, because without a companion there is nowhere to put "we
//     did not measure this" and the caller's only option is a zero value that
//     reads as a measurement.
//  2. NO AUTONOMY FOR MUTATIONS — every place policy.go sets AllowAuto to true
//     is a `Decision{AllowAuto: true}` returned from a case of Decide whose
//     whole condition is the observe class. Vulngraph never executes a
//     state-changing action without a human (ADR 087), so a grant anywhere
//     else is refused outright rather than checked for evidence.
//
// The second half reads policy.go as SOURCE rather than calling Decide: a call
// can only sample inputs (TestGate_NoStateChangingInputIsAutonomous samples
// them), while a grant under any other condition is wrong for every input
// whether or not a sample happens to reach it.
func TestAutoExecuteGateRequiresKnownEvidence(t *testing.T) {
	fset, file := parsePolicy(t)
	fields := inputFields(t, file)
	require.NotEmpty(t, fields, "parsed no fields from Input — the walk is broken")

	// ── half 1: every evidence field is paired ────────────────────────────
	byName := map[string]inputField{}
	for _, f := range fields {
		byName[f.name] = f
	}
	for _, f := range fields {
		if strings.HasSuffix(f.name, evidenceKnownSuffix) {
			continue // the companion itself
		}
		if _, ok := actionFields[f.name]; ok {
			continue
		}
		companion, ok := byName[f.name+evidenceKnownSuffix]
		require.Truef(t, ok,
			"policy.Input.%s is evidence the gate weighs, but has no %s%s companion.\n\n"+
				"Go zero values cannot express \"not measured\": whatever %s is when the lookup that produces it "+
				"errors, the gate will read it as a fact. Add `%s%s bool`, or — if this field really is part of "+
				"the action being proposed rather than evidence about it — add it to actionFields with the reason.",
			f.name, f.name, evidenceKnownSuffix, f.name, f.name, evidenceKnownSuffix)
		require.Equalf(t, "bool", companion.typ,
			"policy.Input.%s must be a bool — it answers \"did we measure it\", nothing more", companion.name)
	}

	// ── half 2: AllowAuto is granted only on the observe class ────────────
	require.Equal(t, "observe", classObserve, "classObserve must name the read-only class the planner emits")
	grants := allowAutoGrants(t, fset, file)
	require.NotEmpty(t, grants,
		"found no AllowAuto grant at all — observe actions would park for approval, or the parse broke")
	for _, g := range grants {
		require.Truef(t, g.inDecide && g.caseCond == observeCondition,
			"policy.go:%d grants AllowAuto outside a Decide case conditioned on exactly %s (found %q).\n\n"+
				"Vulngraph never executes a state-changing action without a human's explicit yes (ADR 087): "+
				"remediations are parked for approval and run through the executor's approval path. "+
				"AllowAuto is for read-only observe actions only — no confidence or blast radius earns more.",
			g.line, observeCondition, g.caseCond)
	}
}

func parsePolicy(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "policy.go", nil, 0)
	require.NoError(t, err, "parsing policy.go")
	return fset, file
}

type allowAutoGrant struct {
	line     int
	inDecide bool
	caseCond string
}

// allowAutoGrants returns every place policy.go may set AllowAuto. A form this
// walk cannot vouch for (an assignment to a field, an unkeyed Decision literal,
// a value other than the literal true or false) is refused rather than skipped.
func allowAutoGrants(t *testing.T, fset *token.FileSet, file *ast.File) []allowAutoGrant {
	t.Helper()
	var out []allowAutoGrant
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "AllowAuto" {
					require.Failf(t, "AllowAuto assigned",
						"policy.go:%d assigns AllowAuto; grant it only as Decision{AllowAuto: true} in a Decide case",
						fset.Position(x.Pos()).Line)
				}
			}
		case *ast.CompositeLit:
			if id, ok := x.Type.(*ast.Ident); ok && id.Name == "Decision" {
				for _, el := range x.Elts {
					_, keyed := el.(*ast.KeyValueExpr)
					require.Truef(t, keyed, "policy.go:%d builds an unkeyed Decision literal this guard cannot read",
						fset.Position(x.Pos()).Line)
				}
			}
		case *ast.KeyValueExpr:
			key, ok := x.Key.(*ast.Ident)
			if !ok || key.Name != "AllowAuto" {
				return true
			}
			val, _ := x.Value.(*ast.Ident)
			require.Truef(t, val != nil && (val.Name == "true" || val.Name == "false"),
				"policy.go:%d sets AllowAuto to %s; only the literal true or false can be vouched for",
				fset.Position(x.Pos()).Line, types.ExprString(x.Value))
			if val.Name == "false" {
				return true
			}
			out = append(out, grantContext(stack, fset.Position(x.Pos()).Line))
		}
		return true
	})
	return out
}

// grantContext reports whether the innermost enclosing function is Decide and
// prints the condition of the innermost enclosing case clause.
func grantContext(stack []ast.Node, line int) allowAutoGrant {
	g := allowAutoGrant{line: line}
	for i := len(stack) - 1; i >= 0; i-- {
		switch x := stack[i].(type) {
		case *ast.CaseClause:
			if g.caseCond == "" {
				parts := make([]string, 0, len(x.List))
				for _, e := range x.List {
					parts = append(parts, types.ExprString(e))
				}
				g.caseCond = strings.Join(parts, ", ")
				if len(parts) == 0 {
					g.caseCond = "default"
				}
			}
		case *ast.FuncLit:
			return g
		case *ast.FuncDecl:
			g.inDecide = x.Recv == nil && x.Name.Name == "Decide"
			return g
		}
	}
	return g
}

type inputField struct {
	name, typ string
}

// inputFields reads the Input struct out of policy.go. Source, not reflection:
// the interesting failure (a field added without a companion) is a
// source-level fact.
func inputFields(t *testing.T, file *ast.File) []inputField {
	t.Helper()
	var out []inputField
	ast.Inspect(file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Input" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, fld := range st.Fields.List {
			id, ok := fld.Type.(*ast.Ident)
			require.Truef(t, ok, "policy.Input holds a non-basic field type; this guard assumes plain scalars")
			for _, nm := range fld.Names {
				out = append(out, inputField{name: nm.Name, typ: id.Name})
			}
		}
		return false
	})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}
