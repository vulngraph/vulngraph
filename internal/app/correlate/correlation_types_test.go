package correlate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// allRules is every Rule implementation in this package, mirroring the
// registration list in cmd/graph/worker.go. TestAllRulesListIsComplete parses
// the package source and fails if a Rule is added without being listed here, so
// this cannot silently drift.
var allRules = []Rule{
	DNSPointsTo{},
	IAMCanAssume{},
	GCPImpersonation{},
	EC2InstanceProfile{},
	ExecutesAs{},
	DeploysTo{},
	K8sManifestOwnership{},
	TFOwnership{},
	&CIAccess{},
	DeclaredIdentityOwnership{},
	ImageOwnership{},
	SecurityGroupAllows{},
	SharedSecurityGroup{},
	GCPFirewallApplies{},
	GCPFirewallReachability{},
	K8sServiceTargets{},
	InternetReachability{},
	FederationTrust{},
	GCPWorkloadIdentity{},
	IRSATrust{},
	K8sPodServiceAccount{},
	IAMEffectivePermissions{},
	SecretAccess{},
	DataClassification{},
	HumanIdentityFederation{},
}

// TestCorrelationTypesCoverEveryRuleAndGraphSwitch pins the invariant the whole
// correlation stage rests on: the view query must load every asset type the
// rules ask for AND every type NewGraph indexes. A type missing from
// correlationTypes is not an error anywhere — the rule simply sees nothing and
// logs edges=0 — which is why this has broken twice: aws_scp_set (the
// org-level cap, silently never applied to any derived edge) and
// declared_cloud_identity (edges produced only by the partial path, so they
// would age out under the 48h edge-freshness rule the moment IaC sync paused).
func TestCorrelationTypesCoverEveryRuleAndGraphSwitch(t *testing.T) {
	loaded := make(map[string]bool, len(correlationTypes))
	for _, ty := range correlationTypes {
		require.False(t, loaded[ty], "correlationTypes lists %q twice", ty)
		loaded[ty] = true
	}

	for _, r := range allRules {
		for _, ty := range r.InterestedIn() {
			require.True(t, loaded[ty],
				"rule %s is interested in %q but correlationTypes never loads it — the rule is dead on the full sweep",
				r.Name(), ty)
		}
	}

	for _, ty := range newGraphSwitchTypes(t) {
		require.True(t, loaded[ty],
			"NewGraph indexes asset type %q but correlationTypes never loads it — the index is always empty",
			ty)
	}
}

// TestCorrelationTypesHasNoUnusedTypes closes the direction
// TestCorrelationTypesCoverEveryRuleAndGraphSwitch does not. That test checks
// declared ⊆ loaded, so a type LOADED but read by nobody was invisible — and four
// were: subnet, vpc, azure_subnet and azure_vnet,
// fetched and JSON-decoded on every sweep for an "InSubnet" correlation rule that
// has never existed. in_subnet/in_vpc edges come from the collectors
// (internal/collect/aws/instances.go), and Ladybug loads its nodes from
// asset.ListAll, not from this view — so adding them here bought nothing.
//
// Graph has no generic all-assets accessor (every field is a typed index), so a
// type that appears in no rule's InterestedIn and no NewGraph case is provably
// dead weight in the view.
func TestCorrelationTypesHasNoUnusedTypes(t *testing.T) {
	used := make(map[string]bool)
	for _, r := range allRules {
		for _, ty := range r.InterestedIn() {
			used[ty] = true
		}
	}
	for _, ty := range newGraphSwitchTypes(t) {
		used[ty] = true
	}
	for _, tys := range graphReadsRequiringDeclaration {
		for _, ty := range tys {
			used[ty] = true
		}
	}

	for _, ty := range correlationTypes {
		require.True(t, used[ty],
			"correlationTypes loads %q but no rule declares interest in it, no NewGraph case indexes it, "+
				"and no Graph read requires it — every sweep pays to fetch and JSON-decode it for nothing",
			ty)
	}
}

// TestCorrelationLimitIsADerivedCircuitBreaker guards the limit against being
// edited to a number nobody derived. 600k comes from the worker memory budget
// (~5 KiB per decoded asset.Asset, 35% of an 8192MiB GOMEMLIMIT) — see the const
// comment. Raising it trades silent truncation for a worker OOM, so a change here
// needs the arithmetic redone, not a bigger round number.
func TestCorrelationLimitIsADerivedCircuitBreaker(t *testing.T) {
	require.Equal(t, 600_000, correlationLimit)
}

// graphReadsRequiringDeclaration maps a Graph accessor to the asset types that
// must be loaded for it to return anything. It lists only reads NOTHING ELSE can
// catch: aws_scp_set is never an edge ENDPOINT, so a rule that consults SCPs
// emits exactly the same edge shapes whether or not the type is loaded — it just
// silently loses the organisation-level cap. Every other Graph read shows
// up in the rule's own edges, and TestCorrelationTypesCoverEveryRuleAndGraphSwitch
// covers the opposite direction (declared ⊆ loaded).
var graphReadsRequiringDeclaration = map[string][]string{
	"SCPPoliciesForAccount": {"aws_scp_set"},
}

// TestRulesDeclareTheTypesTheyReadFromTheGraph closes the other half of the
// split-brain: neededTypesFor reads InterestedIn, so a rule that READS a type
// through the Graph but does not DECLARE it gets an empty index on every
// PartialCorrelate — the rule still runs, still emits edges, and just quietly
// drops the cap those types carry. Dropping "aws_scp_set" from either
// SecretAccess or IAMEffectivePermissions was a fully green mutation before this.
//
// Callers are read from the source, so a new rule that starts consulting SCPs is
// held to the same rule the moment it is written.
func TestRulesDeclareTheTypesTheyReadFromTheGraph(t *testing.T) {
	byTypeName := make(map[string]Rule, len(allRules))
	for _, r := range allRules {
		ty := reflect.TypeOf(r)
		if ty.Kind() == reflect.Pointer {
			ty = ty.Elem()
		}
		byTypeName[ty.Name()] = r
	}

	for accessor, types := range graphReadsRequiringDeclaration {
		callers := rulesCallingGraphAccessor(t, accessor)
		require.NotEmpty(t, callers,
			"no rule calls Graph.%s — the accessor was renamed or the AST walk is broken", accessor)
		for _, name := range callers {
			r, ok := byTypeName[name]
			require.True(t, ok, "%s calls Graph.%s but is not in allRules", name, accessor)
			declared := make(map[string]bool, len(r.InterestedIn()))
			for _, ty := range r.InterestedIn() {
				declared[ty] = true
			}
			for _, ty := range types {
				require.True(t, declared[ty],
					"rule %s reads Graph.%s but does not declare %q in InterestedIn — "+
						"PartialCorrelate will never load it and the rule silently loses that input",
					r.Name(), accessor, ty)
			}
		}
	}
}

// rulesCallingGraphAccessor returns the rule type names whose Correlate or
// CorrelateAssets method calls the named Graph accessor.
func rulesCallingGraphAccessor(t *testing.T, accessor string) []string {
	t.Helper()
	var out []string
	for _, f := range parsePackage(t) {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			if fn.Name.Name != "Correlate" && fn.Name.Name != "CorrelateAssets" {
				continue
			}
			calls := false
			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == accessor {
					calls = true
				}
				return true
			})
			if !calls {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok {
				out = append(out, id.Name)
			}
		}
	}
	return out
}

// TestAllRulesListIsComplete keeps allRules honest by parsing the package for
// every type that implements Rule (i.e. declares an InterestedIn method).
func TestAllRulesListIsComplete(t *testing.T) {
	listed := make(map[string]bool, len(allRules))
	for _, r := range allRules {
		ty := reflect.TypeOf(r)
		if ty.Kind() == reflect.Pointer {
			ty = ty.Elem()
		}
		listed[ty.Name()] = true
	}
	for _, name := range ruleTypeNames(t) {
		require.True(t, listed[name],
			"%s implements Rule but is missing from allRules in correlation_types_test.go", name)
	}
}

// parsePackage parses this package's non-test sources.
func parsePackage(t *testing.T) []*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		files = append(files, f)
	}
	require.NotEmpty(t, files, "no correlate sources found")
	return files
}

// ruleTypeNames returns the name of every type in the package declaring an
// InterestedIn method — the distinguishing method of the Rule interface.
func ruleTypeNames(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, f := range parsePackage(t) {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "InterestedIn" || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			recv := fn.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok {
				out = append(out, id.Name)
			}
		}
	}
	require.NotEmpty(t, out, "found no Rule implementations — the AST walk is broken")
	return out
}

// newGraphSwitchTypes returns every asset-type string literal NewGraph switches
// on. Read from the source rather than restated, so a new `case "foo":` is
// covered by this test the moment it is written.
func newGraphSwitchTypes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, f := range parsePackage(t) {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "NewGraph" {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				sw, ok := n.(*ast.SwitchStmt)
				if !ok || !isAssetTypeSelector(sw.Tag) {
					return true
				}
				for _, stmt := range sw.Body.List {
					cc, ok := stmt.(*ast.CaseClause)
					if !ok {
						continue
					}
					for _, e := range cc.List {
						lit, ok := e.(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, err := strconv.Unquote(lit.Value)
						require.NoError(t, err)
						out = append(out, v)
					}
				}
				return true
			})
		}
	}
	require.NotEmpty(t, out, "found no type switch in NewGraph — the AST walk is broken")
	return out
}

// isAssetTypeSelector reports whether an expression is `a.Type` — the tag of
// NewGraph's asset-type switches.
func isAssetTypeSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Type" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "a"
}
